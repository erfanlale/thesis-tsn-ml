#ifndef __MINIMALPSFPATTACKML_DATACOLLECTOR_H
#define __MINIMALPSFPATTACKML_DATACOLLECTOR_H

#include <omnetpp.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <map>
#include <deque>
#include <array>
#include "CsvWriter.h"
#include "PerPacketCsvWriter.h"

// INET includes
#include "inet/common/Simsignals.h"
#include "inet/common/packet/Packet.h"

using namespace omnetpp;

/**
 * DataCollector Module for Time-Windowed TSN Data Collection
 * 
 * This module subscribes to key TSN signals and aggregates them into 
 * time windows for ML-ready CSV output. Replaces per-event JSON with
 * efficient windowed aggregation for real-time ML inference.
 * 
 * Features:
 * - Time-windowed aggregation (configurable window size)
 * - CSV output format for ML pipeline
 * - Key TSN metrics: packet counts, loss rates, queue metrics
 * - Automatic labeling based on attack timing
 */
class DataCollector : public cSimpleModule, public cIListener
{
protected:
    // Configuration parameters
    double windowSize; // Time window size in seconds
    bool emitCSV;
    bool emitJSON;
    bool emitNDJSON;
    bool diag = false; // diagnostics flag
    bool includeControlFramesInThroughput = false; // include gPTP/LLDP/pause in throughput stats
    bool emitZeroIfNoSamples = true;               // emit 0.0 when no samples (false -> emit -1.0 as N/A)
    // Diagnostics state
    std::unordered_set<std::string> meterSeenPairs; int meterSeenCount = 0;
    bool guardbandEventSeen = false; int guardGatesSubscribed = 0;
    std::string outputFile;
    // Stage-1 debug counters
    std::unordered_map<std::string,int> subCountBySignal;       // how many modules subscribed per signal name
    std::unordered_map<std::string,int> debugEventPrintCountBySignal; // first N event prints per signal
    int debugMaxEventPrints = 3;
    std::unordered_map<std::string,long> eventsSeenBySignal; // total events observed per signal name
    
    // Dynamic subscription
    std::vector<std::string> wantedSignalNames;
    std::unordered_set<std::string> subscribedKeys; // moduleFullPath:signalName
    
    // Output file
    CsvWriter csv;
    PerPacketCsvWriter packetCsv;
    bool emitPerStreamRows = false;
    CsvWriter streamCsv;
    // Expose current window features for engine (Option A)
    public: struct WindowFeatures { double f[8]; bool ready=false; simtime_t t0=0, t1=0; };
    protected: WindowFeatures lastWindow_;
    public: inline const WindowFeatures& getLastWindow() const { return lastWindow_; }
    // Extended window features aligned to training feature_order (15 features):
    // [throughput_bps_tx, packets_sent, packets_received, packets_dropped, drop_rate, queue_length_max,
    //  ptp_offset_mean, ptp_offset_max, rate_ratio_mean, peer_delay_mean,
    //  e2e_delay_avg, e2e_delay_max, e2e_delay_std, has_ptp, has_e2e]
    public: struct ExtendedWindowFeatures { double f[15]; bool ready=false; simtime_t t0=0, t1=0; };
    protected: ExtendedWindowFeatures lastWindowExt_;
    public: inline const ExtendedWindowFeatures& getLastWindowExtended() const { return lastWindowExt_; }
    
    // Window management
    cMessage *windowTimer;
    cMessage *subscribeTimer = nullptr;
    bool subscriptionsDone = false;
    double currentWindowStart;
    std::map<std::string, double> windowMetrics;
    int windowCount = 0;
    
    // Overall statistics
    int totalPacketsSent;
    int totalPacketsReceived;
    int totalPacketsDropped;
    
    // Simulation context information
    std::string currentConfigName;
    int currentRepetition;

    // Typed per-window aggregates
    long w_packetsSent = 0;
    long w_packetsReceived = 0;
    long w_packetsDropped = 0;
    long w_rxGood = 0;
    long w_txBytes = 0; // legacy, will be unused after vantage migration
    long w_rxBytes = 0; // legacy, will be unused after vantage migration
    // Vantage accumulators (centralSwitch.eth[1].mac and its queue)
    long w_txBits = 0;         // mac packetSentToLower bits
    long w_rxBits = 0;         // mac rxPkOk bits
    long w_txBitsPcp[8] = {0,0,0,0,0,0,0,0};
    long w_rxBitsPcp[8] = {0,0,0,0,0,0,0,0};
    long w_enqOkPcp[8] = {0,0,0,0,0,0,0,0};
    long w_dropsPcp[8] = {0,0,0,0,0,0,0,0};
    // Per-queue tracking
    std::unordered_map<std::string,long> q_len_by_path;
    struct QueueLenState { long len=0; double lastChange=0.0; double timeIntegral=0.0; };
    std::unordered_map<std::string, QueueLenState> q_len_state_by_path;
    std::unordered_map<std::string,long> q_bit_by_path; // bits
    long w_queueLenMax = 0;
    long w_queueBitlenMax = 0;
    long w_queueLenMaxPcp[8] = {0,0,0,0,0,0,0,0};
    double w_queueLenIntegralPcp[8] = {0,0,0,0,0,0,0,0};
    // Map of queue path to pending PCPs seen at packetPushStarted, to resolve acceptance on packetPushEnded
    std::unordered_map<std::string, std::deque<int>> q_pendingPcpByPath;
    // Diagnostics per-window event counts and sampling
    std::unordered_map<std::string, long> windowEvtCounts;
    long sampleMacEvents = 0;
    long sampleQueueEvents = 0;
    bool hadQueueEventThisWindow = false;
    long totalPushStartedSeen = 0;
    // Per-PCP queue integral trackers (computed from enqueue/pull with PCP)
    long qlenPcp[8] = {0,0,0,0,0,0,0,0};
    double qlenPcpLastChange[8] = {0,0,0,0,0,0,0,0};
    double qlenPcpIntegral[8] = {0,0,0,0,0,0,0,0};
    double w_queueingTimeSum = 0.0;
    long w_queueingTimeCount = 0;
    // E2E delay
    double w_e2eSum = 0.0;
    double w_e2eMax = 0.0;
    long w_e2eCount = 0;
    // Receiver-side (sink) E2E delay stats (derived at application sinks)
    double w_sinkE2eSum = 0.0;
    double w_sinkE2eSumSq = 0.0;
    double w_sinkE2eMax = 0.0;
    long w_sinkE2eCount = 0;
    // Sample counters for masking/imputation in ML
    long ptp_samples = 0;      // counts any of: timeDifference, rateRatio, peerDelay
    long e2e_samples = 0;      // counts app sink packetReceived with CreationTimeTag
    std::unordered_map<long, omnetpp::simtime_t> enqTimeById; // for queueing time
    struct GateState { bool hasState=false; bool isOpen=false; double openTimeAccum=0.0; double lastChange=0.0; };
    std::unordered_map<std::string, GateState> gatePathToState;
    std::unordered_map<std::string, GateState> guardPathToState;
    // Gate open state per port (0/1 only)
    std::unordered_map<int,int> lastGateOpenByPort; // port -> 0/1
    double w_gptpOffsetSum = 0.0; double w_gptpOffsetMax = 0.0; long w_gptpOffsetCount = 0;
    double w_rateRatioSum = 0.0; long w_rateRatioCount = 0;
    double w_peerDelaySum = 0.0; long w_peerDelayCount = 0;
    double w_tokensSum = 0.0; long w_tokensCount = 0;
    // PSFP meter counters (centralSwitch ingress)
    struct MeterCounters { long ccp=0; long cnp=0; long ecp=0; long filtered=0; };
    std::unordered_map<std::string, MeterCounters> meterCountersByName;
    long psfp_ccp_sum = 0, psfp_cnp_sum = 0, psfp_ecp_sum = 0, psfp_filtered_sum = 0;
    // Per-packet PSFP/Qbv annotations by Packet::treeId
    std::unordered_map<long,int> lastMeterColorByTreeId; // 0=green,1=yellow,2=red
    std::unordered_set<long> filteredTreeIds;
    std::unordered_map<long,std::string> dropReasonByTreeId; // e.g., filter_drop, queue_drop
    std::unordered_map<long,int> gateIndexByTreeId; // TAS/queue index if inferable

    // Pending per-packet rows awaiting stream classification
    struct PendingPkt {
        double ts = 0.0;
        long bytes = 0;
        std::string srcMAC;
        std::string dstMAC;
        int pcp = -1;
        int vlanId = -1;
    };
    std::unordered_map<long, PendingPkt> pendingByTreeId;

    // Vantage path filters
    std::string vantageMacPrefix = "MinimalAttackNetwork.centralSwitch"; // general prefix (eth/ethg)
    std::string vantageQueuePrefix = "MinimalAttackNetwork.centralSwitch"; // general prefix for queues
    const std::string centralSwitchMeterPrefix = "MinimalAttackNetwork.centralSwitch.bridging.streamFilter.ingress.meter";
    const std::string centralSwitchEthPrefix = "MinimalAttackNetwork.centralSwitch.eth[";
    // Per-port counters
    std::unordered_map<int,long> txPkByPort; // key: port index
    std::unordered_map<int,long> rxPkByPort; // key: port index
    // Per-port additions (per-window)
    std::unordered_map<int,long> txBytesByPort;
    std::unordered_map<int,long> rxBytesByPort;
    std::unordered_map<int,long> dropQueueByPort;
    std::unordered_map<int,long> dropMacByPort;
    // MAC -> Node name mapping
    std::unordered_map<std::string,std::string> macToNodeName; // lowercase hex with colons -> nodeName
    // Precomputed queue path per port
    std::unordered_map<int,std::string> queuePathByPort;
    bool onlyEgressRows = true;

    // Per-packet dedup at vantage
    std::unordered_set<std::string> seenVantagePacketKeys;

    // Per-stream aggregation for current window
    struct StreamAgg {
        long packetsRx = 0;
        long rxBytes = 0;
        long drops = 0;
        long rxGood = 0;
        double e2eSum = 0.0; long e2eCount = 0;
        double queueingSum = 0.0; long queueingCount = 0;
        int pcp = -1;
        int vlanId = -1;
    };
    std::unordered_map<std::string, StreamAgg> streamAggById;
    // Diagnostics: track how often streamId came from tags vs. fallback
    long streamIdTagSeenCount = 0;
    long streamIdFallbackCount = 0;
    // Dynamic device ID mapping (derived from observed MACs)
    std::unordered_map<std::string,int> deviceIdByMac;
    int nextDeviceId = 1;
    
protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;
    
    // Signal handling methods (INET convention)
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, bool value, cObject *details) override;
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, intval_t value, cObject *details) override;   // long/int type (e.g., pause units)
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, uintval_t value, cObject *details) override;  // unsigned long/int
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, double value, cObject *details) override;     // rateRatio, tokensChanged
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, const SimTime& value, cObject *details) override; // SimTime (gPTP)
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, const char *value, cObject *details) override;
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, cObject *value, cObject *details) override;   // Packet*
    
public:
    DataCollector();
    virtual ~DataCollector();
    
private:
    // Core methods
    void initializeWantedSignals();
    void subscribeToAllModules();
    void subscribeRecursively(cModule *module);
    void recordSignalEvent(cComponent *source, simsignal_t signalID, const std::string& value);
    
    // Window management
    void resetWindowMetrics();
    void flushCurrentWindow();
    
    // Output methods
    void writeCSVHeader();
    void writeCSVRecord();
    
    // Utility methods
    std::string getSignalName(simsignal_t signalID);
    std::string determineLabelForWindow(double windowStart, double windowEnd);
    void extractConfigFromFileName(const std::string& fileName);
    bool isRelevantModulePath(const std::string& path) const;
    void resetTypedWindowAggregates();
    void onGateStateChanged(std::unordered_map<std::string, GateState>& map, const std::string& gatePath, bool isOpen, double tNow);
    std::string makeNodePortKey(cComponent* src, std::string& node, int& port) const;
    void updateQueueLenIntegral(const std::string& qpath, long deltaLen, double tNow);
    int parsePortIndexFromPath(const std::string& path) const;
    int parseGateIndexFromPath(const std::string& path) const;
};

#endif // __MINIMALPSFPATTACKML_DATACOLLECTOR_H
