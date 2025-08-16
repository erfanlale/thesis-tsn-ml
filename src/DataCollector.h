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
    std::string outputFile;
    
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
    
    // Window management
    cMessage *windowTimer;
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
    long w_txBytes = 0;
    long w_rxBytes = 0;
    // Per-queue tracking
    std::unordered_map<std::string,long> q_len_by_path;
    struct QueueLenState { long len=0; double lastChange=0.0; double timeIntegral=0.0; };
    std::unordered_map<std::string, QueueLenState> q_len_state_by_path;
    std::unordered_map<std::string,long> q_bit_by_path; // bits
    long w_queueLenMax = 0;
    long w_queueBitlenMax = 0;
    double w_queueingTimeSum = 0.0;
    long w_queueingTimeCount = 0;
    // E2E delay
    double w_e2eSum = 0.0;
    double w_e2eMax = 0.0;
    long w_e2eCount = 0;
    std::unordered_map<long, omnetpp::simtime_t> enqTimeById; // for queueing time
    struct GateState { bool hasState=false; bool isOpen=false; double openTimeAccum=0.0; double lastChange=0.0; };
    std::unordered_map<std::string, GateState> gatePathToState;
    std::unordered_map<std::string, GateState> guardPathToState;
    double w_gptpOffsetSum = 0.0; double w_gptpOffsetMax = 0.0; long w_gptpOffsetCount = 0;
    double w_rateRatioSum = 0.0; long w_rateRatioCount = 0;
    double w_peerDelaySum = 0.0; long w_peerDelayCount = 0;
    double w_tokensSum = 0.0; long w_tokensCount = 0;

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
};

#endif // __MINIMALPSFPATTACKML_DATACOLLECTOR_H
