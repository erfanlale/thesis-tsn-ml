/*
 Locked Target Signals and Types (do not rename)
 ===============================================

 MAC (EthernetMac):
  - packetReceivedFromLower (Packet*)
  - rxPkOk (Packet*)
  - packetSentToLower (Packet*)
  - packetDropped (Packet*)
  - rxPausePkUnits (long)
  - txPausePkUnits (long)

 Queues (PacketQueue):
  - packetPushStarted (Packet* + details)
  - packetPushEnded (nullptr + details)
  - packetPulled (Packet*)
  - packetRemoved (Packet*)
  - packetDropped (Packet* + details)

 Qbv gates:
  - gateStateChanged (bool)
  - guardBandStateChanged (bool, if present)

 gPTP:
  - localTime (SimTime)
  - timeDifference (SimTime)
  - rateRatio (double)
  - peerDelay (SimTime)

 PSFP meters:
  - tokensChanged (double)
  - Note: Per-color counters don’t exist; derive stream/color via LabelsTag.

 Per-packet tags to extract (on Packet arrival):
  - MacAddressInd
  - L3AddressInd
  - CreationTimeTag
  - QueueingTimeTag
  - LabelsTag
  - PcpInd
  - VlanInd
*/
#include "DataCollector.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <cmath>
#include "inet/common/TimeTag_m.h"
#include "inet/linklayer/common/MacAddressTag_m.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/linklayer/ethernet/common/EthernetMacHeader_m.h"
#include "inet/queueing/common/LabelsTag_m.h"
#include "inet/linklayer/common/PcpTag_m.h"
#include "inet/linklayer/common/VlanTag_m.h"
#include "inet/protocolelement/redundancy/StreamTag_m.h"

Define_Module(DataCollector);

DataCollector::DataCollector() : csv("/dev/null"), packetCsv("/dev/null"), streamCsv("/dev/null")
{
    windowSize = 0.005; // 5ms default
    emitCSV = true;
    emitJSON = false;
    emitNDJSON = false;
    windowTimer = nullptr;
    totalPacketsSent = 0;
    totalPacketsReceived = 0;
    totalPacketsDropped = 0;
    currentWindowStart = 0.0;
    currentConfigName = "Unknown";
    currentRepetition = 0;
    // CsvWriter constructed later when path known
}

DataCollector::~DataCollector()
{
    if (windowTimer) {
        cancelAndDelete(windowTimer);
        windowTimer = nullptr;
    }
    // CsvWriter closes on destruction
}

void DataCollector::initialize()
{
    EV_INFO << "🎯 [DataCollector] Initializing ML-ready data collection with time-windowed aggregation" << endl;
    
    // Get parameters from NED file
    std::string outputFileParam = par("outputFile").stringValue();
    windowSize = par("windowLength").doubleValue();
    emitCSV = par("emitCSV").boolValue();
    emitJSON = par("emitRaw").boolValue(); // raw JSON per event
    emitNDJSON = par("emitNDJSON").boolValue();
    if (hasPar("emitPerStreamRows")) emitPerStreamRows = par("emitPerStreamRows").boolValue();
    
    // Extract config name from output file path (contains ${configname})
    // File format: ml_models/tsn_signals_${configname}-#${repetition}.csv
    extractConfigFromFileName(outputFileParam);
    
    // Update file extension based on output format
    if (emitCSV) {
        // Change .json to .csv in filename
        outputFile = outputFileParam;
        size_t pos = outputFile.find(".json");
        if (pos != std::string::npos) {
            outputFile.replace(pos, 5, ".csv");
        }
    } else {
        outputFile = outputFileParam;
    }
    
    EV_INFO << "📂 Output file: " << outputFile << endl;
    EV_INFO << "⏱️ Window size: " << windowSize << "s (" << (windowSize * 1000) << "ms)" << endl;
    EV_INFO << "📊 Output format: " << (emitCSV ? "CSV" : "JSON") << endl;
    
    // Initialize signal subscriptions (dynamic)
    initializeWantedSignals();
    subscribeToAllModules();
    
    // Initialize window tracking
    currentWindowStart = 0.0;
    resetWindowMetrics();
    
    // Set up periodic window flushing
    if (!windowTimer) {
        windowTimer = new cMessage("windowTimer");
    }
    scheduleAt(simTime() + windowSize, windowTimer);
    
    // Open output file and write header if CSV
    if (emitCSV) {
        CsvWriter writer(outputFile);
        if (!writer.good()) {
            throw cRuntimeError("Failed to open CSV output file: %s", outputFile.c_str());
        }
        csv = std::move(writer);
        writeCSVHeader();
        // per-packet CSV path next to windowed CSV
        std::string packetPath = outputFile;
        size_t pos = packetPath.find("tsn_signals_");
        if (pos != std::string::npos) packetPath.replace(pos, std::string("tsn_signals_").size(), "perpacket_");
        PerPacketCsvWriter pw(packetPath);
        if (!pw.writer.good()) throw cRuntimeError("Failed to open per-packet CSV: %s", packetPath.c_str());
        packetCsv = std::move(pw);
        packetCsv.writeHeader();
    }
    
    EV_INFO << "✅ DataCollector initialized and ready for ML data collection!" << endl;
}

void DataCollector::handleMessage(cMessage *msg)
{
    if (msg == windowTimer) {
        // Process window boundary - aggregate and emit current window data
        flushCurrentWindow();
        
        // Advance to next window
        currentWindowStart = simTime().dbl();
        resetWindowMetrics();
        
        // Schedule next window
        scheduleAt(simTime() + windowSize, windowTimer);
    } else {
        delete msg;
    }
}

void DataCollector::finish()
{
    EV_INFO << "🏁 DataCollector finishing..." << endl;
    
    // Flush any remaining data in current window
    flushCurrentWindow();
    
    // CsvWriter closes on destruction
    
    // Ensure final contents are on disk
    if (emitCSV) {
        csv.flush();
        packetCsv.writer.flush();
    }

    // Print summary statistics
    EV_INFO << "📊 DataCollector Summary:" << endl;
    EV_INFO << "   Total packets sent: " << totalPacketsSent << endl;
    EV_INFO << "   Total packets received: " << totalPacketsReceived << endl;
    EV_INFO << "   Total packets dropped: " << totalPacketsDropped << endl;
    EV_INFO << "   Windows processed: " << windowCount << endl;
    EV_INFO << "   Output file: " << outputFile << endl;
    
    if (windowTimer) {
        cancelAndDelete(windowTimer);
        windowTimer = nullptr;
    }
}

void DataCollector::initializeWantedSignals()
{
    wantedSignalNames = {
        // MAC
        "packetReceivedFromLower","rxPkOk","packetSentToLower","packetDropped",
        "rxPausePkUnits","txPausePkUnits",
        // Queues
        "packetPushStarted","packetPushEnded","packetPulled","packetRemoved",
        // Qbv
        "gateStateChanged","guardBandStateChanged",
        // gPTP
        "localTime","timeDifference","rateRatio","peerDelay",
        // PSFP
        "tokensChanged"
    };
}

void DataCollector::subscribeToAllModules()
{
    // Subscribe to signals from all modules in the network
    cModule *systemModule = getSystemModule();
    subscribeRecursively(systemModule);
    EV_INFO << "📡 Subscribed to signals from entire network hierarchy" << endl;
}

void DataCollector::subscribeRecursively(cModule *module)
{
    if (!module) return;
    // Filter relevant module paths
    std::string path = module->getFullPath().c_str();
    if (isRelevantModulePath(path)) {
        for (const auto& sname : wantedSignalNames) {
            simsignal_t sid = cComponent::registerSignal(sname.c_str());
            if (sid != SIMSIGNAL_NULL) {
                std::string key = path + ":" + sname;
                if (subscribedKeys.insert(key).second) {
                    module->subscribe(sid, this);
                }
            }
        }
    }
    
    // Recursively subscribe to submodules
    for (cModule::SubmoduleIterator it(module); !it.end(); it++) {
        cModule *submodule = *it;
        subscribeRecursively(submodule);
    }
}

void DataCollector::resetWindowMetrics()
{
    windowMetrics.clear();
    resetTypedWindowAggregates();
    streamAggById.clear();
}

void DataCollector::flushCurrentWindow()
{
    if (emitCSV) {
        writeCSVRecord();
        if (emitPerStreamRows && !streamAggById.empty()) {
            // Write per-stream rows after the global row
            for (const auto &kv : streamAggById) {
                const std::string &sid = kv.first;
                const StreamAgg &a = kv.second;
                csv.newRow();
                // reuse run/config/module/name columns, tag name as "streamFeatures"
                simtime_t currentTime = simTime();
                double windowEnd = currentTime.dbl();
                const std::string runId = currentConfigName + "-#" + std::to_string(currentRepetition);
                csv.add(runId);
                csv.add(currentRepetition);
                csv.add(currentConfigName);
                csv.add("MinimalAttackNetwork");
                csv.add("streamFeatures");
                csv.add(currentTime.dbl());
                csv.add(currentWindowStart);
                csv.add(windowEnd);
                // Place per-stream metrics into available numeric columns; leave others as 0
                csv.add((int)a.packetsRx);                      // packets_sent (reuse)
                csv.add((int)a.rxGood);                         // packets_received (reuse)
                csv.add((int)a.drops);                          // packets_dropped (reuse)
                csv.add((int)a.rxGood);                         // rx_good
                csv.add((long)a.rxBytes);                       // tx_bytes (reuse for rx)
                csv.add((long)a.rxBytes);                       // rx_bytes
                csv.add(0.0);                                   // throughput_bps_tx
                csv.add(0.0);                                   // throughput_bps_rx
                csv.add(0.0);                                   // queue_length_max
                csv.add(0.0);                                   // queue_bitlength_max
                csv.add(a.queueingCount>0 ? a.queueingSum/(double)a.queueingCount : 0.0); // queueing_time_avg
                csv.add(0.0);                                   // gate_open_fraction
                csv.add(0.0);                                   // guardband_fraction
                csv.add(a.e2eCount>0 ? (a.e2eSum/(double)a.e2eCount) : NAN); // gptp_offset_ns_avg (reuse for e2e avg seconds)
                csv.add(0.0);                                   // gptp_offset_ns_max
                csv.add(0.0);                                   // rate_ratio_avg
                csv.add(0.0);                                   // peer_delay_avg
                csv.add(sid);                                    // label column reused to carry stream_id tag
                csv.add(a.pcp >= 0 ? std::to_string(a.pcp) : ""); // predicted_label column reused to carry PCP
                csv.add(a.vlanId >= 0 ? (double)a.vlanId : NAN);   // confidence column reused to carry VLAN ID
                csv.writeToFile();
            }
        }
    }
    windowCount++;
    // Clear per-stream accumulators for next window
    streamAggById.clear();
}

void DataCollector::writeCSVHeader()
{
    // Locked schema for training/inference alignment (F; queue_length_avg dropped)
    csv.setHeader({
        "run","itervar:repetition","param:config_name","module","name",
        "timestamp","window_start","window_end",
        "throughput_bps_tx","throughput_bps_rx",
        "packets_sent","packets_received","packets_dropped","drop_rate",
        "queue_length_max","queue_bitlength_max",
        // additional observability (optional; safe to keep at end)
        "queue_length_avg","gate_open_fraction_avg","guardband_fraction_avg",
        "label"
    });
}

void DataCollector::writeCSVRecord()
{
    simtime_t currentTime = simTime();
    double windowEnd = currentTime.dbl();
    
    // Calculate derived metrics
    int sent = (int)w_packetsSent;
    int received = (int)w_packetsReceived;
    int dropped = (int)w_packetsDropped;
    int total = sent + received + dropped;
    
    double lossRate = (total > 0) ? (double)dropped / total : 0.0;
    double thrTx = (windowSize > 0) ? (w_txBytes * 8.0 / windowSize) : 0.0;
    double thrRx = (windowSize > 0) ? (w_rxBytes * 8.0 / windowSize) : 0.0;
    
    // Gate fractions (average across gates per window; kept out of CSV per current schema)
    auto avgFracAcrossGates = [&](const std::unordered_map<std::string, GateState>& mp) {
        if (windowSize <= 0.0) return 0.0;
        double end = windowEnd;
        double sumFrac = 0.0;
        int n = 0;
        for (const auto &kv : mp) {
            const auto &gs = kv.second;
            if (!gs.hasState) continue;
            double last = std::max(gs.lastChange, currentWindowStart);
            double open = gs.openTimeAccum;
            if (gs.isOpen) open += std::max(0.0, end - last);
            double frac = open / windowSize;
            // clamp to [0,1] per gate
            if (frac < 0.0) frac = 0.0; else if (frac > 1.0) frac = 1.0;
            sumFrac += frac;
            n++;
        }
        return (n > 0) ? (sumFrac / (double)n) : 0.0;
    };
    double gateOpenAvg = avgFracAcrossGates(gatePathToState);
    double guardbandAvg = avgFracAcrossGates(guardPathToState);
    // Store for potential future use (not emitted to CSV by request)
    windowMetrics["gate_open_fraction_avg"] = gateOpenAvg;
    windowMetrics["guardband_fraction_avg"] = guardbandAvg;
    
    // Queue length average via time integral across all queues
    double qlenAvg = 0.0;
    if (windowSize > 0.0 && !q_len_state_by_path.empty()) {
        double sumInt = 0.0;
        for (auto &kv : q_len_state_by_path) {
            const auto &st = kv.second;
            // Include tail from lastChange to windowEnd at current len
            double tPrev = st.lastChange > 0.0 ? st.lastChange : currentWindowStart;
            double contrib = st.timeIntegral + st.len * std::max(0.0, windowEnd - std::max(currentWindowStart, tPrev));
            sumInt += contrib;
        }
        qlenAvg = sumInt / windowSize;
    }
    
    // Expose minimal 7-feature vector for engine pull
    // F7 = [throughput_bps_tx, throughput_bps_rx, packets_sent, packets_received, packets_dropped, drop_rate, queue_length_max]
    lastWindow_.f[0] = thrTx;
    lastWindow_.f[1] = thrRx;
    lastWindow_.f[2] = sent;
    lastWindow_.f[3] = received;
    lastWindow_.f[4] = dropped;
    lastWindow_.f[5] = (total>0? ((double)dropped/(double)total) : 0.0);
    lastWindow_.f[6] = (double)w_queueLenMax;
    lastWindow_.t0 = SimTime(currentWindowStart);
    lastWindow_.t1 = SimTime(windowEnd);
    lastWindow_.ready = true;
    
    // Determine label based on simulation time and scenario
    std::string label = determineLabelForWindow(currentWindowStart, windowEnd);
    
    // Extract scenario information from simulation - use cached values
    // These will be set during initialization or extracted from run context
    std::string configName = currentConfigName;
    int repetition = currentRepetition;
    
    const std::string runId = configName + "-#" + std::to_string(repetition);
    csv.newRow();
    csv.add(runId);
    csv.add(repetition);
    csv.add(configName);
    csv.add("MinimalAttackNetwork");
    csv.add("windowFeatures");
    csv.add(currentTime.dbl());
    csv.add(currentWindowStart);
    csv.add(windowEnd);
    csv.add(thrTx);
    csv.add(thrRx);
    csv.add(sent);
    csv.add(received);
    csv.add(dropped);
    csv.add(lossRate);
    csv.add((double)w_queueLenMax);
    csv.add((double)w_queueBitlenMax);
    csv.add(qlenAvg);
    csv.add(windowMetrics.count("gate_open_fraction_avg") ? windowMetrics["gate_open_fraction_avg"] : 0.0);
    csv.add(windowMetrics.count("guardband_fraction_avg") ? windowMetrics["guardband_fraction_avg"] : 0.0);
    csv.add(label);
    csv.writeToFile();
}

std::string DataCollector::determineLabelForWindow(double windowStart, double windowEnd)
{
    // Determine attack label based on scenario configuration and time window
    // Use cached config name
    std::string configName = currentConfigName;
    
    if (configName == "Baseline") {
        return "normal";
    } else if (configName == "DoSAttack" || configName == "DoSFlooding") {
        // Support both Minimal (0.100-0.400s) and PSFP scenario (1s-2s/2.5s) DoS intervals
        auto overlaps = [](double ws, double we, double as, double ae){ return ws < ae && we > as; };
        if (overlaps(windowStart, windowEnd, 0.100, 0.400) ||
            overlaps(windowStart, windowEnd, 1.000, 2.000) ||
            overlaps(windowStart, windowEnd, 1.000, 2.500)) {
            return "dos_attack";
        }
        return "normal";
    } else if (configName == "TimingAttack") {
        // Minimal: 0.050-0.450s; PSFP: disruptive traffic from 0.1s (clock drift also active)
        auto overlaps = [](double ws, double we, double as, double ae){ return ws < ae && we > as; };
        if (overlaps(windowStart, windowEnd, 0.050, 0.450) ||
            overlaps(windowStart, windowEnd, 0.100, 3.000)) {
            return "timing_attack";
        }
        return "normal";
    } else if (configName == "SpoofingAttack") {
        // Minimal: 0.150-0.350s; PSFP: 0.5-1.5s
        auto overlaps = [](double ws, double we, double as, double ae){ return ws < ae && we > as; };
        if (overlaps(windowStart, windowEnd, 0.150, 0.350) ||
            overlaps(windowStart, windowEnd, 0.500, 1.500)) {
            return "spoofing_attack";
        }
        return "normal";
    } else if (configName == "MixedAttacks") {
        // PSFP MixedAttacks: multiple overlapping attacks
        auto overlaps = [](double ws, double we, double as, double ae){ return ws < ae && we > as; };
        bool dos = overlaps(windowStart, windowEnd, 1.000, 2.500);
        bool spoof = overlaps(windowStart, windowEnd, 0.500, 2.000);
        bool timing = overlaps(windowStart, windowEnd, 1.500, 2.500);
        if (dos || spoof || timing) return "mixed_attack";
        return "normal";
    }
    
    return "normal";
}

// Signal handlers for different data types
void DataCollector::receiveSignal(cComponent *source, simsignal_t signalID, bool value, cObject *details)
{
    // Qbv: gateStateChanged / guardBandStateChanged
    std::string signalName = getSignalName(signalID);
    double tNow = SIMTIME_DBL(simTime());
    if (signalName == "gateStateChanged") {
        std::string gatePath = source->getFullPath().c_str();
        onGateStateChanged(gatePathToState, gatePath, value, tNow);
    } else if (signalName == "guardBandStateChanged") {
        std::string guardPath = source->getFullPath().c_str();
        onGateStateChanged(guardPathToState, guardPath, value, tNow);
    }
    recordSignalEvent(source, signalID, value ? "true" : "false");
}

void DataCollector::receiveSignal(cComponent *source, simsignal_t signalID, intval_t value, cObject *details)
{
    // MAC pause units (long): rxPausePkUnits / txPausePkUnits
    recordSignalEvent(source, signalID, std::to_string(value));
}

void DataCollector::receiveSignal(cComponent *source, simsignal_t signalID, uintval_t value, cObject *details)
{
    recordSignalEvent(source, signalID, std::to_string(value));
}

void DataCollector::receiveSignal(cComponent *source, simsignal_t signalID, double value, cObject *details)
{
    // rateRatio, tokensChanged (and any other doubles)
    recordSignalEvent(source, signalID, std::to_string(value));
}

void DataCollector::receiveSignal(cComponent *source, simsignal_t signalID, const SimTime& value, cObject *details)
{
    // gPTP times: localTime, timeDifference, peerDelay
    recordSignalEvent(source, signalID, value.str());
}

void DataCollector::receiveSignal(cComponent *source, simsignal_t signalID, const char *value, cObject *details)
{
    recordSignalEvent(source, signalID, value ? value : "");
}

void DataCollector::receiveSignal(cComponent *source, simsignal_t signalID, cObject *value, cObject *details)
{
    std::string signalName = getSignalName(signalID);
    // Packet-based signals: accumulate bytes and queueing time
    auto packet = dynamic_cast<inet::Packet*>(value);
    if (packet) {
        auto bytes = (long)packet->getTotalLength().get();
        if (signalName == "packetSentToLower")      w_txBytes += bytes;
        else if (signalName == "packetReceivedFromLower" || signalName == "rxPkOk") w_rxBytes += bytes;
        if (signalName == "packetPushStarted") {
            // bit-length bookkeeping: add on push start
            std::string q = source->getFullPath().c_str();
            long &qb = q_bit_by_path[q]; qb += bytes*8; if (qb > w_queueBitlenMax) w_queueBitlenMax = qb;
        } else if (signalName == "packetPushEnded") {
            // no Packet* provided for pushEnded; handled in recordSignalEvent for len integral
        } else if (signalName == "packetPulled") {
            std::string q = source->getFullPath().c_str();
            auto itb = q_bit_by_path.find(q); if (itb!=q_bit_by_path.end() && itb->second>=bytes*8) itb->second -= bytes*8;
            // queueing time from tag (preferred)
            if (auto qt = packet->findTag<inet::QueueingTimeTag>()) {
                double qv = SIMTIME_DBL(qt->getPacketTotalTimes(0));
                w_queueingTimeSum += qv; w_queueingTimeCount++;
            }
        } else if (signalName == "packetRemoved") {
            std::string q = source->getFullPath().c_str();
            auto itb = q_bit_by_path.find(q); if (itb!=q_bit_by_path.end() && itb->second>=bytes*8) itb->second -= bytes*8; // subtract on remove too
        }
        // Tags and derived measurements
        std::string srcMAC, dstMAC, srcL3, dstL3;
        std::string streamId;
        int pcp = -1; int vlanId = -1;
        if (auto mac = packet->findTag<inet::MacAddressInd>()) { srcMAC = mac->getSrcAddress().str(); dstMAC = mac->getDestAddress().str(); }
        if (auto l3 = packet->findTag<inet::L3AddressInd>()) { srcL3 = l3->getSrcAddress().str(); dstL3 = l3->getDestAddress().str(); }
        // Fallback to Ethernet header if tags not present
        if ((srcMAC.empty() || dstMAC.empty())) {
            try {
                auto ethHdr = packet->peekAtFront<inet::EthernetMacHeader>();
                if (srcMAC.empty()) srcMAC = ethHdr->getSrc().str();
                if (dstMAC.empty()) dstMAC = ethHdr->getDest().str();
            } catch (...) {}
        }
        if (auto pcpTag = packet->findTag<inet::PcpInd>()) { pcp = pcpTag->getPcp(); }
        if (auto vlanTag = packet->findTag<inet::VlanInd>()) { vlanId = vlanTag->getVlanId(); }
        if (auto labels = packet->findTag<inet::LabelsTag>()) {
            if (labels->getLabelsArraySize() > 0) streamId = labels->getLabels(0);
        }
        if (streamId.empty()) {
            // fallback composite stream key only if we have MACs
            if (!srcMAC.empty() && !dstMAC.empty())
                streamId = srcMAC + "->" + dstMAC + (pcp>=0? ("#pcp=" + std::to_string(pcp)) : "");
            else
                streamId = "unknown_stream";
        }

        if (signalName == "rxPkOk") {
            if (auto ct = packet->findTag<inet::CreationTimeTag>()) {
                double e2e = SIMTIME_DBL(simTime() - ct->getCreationTime());
                w_e2eSum += e2e; if (e2e > w_e2eMax) w_e2eMax = e2e; w_e2eCount++;
                // per-stream
                auto &agg = streamAggById[streamId];
                agg.e2eSum += e2e; agg.e2eCount++;
            }
            if (auto qt = packet->findTag<inet::QueueingTimeTag>()) {
                // queueing time accumulated in tag
                double qv = SIMTIME_DBL(qt->getPacketTotalTimes(0));
                w_queueingTimeSum += qv; w_queueingTimeCount++;
                auto &agg = streamAggById[streamId];
                agg.queueingSum += qv; agg.queueingCount++;
            }
        }
        // per-stream basic counters
        if (signalName == "packetReceivedFromLower" || signalName == "rxPkOk") {
            auto &agg = streamAggById[streamId];
            agg.packetsRx++; agg.rxBytes += bytes; if (signalName=="rxPkOk") agg.rxGood++;
            if (agg.pcp < 0) agg.pcp = pcp;
            if (agg.vlanId < 0) agg.vlanId = vlanId;
        }
        // Per-packet CSV write: log rxPkOk and MAC-context packetReceivedFromLower
        if (signalName == "rxPkOk" || signalName == "packetReceivedFromLower") {
            double ts = SIMTIME_DBL(simTime());
            // Derive module path and context
            std::string modulePath = source ? source->getFullPath().c_str() : "";
            bool isMacContext = (modulePath.find(".macLayer.") != std::string::npos) || (modulePath.find(".mac.") != std::string::npos);
            // Only at MAC receive context; skip PHY and other duplicates (packetReceivedFromLower is common)
            if (!isMacContext) { recordSignalEvent(source, signalID, value ? value->str() : ""); return; }
            // Require MAC addresses to avoid empty columns; otherwise skip row
            if (srcMAC.empty() || dstMAC.empty()) {
                recordSignalEvent(source, signalID, value ? value->str() : "");
                return;
            }
            // Key by MAC src+dst for dt computation
            std::string key = srcMAC + "->" + dstMAC;
            double dt = 0.0; auto it = packetCsv.lastTsByKey.find(key); if (it!=packetCsv.lastTsByKey.end()) dt = ts - it->second; packetCsv.lastTsByKey[key] = ts;
            // Maintain short stream history per key
            auto &rb = packetCsv.prevStreamsByKey[key];
            std::string p1 = rb.prev1(), p2 = rb.prev2(), p3 = rb.prev3();
            rb.push(streamId);
            // Derive run info and module metadata
            const std::string runId = currentConfigName + "-#" + std::to_string(currentRepetition);
            std::string node; int port = -1;
            std::string moduleName = signalName;
            if (source) { moduleName = source->getName(); }
            // Extract node (top-level submodule) from module path like MinimalAttackNetwork.centralSwitch.eth[1].macLayer
            node = "";
            {
                size_t p0 = modulePath.find('.');
                if (p0 != std::string::npos) {
                    size_t p1 = modulePath.find('.', p0 + 1);
                    if (p1 != std::string::npos) node = modulePath.substr(p0 + 1, p1 - p0 - 1);
                }
            }
            size_t ethPos = modulePath.find(".eth[");
            if (ethPos != std::string::npos) {
                size_t lb = modulePath.find('[', ethPos); size_t rbp = modulePath.find(']', lb);
                if (lb != std::string::npos && rbp != std::string::npos) {
                    try { port = std::stoi(modulePath.substr(lb+1, rbp-lb-1)); } catch(...) { port = -1; }
                }
            }
            // Ensure streamId not empty
            if (streamId.empty()) {
                if (auto st = packet->findTag<inet::StreamTagBase>()) { streamId = st->getStreamName(); }
                if (streamId.empty()) streamId = key + "#pcp=" + std::to_string(pcp);
            }
            // Write aligned row matching header columns
            packetCsv.writer.newRow();
            packetCsv.writer.add(runId);                       // run
            packetCsv.writer.add(currentRepetition);           // repetition
            packetCsv.writer.add(currentConfigName);           // config
            packetCsv.writer.add(node);                        // node
            packetCsv.writer.add(port);                        // port
            packetCsv.writer.add(modulePath);                  // module
            packetCsv.writer.add(moduleName);                  // name (module short name, varies)
            packetCsv.writer.add(ts);                          // ts
            packetCsv.writer.add(dt);                          // dt
            packetCsv.writer.add(streamId);                    // stream_id
            packetCsv.writer.add(p1);                          // prev1
            packetCsv.writer.add(p2);                          // prev2
            packetCsv.writer.add(p3);                          // prev3
            packetCsv.writer.add(srcMAC);                      // src_mac
            packetCsv.writer.add(dstMAC);                      // dst_mac
            packetCsv.writer.add((long)bytes);                 // len_bytes
            packetCsv.writer.add((long)packet->getTreeId());   // tree_id
            packetCsv.writer.add(signalName == "rxPkOk" ? 1 : 0); // rx_ok
            packetCsv.writer.writeToFile();
        }
    }
    recordSignalEvent(source, signalID, value ? value->str() : "");
}

void DataCollector::onGateStateChanged(std::unordered_map<std::string, GateState>& map, const std::string& gatePath, bool isOpen, double tNow)
{
    auto &st = map[gatePath];
    if (!st.hasState) {
        st.hasState = true;
        st.isOpen = isOpen;
        st.lastChange = tNow;
        return;
    }
    if (st.isOpen) {
        st.openTimeAccum += std::max(0.0, tNow - st.lastChange);
    }
    st.isOpen = isOpen;
    st.lastChange = tNow;
}

void DataCollector::recordSignalEvent(cComponent *source, simsignal_t signalID, const std::string& value)
{
    std::string signalName = getSignalName(signalID);
    
    // Aggregate into current window metrics
    if (signalName == "packetSentToLower") { w_packetsSent++; totalPacketsSent++; }
    else if (signalName == "packetReceivedFromLower" || signalName == "rxPkOk") { w_packetsReceived++; if (signalName=="rxPkOk") w_rxGood++; totalPacketsReceived++; }
    else if (signalName == "packetDropped") { w_packetsDropped++; totalPacketsDropped++; }
    else if (signalName == "packetPushEnded") {
        std::string q = source->getFullPath().c_str();
        // queue length integral update (+1)
        updateQueueLenIntegral(q, +1, SIMTIME_DBL(simTime()));
        auto &st = q_len_state_by_path[q];
        if (st.len > w_queueLenMax) w_queueLenMax = st.len;
    }
    else if (signalName == "packetPulled" || signalName == "packetRemoved") {
        std::string q = source->getFullPath().c_str();
        // queue length integral update (-1)
        updateQueueLenIntegral(q, -1, SIMTIME_DBL(simTime()));
    }
    else if (signalName == "localTime") { /* clock time seen; not aggregated */ }
    else if (signalName == "timeDifference") { double v = std::stod(value); w_gptpOffsetSum += v; w_gptpOffsetMax = std::max(w_gptpOffsetMax, v); w_gptpOffsetCount++; }
    else if (signalName == "rateRatio") { double v = std::stod(value); w_rateRatioSum += v; w_rateRatioCount++; }
    else if (signalName == "peerDelay") { double v = std::stod(value); w_peerDelaySum += v; w_peerDelayCount++; }
    else if (signalName == "tokensChanged") { double v = std::stod(value); w_tokensSum += v; w_tokensCount++; }
}

std::string DataCollector::getSignalName(simsignal_t signalID)
{
    const char* n = cComponent::getSignalName(signalID);
    return n ? std::string(n) : std::string();
}

void DataCollector::extractConfigFromFileName(const std::string& fileName)
{
    // Parse filename like "ml_models/tsn_signals_DoSAttack-#3.csv" 
    // to extract configName="DoSAttack" and repetition=3
    
    // Find pattern tsn_signals_CONFIGNAME-#NUMBER
    size_t prefixPos = fileName.find("tsn_signals_");
    if (prefixPos == std::string::npos) {
        currentConfigName = "Unknown";
        currentRepetition = 0;
        return;
    }
    
    size_t configStart = prefixPos + 12; // length of "tsn_signals_"
    size_t dashPos = fileName.find("-#", configStart);
    if (dashPos == std::string::npos) {
        currentConfigName = "Unknown";
        currentRepetition = 0;
        return;
    }
    
    // Extract config name
    currentConfigName = fileName.substr(configStart, dashPos - configStart);
    
    // Extract repetition number
    size_t repStart = dashPos + 2; // length of "-#"
    size_t dotPos = fileName.find(".", repStart);
    if (dotPos != std::string::npos) {
        std::string repStr = fileName.substr(repStart, dotPos - repStart);
        currentRepetition = atoi(repStr.c_str());
    } else {
        currentRepetition = 0;
    }
    
    EV_INFO << "📊 Extracted config: " << currentConfigName << ", repetition: " << currentRepetition << endl;
}

bool DataCollector::isRelevantModulePath(const std::string& path) const {
    static const char* patterns[] = {".mac", ".phy", ".macLayer.queue", ".queue[", ".bridging.streamFilter.ingress.meter", ".gptp", ".app[", ".udp", ".ipv4"};
    for (auto p : patterns) if (path.find(p) != std::string::npos) return true;
    return false;
}

void DataCollector::resetTypedWindowAggregates() {
    w_packetsSent = w_packetsReceived = w_packetsDropped = 0;
    w_rxGood = 0;
    w_txBytes = w_rxBytes = 0;
    // Maintain queue states across windows; reset integrals and timestamps at window boundary
    if (windowCount == 0) {
        q_len_by_path.clear();
        q_len_state_by_path.clear();
        q_bit_by_path.clear();
    } else {
        for (auto &kv : q_len_state_by_path) {
            kv.second.timeIntegral = 0.0;
            kv.second.lastChange = currentWindowStart;
        }
        // keep q_bit_by_path as current bits per queue
    }
    w_queueLenMax = 0;
    w_queueBitlenMax = 0;
    w_queueingTimeSum = 0.0; w_queueingTimeCount = 0;
    w_e2eSum = 0.0; w_e2eMax = 0.0; w_e2eCount = 0;
    // Maintain gate states across windows so fractions are correct even if no change occurs in the window
    for (auto &kv : gatePathToState) {
        kv.second.openTimeAccum = 0.0;
        kv.second.lastChange = currentWindowStart;
    }
    for (auto &kv : guardPathToState) {
        kv.second.openTimeAccum = 0.0;
        kv.second.lastChange = currentWindowStart;
    }
    w_gptpOffsetSum = 0.0; w_gptpOffsetMax = 0.0; w_gptpOffsetCount = 0;
    w_rateRatioSum = 0.0; w_rateRatioCount = 0;
    w_peerDelaySum = 0.0; w_peerDelayCount = 0;
    w_tokensSum = 0.0; w_tokensCount = 0;
}

void DataCollector::updateQueueLenIntegral(const std::string& qpath, long deltaLen, double tNow)
{
    auto &st = q_len_state_by_path[qpath];
    // Accumulate time integral up to now
    double tPrev = st.lastChange > 0.0 ? st.lastChange : currentWindowStart;
    if (tNow >= tPrev) {
        st.timeIntegral += st.len * (tNow - tPrev);
    }
    st.len = std::max(0L, st.len + deltaLen);
    st.lastChange = tNow;
}
