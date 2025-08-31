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
  - Note: Per-color counters don't exist; derive stream/color via LabelsTag.

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
#include "inet/common/packet/Packet.h"
#include "inet/linklayer/common/MacAddressTag_m.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/linklayer/ethernet/common/EthernetMacHeader_m.h"
#include "inet/queueing/common/LabelsTag_m.h"
#include "inet/linklayer/common/UserPriorityTag_m.h"
#include "inet/linklayer/common/PcpTag_m.h"
#include "inet/linklayer/common/VlanTag_m.h"
#include "inet/protocolelement/redundancy/StreamTag_m.h"
#include "inet/linklayer/ieee8021q/Ieee8021qTagHeader_m.h"

Define_Module(DataCollector);

static bool isControlFrame(const inet::Packet* pk) {
    try {
        auto eth = pk->peekAtFront<inet::EthernetMacHeader>();
        auto da  = eth->getDest();
        unsigned char b[6];
        da.getAddressBytes(b);
        if ((b[0] & 0x01) == 0x01) {
            if (b[0]==0x01 && b[1]==0x80 && b[2]==0xC2) return true;
        }
        auto type = eth->getTypeOrLength();
        return type==0x88CC || type==0x88F7 || type==0x8808;
    } catch (...) { return false; }
}

int DataCollector::parsePortIndexFromPath(const std::string& path) const {
    size_t e = path.find(".eth[");
    if (e == std::string::npos) e = path.find(".ethg[");
    if (e == std::string::npos) return -1;
    size_t lb = path.find('[', e);
    size_t rb = path.find(']', lb);
    if (lb==std::string::npos || rb==std::string::npos) return -1;
    try { return std::stoi(path.substr(lb+1, rb-lb-1)); } catch(...) { return -1; }
}

int DataCollector::parseGateIndexFromPath(const std::string& path) const {
    size_t g = path.find(".transmissionGate[");
    if (g == std::string::npos) return -1;
    size_t lb = path.find('[', g);
    size_t rb = path.find(']', lb);
    if (lb==std::string::npos || rb==std::string::npos) return -1;
    try { return std::stoi(path.substr(lb+1, rb-lb-1)); } catch(...) { return -1; }
}

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
    if (subscribeTimer) {
        cancelAndDelete(subscribeTimer);
        subscribeTimer = nullptr;
    }
    // CsvWriter closes on destruction
}

void DataCollector::initialize()
{
    EV_INFO << "🎯 [DataCollector] Initializing ML-ready data collection with time-windowed aggregation" << endl;
    
    // Get parameters from NED file
    std::string outputFileParam = par("outputFile").stringValue();
    windowSize = par("windowLength").doubleValue();
    if (windowSize <= 0) {
        EV_WARN << "[DataCollector] windowLength <= 0; defaulting to 1ms\n";
        windowSize = 0.001;
    }
    emitCSV = par("emitCSV").boolValue();
    emitJSON = par("emitRaw").boolValue(); // raw JSON per event
    emitNDJSON = par("emitNDJSON").boolValue();
    diag = hasPar("diag") ? par("diag").boolValue() : false;
    if (!diag) {
        const char* dv = getenv("DC_DIAG");
        if (dv && (strcmp(dv, "1")==0 || strcmp(dv, "true")==0 || strcmp(dv, "TRUE")==0)) diag = true;
    }
    if (hasPar("emitPerStreamRows")) emitPerStreamRows = par("emitPerStreamRows").boolValue();
    if (hasPar("includeControlFramesInThroughput")) includeControlFramesInThroughput = par("includeControlFramesInThroughput").boolValue();
    if (hasPar("emitZeroIfNoSamples")) emitZeroIfNoSamples = par("emitZeroIfNoSamples").boolValue();
    
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
    
    // Validate presence of key module paths (single concrete instance check)
    const char* checkPaths[] = {
        "MinimalAttackNetwork.centralSwitch.eth[0].macLayer",
        "MinimalAttackNetwork.centralSwitch.eth[0].macLayer.queue",
        "MinimalAttackNetwork.centralSwitch.eth[0].macLayer.queue.transmissionGate[0]",
        "MinimalAttackNetwork.centralSwitch.bridging.streamFilter.ingress.meter[0]",
        "MinimalAttackNetwork.centralSwitch.bridging.streamFilter.ingress.filter[0]"
    };
    for (auto p : checkPaths) {
        if (!getSimulation()->findModuleByPath(p)) {
            EV_ERROR << "[DC] Missing path: " << p << endl;
        }
    }

    // Build MAC -> node name map and precompute queue paths per port
    macToNodeName.clear(); queuePathByPort.clear();
    if (auto *root = getSystemModule()) {
        std::vector<cModule*> stack; stack.push_back(root);
        while(!stack.empty()) {
            cModule *m = stack.back(); stack.pop_back();
            std::string path = m->getFullPath().c_str();
            // capture eth[*] interface address parameter if present (LayeredEthernetInterface has 'address')
            if (path.find(".eth[") != std::string::npos && path.find(".macLayer") == std::string::npos && path.find(".mac.") == std::string::npos) {
                bool recorded = false;
                if (m->hasPar("address")) {
                    std::string mac = m->par("address").stdstringValue();
                    std::transform(mac.begin(), mac.end(), mac.begin(), ::tolower);
                    if (!mac.empty() && mac != "auto") {
                        std::string node = path.substr(0, path.find(".eth["));
                        if (!macToNodeName.count(mac)) {
                            macToNodeName[mac] = node;
                        }
                        recorded = true;
                    }
                }
                // Fallback: read MAC from macLayer.mac.address
                if (!recorded) {
                    size_t e = path.find(".eth[");
                    size_t lb = path.find('[', e);
                    size_t rb = path.find(']', lb);
                    if (e != std::string::npos && lb != std::string::npos && rb != std::string::npos) {
                        std::string node = path.substr(0, e);
                        std::string idx = path.substr(lb+1, rb-lb-1);
                        std::string macPath = node + ".eth[" + idx + "].macLayer.mac";
                        if (auto macMod = getSimulation()->findModuleByPath(macPath.c_str())) {
                            if (macMod->hasPar("address")) {
                                std::string mac = macMod->par("address").stdstringValue();
                                std::transform(mac.begin(), mac.end(), mac.begin(), ::tolower);
                                if (!mac.empty() && mac != "auto") {
                                    if (!macToNodeName.count(mac)) {
                                        macToNodeName[mac] = node;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // precompute queue path for centralSwitch ports
            if (path.rfind("MinimalAttackNetwork.centralSwitch.eth[",0)==0 && path.find(".macLayer.queue")!=std::string::npos && path.find(".macLayer.queue.")==std::string::npos) {
                int port = parsePortIndexFromPath(path);
                if (port>=0) queuePathByPort[port] = path;
            }
            for (cModule::SubmoduleIterator it(m); !it.end(); ++it) stack.push_back(*it);
        }
    }

    // Initialize signal subscriptions (deferred until submodules ready)
    if (!subscribeTimer) subscribeTimer = new cMessage("subscribeTimer");
    scheduleAt(simTime() + SimTime(0), subscribeTimer);
    
    // Initialize window tracking
    currentWindowStart = 0.0;
    resetWindowMetrics();
    
    // Set up periodic window flushing
    if (!windowTimer) {
        windowTimer = new cMessage("windowTimer");
    }
    scheduleAt(SimTime(currentWindowStart + windowSize), windowTimer);
    
    // Open output file and write header if CSV (final slim schema; single file)
    if (emitCSV) {
        CsvWriter writer(outputFile);
        if (!writer.good()) {
            throw cRuntimeError("Failed to open CSV output file: %s", outputFile.c_str());
        }
        csv = std::move(writer);
        writeCSVHeader();

        // Open secondary window-level CSV alongside per-packet CSV
        std::string windowFile = outputFile;
        size_t sigpos = windowFile.find("tsn_signals_");
        if (sigpos != std::string::npos) {
            windowFile.replace(sigpos, std::string("tsn_signals_").size(), "window_features_");
        } else {
            // Fallback: append .windows before extension
            size_t dotp = windowFile.rfind('.');
            if (dotp != std::string::npos) windowFile.insert(dotp, ".windows");
            else windowFile += ".windows.csv";
        }
        CsvWriter wwriter(windowFile);
        if (!wwriter.good()) {
            throw cRuntimeError("Failed to open window CSV output file: %s", windowFile.c_str());
        }
        streamCsv = std::move(wwriter);
        // Header aligned with training pipeline expectations + servo/sink observables
        streamCsv.setHeader({
            "throughput_bps_tx","throughput_bps_rx",
            "packets_sent","packets_received","packets_dropped",
            "drop_rate","queue_length_max",
            // gPTP servo observables (per-window aggregates)
            "ptp_offset_mean","ptp_offset_max","rate_ratio_mean","peer_delay_mean",
            // Receiver-side timing outcomes
            "e2e_delay_avg","e2e_delay_max","e2e_delay_std",
            // Sample counters for masking/imputation
            "ptp_samples","e2e_samples",
            // Label last
            "label"
        });
    }
    
    EV_INFO << "✅ DataCollector initialized and ready for ML data collection!" << endl;
}

void DataCollector::handleMessage(cMessage *msg)
{
    if (msg == subscribeTimer) {
        // Perform deferred subscriptions now that submodules exist
        if (!subscriptionsDone) {
            // 1) Subscribe to MAC egress/ingress per node: **.eth[*].macLayer → packetSentToLower, rxPkOk
            int macSubCount = 0;
            // 2) Subscribe to switch MAC queues: MinimalAttackNetwork.centralSwitch.eth[*].macLayer.queue → push/pull/remove/drop
            int queueSubCount = 0;
            // 3) Subscribe TAS gates: ...queue.transmissionGate[*] → gateStateChanged
            int gateSubCount = 0;
            // 4) Subscribe PSFP meters: ...ingress.meter[*] → packetPushedOut
            int meterSubCount = 0;
            // 5) Subscribe PSFP filters: ...ingress.filter[*] → packetDropped
            int filterSubCount = 0;

            // Scan entire hierarchy and attach by path patterns
            if (auto *root = getSystemModule()) {
                std::vector<cModule*> stack; stack.push_back(root);
                while(!stack.empty()) {
                        cModule *m = stack.back(); stack.pop_back();
                    std::string path = m->getFullPath().c_str();

                    // MAC layer aggregator on any eth[*]
                    if (path.find(".eth[") != std::string::npos) {
                        size_t ml = path.find(".macLayer");
                        if (ml != std::string::npos && path.find(".macLayer.", ml) == std::string::npos) {
                            // Subscribe to mac-layer signals
                            m->subscribe("packetSentToLower", this); subCountBySignal["packetSentToLower"]++; macSubCount++;
                            m->subscribe("rxPkOk", this); subCountBySignal["rxPkOk"]++; macSubCount++;
                            m->subscribe("packetReceivedFromLower", this); subCountBySignal["packetReceivedFromLower"]++; macSubCount++;
                            m->subscribe("packetDropped", this); subCountBySignal["packetDropped.mac"]++; macSubCount++;
                            if (diag) { EV_INFO << "[SUB] " << path << " : packetSentToLower\n"; EV_INFO << "[SUB] " << path << " : rxPkOk\n"; }
                        }
                    }

                    // Switch queues under centralSwitch
                    if (path.rfind("MinimalAttackNetwork.centralSwitch.eth[", 0) == 0 && path.find(".macLayer.queue") != std::string::npos && path.find(".macLayer.queue.") == std::string::npos) {
                        m->subscribe("packetPushStarted", this); subCountBySignal["packetPushStarted"]++; queueSubCount++;
                        m->subscribe("packetPushEnded", this);   subCountBySignal["packetPushEnded"]++;   queueSubCount++;
                        m->subscribe("packetPulled", this);       subCountBySignal["packetPulled"]++;       queueSubCount++;
                        m->subscribe("packetRemoved", this);      subCountBySignal["packetRemoved"]++;      queueSubCount++;
                        m->subscribe("packetDropped", this);      subCountBySignal["packetDropped"]++;      queueSubCount++;
                        
                    }

                    // TAS gates
                    if (path.find(".macLayer.queue.transmissionGate[") != std::string::npos) {
                        m->subscribe("gateStateChanged", this); subCountBySignal["gateStateChanged"]++; gateSubCount++;
                        m->subscribe("guardBandStateChanged", this); subCountBySignal["guardBandStateChanged"]++; gateSubCount++;
                    }

                    // PSFP meters (support both 'packetPushedOut' and 'packetPushed')
                    if (path.find(".bridging.streamFilter.ingress.meter[") != std::string::npos) {
                        m->subscribe("packetPushedOut", this); subCountBySignal["packetPushedOut"]++; meterSubCount++;
                        m->subscribe("packetPushed", this);    subCountBySignal["packetPushed"]++;    meterSubCount++;
                    }

                    // PSFP filters (support both 'packetDropped' and 'packetFiltered')
                    if (path.find(".bridging.streamFilter.ingress.filter[") != std::string::npos) {
                        m->subscribe("packetDropped", this); subCountBySignal["filter.packetDropped"]++; filterSubCount++;
                        m->subscribe("packetFiltered", this); subCountBySignal["filter.packetFiltered"]++; filterSubCount++;
                    }

                    // gPTP servo under each participant
                    if (path.find(".gptp") != std::string::npos) {
                        m->subscribe("timeDifference", this); subCountBySignal["timeDifference"]++;
                        m->subscribe("rateRatio", this);      subCountBySignal["rateRatio"]++;
                        m->subscribe("peerDelay", this);       subCountBySignal["peerDelay"]++;
                    }

                    // Application sinks (packetReceived)
                    if (path.find(".app[") != std::string::npos) {
                        m->subscribe("packetReceived", this); subCountBySignal["packetReceived"]++;
                    }

                    for (cModule::SubmoduleIterator it(m); !it.end(); ++it) stack.push_back(*it);
                }
            }

            // Stage-3: no subscription count debug

            subscriptionsDone = true;
        }
    } else if (msg == windowTimer) {
        // 1) Flush the window that ended at (currentWindowStart + windowSize)
        flushCurrentWindow();

        // 2) Advance the window anchor deterministically (fixed cadence)
        const double tNextStart = currentWindowStart + windowSize;
        currentWindowStart = tNextStart;

        // 3) Reset per-window state AFTER advancing start (so lastChange baselines are correct)
        resetWindowMetrics();

        // 4) Schedule the next boundary strictly from the anchor (no drift)
        scheduleAt(SimTime(tNextStart + windowSize), windowTimer);
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
        streamCsv.flush();
    }

    // Print compact summary only
    EV_INFO << "📊 DataCollector Summary:" << endl;
    EV_INFO << "   Total packets sent: " << totalPacketsSent << endl;
    EV_INFO << "   Total packets received: " << totalPacketsReceived << endl;
    EV_INFO << "   Total packets dropped: " << totalPacketsDropped << endl;
    EV_INFO << "   Windows processed: " << windowCount << endl;
    EV_INFO << "   Output file: " << outputFile << endl;

    if (diag) {
        for (const auto &kv : txPkByPort) {
            int p = kv.first;
            long txB = txBytesByPort[p];
            long rxB = rxBytesByPort[p];
            long dq = dropQueueByPort[p];
            long dm = dropMacByPort[p];
            EV_INFO << "[PORT] p=" << p
                    << " txPk=" << kv.second
                    << " rxPk=" << (rxPkByPort.count(p)?rxPkByPort[p]:0)
                    << " txB=" << txB
                    << " rxB=" << rxB
                    << " drop.queue=" << dq
                    << " drop.mac=" << dm << "\n";
        }
    }
    
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
        // App sinks
        "packetReceived",
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
    seenVantagePacketKeys.clear();
    psfp_ccp_sum = psfp_cnp_sum = psfp_ecp_sum = psfp_filtered_sum = 0;
    for (int i=0;i<8;i++) { w_txBitsPcp[i]=0; w_rxBitsPcp[i]=0; w_enqOkPcp[i]=0; w_dropsPcp[i]=0; w_queueLenMaxPcp[i]=0; w_queueLenIntegralPcp[i]=0; }
    resetTypedWindowAggregates();
    streamAggById.clear();
}

void DataCollector::flushCurrentWindow()
{
    // Window-level CSV write (secondary file)
    if (emitCSV) {
        double t1 = SIMTIME_DBL(simTime());
        double dur = t1 - currentWindowStart;
        if (dur > 1e-12) {
            double thrTx = (dur > 0) ? ((double)w_txBits / dur) : 0.0;
            double thrRx = (dur > 0) ? ((double)w_rxBits / dur) : 0.0;
            long sent = (long)w_packetsSent;
            long received = (long)w_packetsReceived;
            long dropped = (long)w_packetsDropped;
            double denom = (double)sent + (double)received + (double)dropped;
            double dropRate = denom > 0.0 ? ((double)dropped / denom) : 0.0;
            long qlenMax = (long)w_queueLenMax;
            // gPTP servo aggregates (means over events in the window) with NA semantics
            auto noneVal = emitZeroIfNoSamples ? 0.0 : -1.0;
            double offsetMean = (w_gptpOffsetCount>0) ? (w_gptpOffsetSum / (double)w_gptpOffsetCount) : noneVal;
            double offsetMax  = (w_gptpOffsetCount>0) ? w_gptpOffsetMax : noneVal;
            double rateMean   = (w_rateRatioCount>0) ? (w_rateRatioSum / (double)w_rateRatioCount) : noneVal;
            double pdelayMean = (w_peerDelayCount>0) ? (w_peerDelaySum / (double)w_peerDelayCount) : noneVal;
            // Receiver-side e2e stats with NA semantics
            double e2eAvg = (w_sinkE2eCount>0) ? (w_sinkE2eSum / (double)w_sinkE2eCount) : noneVal;
            double e2eMax = (w_sinkE2eCount>0) ? w_sinkE2eMax : noneVal;
            double e2eStd = noneVal;
            if (w_sinkE2eCount>1) {
                double mean = (w_sinkE2eSum / (double)w_sinkE2eCount);
                double var = std::max(0.0, (w_sinkE2eSumSq / (double)w_sinkE2eCount) - mean*mean);
                e2eStd = std::sqrt(var);
            }
            std::string label = determineLabelForWindow(currentWindowStart, t1);
            streamCsv.newRow();
            streamCsv.add(thrTx);
            streamCsv.add(thrRx);
            streamCsv.add((double)sent);
            streamCsv.add((double)received);
            streamCsv.add((double)dropped);
            streamCsv.add(dropRate);
            streamCsv.add((double)qlenMax);
            streamCsv.add(offsetMean);
            streamCsv.add(offsetMax);
            streamCsv.add(rateMean);
            streamCsv.add(pdelayMean);
            streamCsv.add(e2eAvg);
            streamCsv.add(e2eMax);
            streamCsv.add(e2eStd);
            streamCsv.add((double)ptp_samples);
            streamCsv.add((double)e2e_samples);
            streamCsv.add(label);
            streamCsv.writeToFile();

            // Populate minimal 7-feature shared window (legacy for compatibility)
            lastWindow_.f[0] = thrTx;
            lastWindow_.f[1] = thrRx;
            lastWindow_.f[2] = (double)sent;
            lastWindow_.f[3] = (double)received;
            lastWindow_.f[4] = (double)dropped;
            lastWindow_.f[5] = dropRate;
            lastWindow_.f[6] = (double)w_queueLenMax;
            lastWindow_.t0 = SimTime(currentWindowStart);
            lastWindow_.t1 = SimTime(t1);
            lastWindow_.ready = true;

            // Populate extended 15-feature vector aligned to training feature_order
            // [throughput_bps_tx, packets_sent, packets_received, packets_dropped, drop_rate, queue_length_max,
            //  ptp_offset_mean, ptp_offset_max, rate_ratio_mean, peer_delay_mean,
            //  e2e_delay_avg, e2e_delay_max, e2e_delay_std, has_ptp, has_e2e]
            lastWindowExt_.f[0]  = thrTx;
            lastWindowExt_.f[1]  = (double)sent;
            lastWindowExt_.f[2]  = (double)received;
            lastWindowExt_.f[3]  = (double)dropped;
            lastWindowExt_.f[4]  = dropRate;
            lastWindowExt_.f[5]  = (double)qlenMax;
            lastWindowExt_.f[6]  = offsetMean;
            lastWindowExt_.f[7]  = offsetMax;
            lastWindowExt_.f[8]  = rateMean;
            lastWindowExt_.f[9]  = pdelayMean;
            lastWindowExt_.f[10] = e2eAvg;
            lastWindowExt_.f[11] = e2eMax;
            lastWindowExt_.f[12] = e2eStd;
            lastWindowExt_.f[13] = (ptp_samples > 0) ? 1.0 : 0.0;
            lastWindowExt_.f[14] = (e2e_samples > 0) ? 1.0 : 0.0;
            lastWindowExt_.t0 = SimTime(currentWindowStart);
            lastWindowExt_.t1 = SimTime(t1);
            lastWindowExt_.ready = true;
        }
    }
    
    // Stage 3 diagnostics and maintenance
    windowCount++;
    if (diag) {
        // [EVT] per-window event counters
        std::stringstream ss;
        ss << "[EVT] window [" << currentWindowStart << "," << SIMTIME_DBL(simTime()) << ")";
        for (const auto &kv : windowEvtCounts) {
            if (kv.second > 0) ss << "  " << kv.first << "=" << kv.second;
        }
        EV_INFO << ss.str() << "\n";
        windowEvtCounts.clear();
        if (hadQueueEventThisWindow && w_queueLenMax == 0) {
            EV_WARN << "[CHECK] queue integral didn't move despite queue events" << "\n";
        }
        // Top contributing queue paths (compact)
        std::vector<std::pair<std::string,double>> contrib;
        for (const auto &kv : q_len_state_by_path) {
            if (kv.first.rfind(vantageQueuePrefix,0)==0) {
                contrib.emplace_back(kv.first, kv.second.timeIntegral);
            }
        }
        std::sort(contrib.begin(), contrib.end(), [](auto &a, auto &b){return a.second>b.second;});
        std::stringstream qs; qs << "[CHECK] queue contributors:";
        for (size_t i=0;i<std::min<size_t>(10, contrib.size()); ++i) qs << "  (" << contrib[i].first << "," << contrib[i].second << ")";
        EV_INFO << qs.str() << "\n";
        // Δlen invariant per path
        for (auto &kv : q_len_state_by_path) {
            const std::string &qpath = kv.first;
            if (qpath.rfind(vantageQueuePrefix,0)!=0) continue;
            long enq = 0, deq = 0, dr = 0;
            std::string k1 = qpath + ":packetPushEnded";
            std::string k2 = qpath + ":packetPulled";
            std::string k3 = qpath + ":packetRemoved";
            std::string k4 = qpath + ":packetDropped";
            if (windowEvtCounts.count(k1)) enq += windowEvtCounts[k1];
            if (windowEvtCounts.count(k2)) deq += windowEvtCounts[k2];
            if (windowEvtCounts.count(k3)) deq += windowEvtCounts[k3];
            if (windowEvtCounts.count(k4)) dr  += windowEvtCounts[k4];
            long dlen = enq - (deq + dr);
            if (std::labs(dlen) > 0) EV_WARN << "[CHECK] Δlen mismatch on " << qpath << ": enq=" << enq << ", deq=" << deq << ", drop=" << dr << ", Δ=" << dlen << "\n";
        }
    }
    // Clear per-stream accumulators for next window
    streamAggById.clear();
}

void DataCollector::writeCSVHeader()
{
    // Canonical per-packet schema for tsn_signals_*.csv (egress rows + filter-drop rows)
    std::vector<std::string> header = {
        "run","t","streamName",
        "srcMACdec","dstMACdec","pcp","vid","lenB","qLenBits",
        "gateState","meter_conform","meter_exceed","meter_filtered"
    };
    csv.setHeader(header);
}

void DataCollector::writeCSVRecord()
{
    simtime_t currentTime = simTime();
    double windowEnd = currentTime.dbl();
    double windowDur = windowEnd - currentWindowStart;
    if (windowDur <= 1e-12) return; // drop zero-length flush
    
    // Calculate derived metrics (vantage-only)
    int sent = (int)w_packetsSent;              // MAC tx packets
    int received = (int)w_packetsReceived;      // MAC rx good packets
    int dropped = (int)w_packetsDropped;        // queue drops
    int totalArrivals = dropped;
    long enqSum = 0; for (int i=0;i<8;i++) { totalArrivals += (int)w_enqOkPcp[i]; enqSum += w_enqOkPcp[i]; }
    double lossRate = (totalArrivals > 0) ? ((double)dropped / (double)totalArrivals) : 0.0;
    double thrTx = (windowDur > 0) ? ((double)w_txBits / windowDur) : 0.0; // bits/sec
    double thrRx = (windowDur > 0) ? ((double)w_rxBits / windowDur) : 0.0; // bits/sec
    
    // Gate fractions (average across gates per window; kept out of CSV per current schema)
    auto avgFracAcrossGates = [&](const std::unordered_map<std::string, GateState>& mp) {
        if (windowDur <= 0.0) return 0.0;
        double end = windowEnd;
        double sumFrac = 0.0;
        int n = 0;
        for (const auto &kv : mp) {
            const auto &gs = kv.second;
            if (!gs.hasState) continue;
            double last = std::max(gs.lastChange, currentWindowStart);
            double open = gs.openTimeAccum;
            if (gs.isOpen) open += std::max(0.0, end - last);
            double frac = open / windowDur;
            if (frac < 0.0) frac = 0.0; else if (frac > 1.0) frac = 1.0;
            sumFrac += frac;
            n++;
        }
        return (n > 0) ? (sumFrac / (double)n) : 0.0;
    };
    double gateOpenAvg = avgFracAcrossGates(gatePathToState);
    double guardbandAvg = avgFracAcrossGates(guardPathToState);
    windowMetrics["gate_open_fraction_avg"] = gateOpenAvg;
    windowMetrics["guardband_fraction_avg"] = guardbandAvg;
    
    // Queue length average via time integral across vantage queues only
    double qlenAvg = 0.0;
    if (windowDur > 0.0 && !q_len_state_by_path.empty()) {
        double sumInt = 0.0;
        for (auto &kv : q_len_state_by_path) {
            const auto &st = kv.second;
            // Only include vantage queue paths
            if (kv.first.rfind(vantageQueuePrefix, 0) != 0) continue;
            double tPrev = st.lastChange > 0.0 ? st.lastChange : currentWindowStart;
            double contrib = st.timeIntegral + st.len * std::max(0.0, windowEnd - std::max(currentWindowStart, tPrev));
            sumInt += contrib;
            // Per-PCP queue integrals: map sub-queue index to PCP
            std::string qpath = kv.first;
            size_t qi = qpath.find(".queue[");
            if (qi != std::string::npos) {
                size_t lb = qpath.find('[', qi); size_t rb = qpath.find(']', lb);
                if (lb!=std::string::npos && rb!=std::string::npos) {
                    int p = -1; try { p = std::stoi(qpath.substr(lb+1, rb-lb-1)); } catch(...) { p=-1; }
                    if (p>=0 && p<8) {
                        double integral = st.timeIntegral + st.len * std::max(0.0, windowEnd - std::max(currentWindowStart, tPrev));
                        w_queueLenIntegralPcp[p] += integral;
                        if (st.len > w_queueLenMaxPcp[p]) w_queueLenMaxPcp[p] = st.len;
                    }
                }
            }
        }
        qlenAvg = sumInt / windowDur;
    }
    
    // Expose minimal 7-feature vector for engine pull (aligned to vantage metrics)
    lastWindow_.f[0] = thrTx;
    lastWindow_.f[1] = thrRx;
    lastWindow_.f[2] = sent;
    lastWindow_.f[3] = received;
    lastWindow_.f[4] = dropped;
    lastWindow_.f[5] = lossRate;
    lastWindow_.f[6] = (double)w_queueLenMax;
    lastWindow_.t0 = SimTime(currentWindowStart);
    lastWindow_.t1 = SimTime(windowEnd);
    lastWindow_.ready = true;
    
    // Determine label based on simulation time and scenario (half-open [start,end))
    std::string label = determineLabelForWindow(currentWindowStart, windowEnd);
    
    std::string configName = currentConfigName;
    int repetition = currentRepetition;
    const std::string runId = configName + "-#" + std::to_string(repetition);
    if (false) { // window-level CSV disabled: tsn_signals.csv is per-packet egress only
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
        bool emitPCP2 = hasPar("emitPCPBreakdowns") ? par("emitPCPBreakdowns").boolValue() : true;
        if (emitPCP2) {
            for (int p=0;p<8;p++) csv.add((windowDur>0)? ((double)w_txBitsPcp[p]/windowDur) : 0.0);
            for (int p=0;p<8;p++) csv.add((windowDur>0)? ((double)w_rxBitsPcp[p]/windowDur) : 0.0);
            for (int p=0;p<8;p++) { long denom = w_dropsPcp[p] + w_enqOkPcp[p]; double dr = denom>0? ((double)w_dropsPcp[p]/(double)denom) : 0.0; csv.add(dr); }
            for (int p=0;p<8;p++) csv.add((double)w_queueLenMaxPcp[p]);
            for (int p=0;p<8;p++) csv.add((windowDur>0)? (w_queueLenIntegralPcp[p]/windowDur) : 0.0);
        }
        csv.add((double)psfp_ccp_sum);
        csv.add((double)psfp_cnp_sum);
        csv.add((double)psfp_ecp_sum);
        csv.add((double)psfp_filtered_sum);
        csv.writeToFile();
    }
}

std::string DataCollector::determineLabelForWindow(double windowStart, double windowEnd)
{
    // Determine attack label based on scenario configuration and time window
    // Use cached config name
    std::string configName = currentConfigName;
    
    if (configName == "Baseline") {
        return "normal";
    } else if (configName == "DoSAttack") {
        // DoS attack runs from 100ms to 400ms
        auto overlaps = [](double ws, double we, double as, double ae){
            const double eps = 1e-12;
            return (ws < ae - eps) && (we > as + eps);
        };
        if (overlaps(windowStart, windowEnd, 0.100, 0.400)) {
            return "dos_attack";
        }
        return "normal";
    } else if (configName == "TimingAttack") {
        // Timing attack runs from 50ms to 450ms
        auto overlaps = [](double ws, double we, double as, double ae){
            const double eps = 1e-12;
            return (ws < ae - eps) && (we > as + eps);
        };
        if (overlaps(windowStart, windowEnd, 0.050, 0.450)) {
            return "timing_attack";
        }
        return "normal";
    } else if (configName == "SpoofingAttack") {
        // Spoofing attack runs from 150ms to 350ms
        auto overlaps = [](double ws, double we, double as, double ae){
            const double eps = 1e-12;
            return (ws < ae - eps) && (we > as + eps);
        };
        if (overlaps(windowStart, windowEnd, 0.150, 0.350)) {
            return "spoofing_attack";
        }
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
        // Maintain last gate state per port (boolean)
        int port = parsePortIndexFromPath(gatePath);
        if (port>=0) lastGateOpenByPort[port] = value ? 1 : 0;
    } else if (signalName == "guardBandStateChanged") {
        std::string guardPath = source->getFullPath().c_str();
        onGateStateChanged(guardPathToState, guardPath, value, tNow);
    }
    eventsSeenBySignal[signalName]++;
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
    recordSignalEvent(source, signalID, std::to_string(SIMTIME_DBL(value)));
}

void DataCollector::receiveSignal(cComponent *source, simsignal_t signalID, const char *value, cObject *details)
{
    recordSignalEvent(source, signalID, value ? value : "");
}

void DataCollector::receiveSignal(cComponent *source, simsignal_t signalID, cObject *value, cObject *details)
{
    std::string signalName = getSignalName(signalID);
    // Packet-based signals: accumulate per vantage using MAC/queue path filters
    auto packet = dynamic_cast<inet::Packet*>(value);
    if (packet) {
        // Count event upfront (even if we early-return due to missing tags)
        eventsSeenBySignal[signalName]++;
        long bits = (long)packet->getTotalLength().get(); // bits if available
        if (bits <= 0) {
            // Fallback: compute from byte length if totalLength not populated
            long bl = (long)packet->getByteLength();
            if (bl > 0) bits = bl * 8;
        }
        long bytes = (bits > 0) ? (bits / 8) : (long)std::max<long>(0L, (long)packet->getByteLength());
        std::string modulePath = source ? source->getFullPath().c_str() : "";
        bool isVantageMac = (modulePath.find(vantageMacPrefix) != std::string::npos) ||
                            (modulePath.rfind("MinimalAttackNetwork.centralSwitch.eth[", 0) == 0);
        bool isVantageQueue = modulePath.rfind(vantageQueuePrefix, 0) == 0;
        // diagnostics: per-window event counts (only for known signal set)
        if (diag) {
            if (isVantageMac || isVantageQueue || modulePath.rfind(centralSwitchMeterPrefix,0)==0 || modulePath.find("bridging.streamFilter.ingress.filter")!=std::string::npos) {
                std::string key = modulePath + ":" + signalName;
                windowEvtCounts[key]++;
            }
        }
        auto getPcp = [&](const inet::Packet* pk)->int {
            if (auto t = pk->findTag<inet::UserPriorityInd>()) return t->getUserPriority();
            if (auto t = pk->findTag<inet::UserPriorityReq>()) return t->getUserPriority();
            if (auto t = pk->findTag<inet::PcpInd>()) return t->getPcp();
            return 0;
        };
        auto getStreamId = [&](const inet::Packet* pk)->std::string {
            // Prefer StreamInd/StreamReq stream name per INET StreamTag.msg
            if (auto sind = pk->findTag<inet::StreamInd>()) {
                const char *sn = sind->getStreamName();
                if (sn && *sn) { streamIdTagSeenCount++; return std::string(sn); }
            }
            if (auto sreq = pk->findTag<inet::StreamReq>()) {
                const char *sn = sreq->getStreamName();
                if (sn && *sn) { streamIdTagSeenCount++; return std::string(sn); }
            }
            // Fallback handled by caller with MAC pair
            streamIdFallbackCount++;
            return std::string();
        };

        // Trimmed: no verbose per-event debug prints

        if (signalName == "packetPushStarted") {
            // Start: update bitlength and remember PCP to resolve acceptance on pushEnded
            std::string q = source->getFullPath().c_str();
            long &qb = q_bit_by_path[q]; qb = std::max(0L, qb + bits); if (qb > w_queueBitlenMax) w_queueBitlenMax = qb;
            if (isVantageQueue) {
                int p = getPcp(packet);
                q_pendingPcpByPath[q].push_back(p);
                if (p>=0 && p<8) {
                    double now = SIMTIME_DBL(simTime());
                    double tPrev = qlenPcpLastChange[p] > 0.0 ? qlenPcpLastChange[p] : currentWindowStart;
                    if (now >= tPrev) qlenPcpIntegral[p] += qlenPcp[p] * (now - tPrev);
                    qlenPcp[p] += 1;
                    qlenPcpLastChange[p] = now;
                    if (qlenPcp[p] > w_queueLenMaxPcp[p]) w_queueLenMaxPcp[p] = qlenPcp[p];
                    if (diag && sampleQueueEvents < 50) {
                        EV_INFO << "[SAMPLE][QUEUE] t=" << simTime() << ", sig=" << signalName
                                << ", path=" << q << ", bits=" << bits << ", pcp=" << p
                                << ", qlen_pcp=" << qlenPcp[p] << "\n";
                        sampleQueueEvents++;
                    }
                }
                hadQueueEventThisWindow = true;
                totalPushStartedSeen++;
            }
        } else if (signalName == "packetPushEnded") {
            // End of atomic push operation: count enqOk if previous pushStarted occurred
            if (isVantageQueue) {
                std::string q = source->getFullPath().c_str();
                if (!q_pendingPcpByPath[q].empty()) {
                    int p = q_pendingPcpByPath[q].front();
                    q_pendingPcpByPath[q].pop_front();
                    if (p>=0 && p<8) w_enqOkPcp[p]++;
                }
                hadQueueEventThisWindow = true;
            }
        } else if (signalName == "packetPulled") {
            std::string q = source->getFullPath().c_str();
            auto itb = q_bit_by_path.find(q); if (itb!=q_bit_by_path.end()) itb->second = std::max(0L, itb->second - bits);
            if (auto qt = packet->findTag<inet::QueueingTimeTag>()) {
                double qv = SIMTIME_DBL(qt->getPacketTotalTimes(0));
                w_queueingTimeSum += qv; w_queueingTimeCount++;
            }
            if (isVantageQueue) {
                int p = getPcp(packet);
                if (p>=0 && p<8) {
                    double now = SIMTIME_DBL(simTime());
                    double tPrev = qlenPcpLastChange[p] > 0.0 ? qlenPcpLastChange[p] : currentWindowStart;
                    if (now >= tPrev) qlenPcpIntegral[p] += qlenPcp[p] * (now - tPrev);
                    qlenPcp[p] = std::max(0L, qlenPcp[p] - 1);
                    qlenPcpLastChange[p] = now;
                    if (diag && sampleQueueEvents < 50) {
                        EV_INFO << "[SAMPLE][QUEUE] t=" << simTime() << ", sig=" << signalName
                                << ", path=" << q << ", bits=" << bits << ", pcp=" << p
                                << ", qlen_pcp=" << qlenPcp[p] << "\n";
                        sampleQueueEvents++;
                    }
                }
                hadQueueEventThisWindow = true;
            }
        } else if (signalName == "packetRemoved") {
            std::string q = source->getFullPath().c_str();
            auto itb = q_bit_by_path.find(q); if (itb!=q_bit_by_path.end()) itb->second = std::max(0L, itb->second - bits);
            if (isVantageQueue) {
                int p = getPcp(packet);
                if (p>=0 && p<8) {
                    double now = SIMTIME_DBL(simTime());
                    double tPrev = qlenPcpLastChange[p] > 0.0 ? qlenPcpLastChange[p] : currentWindowStart;
                    if (now >= tPrev) qlenPcpIntegral[p] += qlenPcp[p] * (now - tPrev);
                    qlenPcp[p] = std::max(0L, qlenPcp[p] - 1);
                    qlenPcpLastChange[p] = now;
                    if (diag && sampleQueueEvents < 50) {
                        EV_INFO << "[SAMPLE][QUEUE] t=" << simTime() << ", sig=" << signalName
                                << ", path=" << q << ", bits=" << bits << ", pcp=" << p
                                << ", qlen_pcp=" << qlenPcp[p] << "\n";
                        sampleQueueEvents++;
                    }
                }
                hadQueueEventThisWindow = true;
            }
        } else if (signalName == "packetDropped" || signalName == "packetFiltered") {
            if (modulePath.find("bridging.streamFilter.ingress.filter") != std::string::npos) {
                psfp_filtered_sum++;
                filteredTreeIds.insert(packet->getTreeId());
                dropReasonByTreeId[packet->getTreeId()] = "filter_drop";
                // Emit immediate main-CSV row with explicit N/A sentinels (no fabrication)
                double ts = SIMTIME_DBL(simTime());
                std::string streamIdNow;
                if (auto sind = packet->findTag<inet::StreamInd>()) { const char *sn = sind->getStreamName(); if (sn && *sn) streamIdNow = sn; }
                else if (auto sreq = packet->findTag<inet::StreamReq>()) { const char *sn = sreq->getStreamName(); if (sn && *sn) streamIdNow = sn; }
                std::string srcMAC2, dstMAC2;
                try { auto ethHdr = packet->peekAtFront<inet::EthernetMacHeader>(); srcMAC2 = ethHdr->getSrc().str(); dstMAC2 = ethHdr->getDest().str(); } catch (...) {}
                if (streamIdNow.empty()) streamIdNow = srcMAC2 + "->" + dstMAC2;
                long bits2 = (long)packet->getTotalLength().get(); long bytes2 = bits2/8;
                int pcpVal2 = -1; if (auto u1 = packet->findTag<inet::UserPriorityInd>()) pcpVal2 = u1->getUserPriority(); else if (auto u2 = packet->findTag<inet::UserPriorityReq>()) pcpVal2 = u2->getUserPriority(); else if (auto p3 = packet->findTag<inet::PcpInd>()) pcpVal2 = p3->getPcp();
                int vlan2 = -1; if (auto v1 = packet->findTag<inet::VlanInd>()) vlan2 = v1->getVlanId(); else if (auto v2 = packet->findTag<inet::VlanReq>()) vlan2 = v2->getVlanId();
                // Fallback: derive PCP/VLAN from 802.1Q header when available
                if (vlan2 < 0 || pcpVal2 < 0) {
                    try {
                        auto ethHdr2 = packet->peekAtFront<inet::EthernetMacHeader>();
                        // Attempt fallback only if INET provides the EPD header type (older INETs may not)
                        #ifdef INET_WITH_IEEE8021Q
                        auto vlanHdr2 = packet->peekDataAt<inet::Ieee8021qTagEpdHeader>(ethHdr2->getChunkLength());
                        if (vlanHdr2 != nullptr) {
                            if (vlan2 < 0) vlan2 = vlanHdr2->getVid();
                            if (pcpVal2 < 0) pcpVal2 = vlanHdr2->getPcp();
                        }
                        #endif
                    } catch (...) {}
                }
                // Last resort: never emit negative PCP/VID in CSV
                if (pcpVal2 < 0) pcpVal2 = 0;
                if (vlan2 < 0) vlan2 = 0;
                auto macToDec2 = [](const std::string& mac)->unsigned long long { unsigned long long val=0ULL; int nib=0; int cnt=0; for(char c:mac){ if(c==':'||c=='-') continue; int v=(c>='0'&&c<='9')?c-'0':(c>='a'&&c<='f')?10+(c-'a'):(c>='A'&&c<='F')?10+(c-'A'):0; nib=(nib<<4)|v; cnt++; if(cnt%2==0){ val=(val<<8)|(unsigned long long)(nib & 0xFF); nib=0; } } return val; };
                unsigned long long srcDec2 = macToDec2(srcMAC2); unsigned long long dstDec2 = macToDec2(dstMAC2);
                auto lower = [](std::string s){ std::transform(s.begin(), s.end(), s.begin(), ::tolower); return s; };
                std::string srcName = macToNodeName.count(lower(srcMAC2)) ? macToNodeName[lower(srcMAC2)] : "";
                std::string dstName = macToNodeName.count(lower(dstMAC2)) ? macToNodeName[lower(dstMAC2)] : "";
                int color2 = -1; auto itC2 = lastMeterColorByTreeId.find(packet->getTreeId()); if (itC2!=lastMeterColorByTreeId.end()) color2 = itC2->second;

                csv.newRow();
                const std::string runId = currentConfigName + "-#" + std::to_string(currentRepetition);
                csv.add(runId);               // run
                csv.add(ts);                  // t
                csv.add(streamIdNow);         // streamName
                csv.add((long)srcDec2);       // srcMACdec
                csv.add((long)dstDec2);       // dstMACdec
                csv.add(pcpVal2);             // pcp
                csv.add(vlan2);               // vid
                csv.add((long)bytes2);        // lenB
                csv.add(-1L);                 // qLenBits N/A
                csv.add(-1);                  // gateState N/A (sentinel)
                csv.add(color2==0 ? 1 : 0);   // meter_conform
                csv.add((color2==1 || color2==2) ? 1 : (color2<0 ? -1 : 0)); // meter_exceed
                csv.add(1);                   // meter_filtered
                csv.writeToFile();
            }
            if (isVantageQueue) {
                int pcpVal = getPcp(packet);
                if (pcpVal>=0 && pcpVal<8) w_dropsPcp[pcpVal]++;
                // Decrement queue bits on drop (clamp at >=0)
                std::string q = source->getFullPath().c_str();
                auto itb = q_bit_by_path.find(q);
                if (itb!=q_bit_by_path.end()) itb->second = std::max(0L, itb->second - bits);
                hadQueueEventThisWindow = true;
            }
        }
        // Tags and derived measurements for per-packet CSV, per-stream agg (standardized precedence)
        std::string srcMAC, dstMAC, srcL3, dstL3;
        std::string streamId;
        int pcp = -1; int vlanId = -1;
        if (auto macTag = packet->findTag<inet::MacAddressInd>()) { srcMAC = macTag->getSrcAddress().str(); dstMAC = macTag->getDestAddress().str(); }
        if (auto l3 = packet->findTag<inet::L3AddressInd>()) { srcL3 = l3->getSrcAddress().str(); dstL3 = l3->getDestAddress().str(); }
        if ((srcMAC.empty() || dstMAC.empty())) {
            try {
                auto ethHdr = packet->peekAtFront<inet::EthernetMacHeader>();
                if (srcMAC.empty()) srcMAC = ethHdr->getSrc().str();
                if (dstMAC.empty()) dstMAC = ethHdr->getDest().str();
            } catch (...) {}
        }
        // PCP precedence: UserPriorityInd -> UserPriorityReq -> PcpInd -> 802.1Q header
        if (auto upi = packet->findTag<inet::UserPriorityInd>()) { pcp = upi->getUserPriority(); }
        else if (auto upr = packet->findTag<inet::UserPriorityReq>()) { pcp = upr->getUserPriority(); }
        else if (auto pcpTag = packet->findTag<inet::PcpInd>()) { pcp = pcpTag->getPcp(); }
        // VID precedence: VlanInd -> VlanReq -> 802.1Q header
        if (auto vlanInd = packet->findTag<inet::VlanInd>()) { vlanId = vlanInd->getVlanId(); }
        else if (auto vlanReq = packet->findTag<inet::VlanReq>()) { vlanId = vlanReq->getVlanId(); }
        // Fallback: peek 802.1Q tag after Ethernet header if present
        if (vlanId < 0 || pcp < 0) {
            try {
                auto ethHdr = packet->peekAtFront<inet::EthernetMacHeader>();
                auto vlanHdr = packet->peekDataAt<inet::Ieee8021qTagEpdHeader>(ethHdr->getChunkLength());
                if (vlanHdr != nullptr) {
                    if (vlanId < 0) vlanId = vlanHdr->getVid();
                    if (pcp < 0) pcp = vlanHdr->getPcp();
                }
            } catch (...) {}
        }
        // Determine stream id: prefer StreamInd/Req; fallback to MAC pair
        if (streamId.empty()) {
            std::string sid = getStreamId(packet);
            if (!sid.empty()) streamId = sid;
        }
        // Deterministic fallback: if no stream tag, fallback to MAC pair
        if (streamId.empty()) {
            streamId = srcMAC + "->" + dstMAC;
        }

        // Opportunistically learn MAC->node mapping from packet events (non-switch nodes)
        // Helps populate srcNode/dstNode columns without relying on eth[*].address params
        if (!modulePath.empty() && modulePath.find(".eth[") != std::string::npos &&
            modulePath.rfind("MinimalAttackNetwork.centralSwitch.", 0) != 0) {
            std::string nodeName = modulePath.substr(0, modulePath.find(".eth["));
            auto toLower = [](std::string s){ std::transform(s.begin(), s.end(), s.begin(), ::tolower); return s; };
            if (signalName == "packetSentToLower" && !srcMAC.empty()) {
                std::string k = toLower(srcMAC);
                if (!k.empty() && !macToNodeName.count(k)) {
                    macToNodeName[k] = nodeName;
                }
            }
            if ((signalName == "packetReceivedFromLower" || signalName == "rxPkOk") && !dstMAC.empty()) {
                std::string k = toLower(dstMAC);
                if (!k.empty() && !macToNodeName.count(k)) {
                    macToNodeName[k] = nodeName;
                }
            }
        }

        if (signalName == "rxPkOk" || signalName == "packetReceived") {
            if (auto ct = packet->findTag<inet::CreationTimeTag>()) {
                double e2e = SIMTIME_DBL(simTime() - ct->getCreationTime());
                w_e2eSum += e2e; if (e2e > w_e2eMax) w_e2eMax = e2e; w_e2eCount++;
                auto &agg = streamAggById[streamId];
                agg.e2eSum += e2e; agg.e2eCount++;
            }
            if (auto qt = packet->findTag<inet::QueueingTimeTag>()) {
                double qv = SIMTIME_DBL(qt->getPacketTotalTimes(0));
                w_queueingTimeSum += qv; w_queueingTimeCount++;
                auto &agg = streamAggById[streamId];
                agg.queueingSum += qv; agg.queueingCount++;
            }
            if (isVantageMac) {
                if (includeControlFramesInThroughput || !isControlFrame(packet)) {
                    int pcpVal = getPcp(packet);
                    w_rxBits += bits;
                    if (pcpVal>=0 && pcpVal<8) w_rxBitsPcp[pcpVal] += bits;
                    if (diag && sampleMacEvents < 50) {
                        EV_INFO << "[SAMPLE][MAC] t=" << simTime() << ", sig=rxPkOk"
                                << ", path=" << modulePath << ", bits=" << bits << ", pcp=" << pcpVal << "\n";
                        sampleMacEvents++;
                    }
                }
            }
        }
        if (signalName == "packetReceivedFromLower" || signalName == "rxPkOk") {
            auto &agg = streamAggById[streamId];
            agg.packetsRx++; agg.rxBytes += bytes; if (signalName=="rxPkOk") agg.rxGood++;
            if (agg.pcp < 0) agg.pcp = pcp;
            if (agg.vlanId < 0) agg.vlanId = vlanId;
        }
        // Switch MAC egress/ingress across all ports (no per-port hardcoding)
        bool isSwitchMacModule = modulePath.rfind("MinimalAttackNetwork.centralSwitch.eth[", 0) == 0;
        if (isSwitchMacModule && (signalName == "rxPkOk" || signalName == "packetReceivedFromLower" || signalName == "packetSentToLower")) {
            double ts = SIMTIME_DBL(simTime());
            modulePath = source ? source->getFullPath().c_str() : modulePath;
            bool isMacContext = (modulePath.find(".macLayer.") != std::string::npos) || (modulePath.find(".mac.") != std::string::npos);
            if (!isMacContext) { recordSignalEvent(source, signalID, value ? value->str() : ""); return; }
            if (srcMAC.empty() || dstMAC.empty()) {
                recordSignalEvent(source, signalID, value ? value->str() : "");
                return;
            }
            // Update per-port RX counter and bytes on ingress
            int portIdxTmp = parsePortIndexFromPath(modulePath);
            if (signalName == "packetReceivedFromLower") {
                rxPkByPort[portIdxTmp]++;
                long lenB_rx = (long)(packet->getTotalLength().get() / 8);
                rxBytesByPort[portIdxTmp] += lenB_rx;
            }
            // Emit rows only on TX at central switch egress; but first, accumulate throughput bits
            if (signalName == "packetSentToLower") {
                if (includeControlFramesInThroughput || !isControlFrame(packet)) {
                    int pcpVal_tx = getPcp(packet);
                    w_txBits += bits;
                    if (pcpVal_tx>=0 && pcpVal_tx<8) w_txBitsPcp[pcpVal_tx] += bits;
                }
            } else {
                recordSignalEvent(source, signalID, value ? value->str() : "");
                return;
            }

            // Determine stream id first
            if (streamId.empty()) {
                std::string sid = getStreamId(packet);
                if (!sid.empty()) streamId = sid;
            }
            if (streamId.empty()) {
                // fallback to MAC pair
                streamId = srcMAC + "->" + dstMAC;
            }

            // Resolve port index for gate state and queue path
            int portIdx = parsePortIndexFromPath(modulePath);
            int gateState = 0; // default 0 if unknown
            if (portIdx>=0 && lastGateOpenByPort.count(portIdx)) gateState = lastGateOpenByPort[portIdx];

            // queue length bits snapshot for matching port
            long qBits = 0;
            if (portIdx>=0) {
                auto itQp = queuePathByPort.find(portIdx);
                if (itQp != queuePathByPort.end()) {
                    auto itB = q_bit_by_path.find(itQp->second);
                    if (itB != q_bit_by_path.end()) qBits = std::max(0L, itB->second);
                }
                // Defensive: if queue path mapping not yet populated, prefer zero over stale
                if (qBits < 0) qBits = 0;
            }

            // Per-port counters (packets and bytes)
            txPkByPort[portIdx]++;
            long lenB_tx = (long)(packet->getTotalLength().get() / 8);
            txBytesByPort[portIdx] += lenB_tx;

            // PSFP meter mapping
            int color = -1; // 0=green,1=yellow,2=red
            auto itC = lastMeterColorByTreeId.find(packet->getTreeId());
            if (itC != lastMeterColorByTreeId.end()) color = itC->second;
            int meter_conform = (color==0) ? 1 : 0;
            int meter_exceed = (color==1 || color==2) ? 1 : 0;
            int meter_filtered = filteredTreeIds.count(packet->getTreeId()) ? 1 : 0;
            std::string reason = "";
            auto itR = dropReasonByTreeId.find(packet->getTreeId());
            if (itR != dropReasonByTreeId.end()) reason = itR->second;

            // Resolve node names from MACs (no -1). If unknown, leave blank.
            auto macLower = [](std::string s){ std::transform(s.begin(), s.end(), s.begin(), ::tolower); return s; };
            std::string srcName = macToNodeName.count(macLower(srcMAC)) ? macToNodeName[macLower(srcMAC)] : "";
            std::string dstName = macToNodeName.count(macLower(dstMAC)) ? macToNodeName[macLower(dstMAC)] : "";

            // Convert MACs to 48-bit unsigned decimal
            auto macToDec = [](const std::string& mac)->unsigned long long {
                unsigned long long val = 0ULL; int byte = 0; bool have = false; 
                for (size_t i=0;i<mac.size();++i) {
                    char c = mac[i]; if (c==':' || c=='-') continue; int v=0; 
                    if (c>='0'&&c<='9') v=c-'0'; else if (c>='a'&&c<='f') v=10+(c-'a'); else if (c>='A'&&c<='F') v=10+(c-'A'); else continue; 
                    byte=(byte<<4)|v; have=true; 
                    if ((i+1<mac.size() && (mac[i+1]==':'||mac[i+1]=='-')) || (i+1==mac.size())) { val=(val<<8)| (unsigned long long)(byte & 0xFF); byte=0; }
                }
                return have? val: 0ULL;
            };
            unsigned long long srcMacDec = macToDec(srcMAC);
            unsigned long long dstMacDec = macToDec(dstMAC);

            // Deterministic tag lookups
            // PCP precedence: UserPriorityInd -> UserPriorityReq -> PcpInd -> 802.1Q header
            // VID precedence: VlanInd -> VlanReq -> 802.1Q header
            int pcpVal = -1;
            if (auto t = packet->findTag<inet::UserPriorityInd>()) pcpVal = t->getUserPriority();
            else if (auto t2 = packet->findTag<inet::UserPriorityReq>()) pcpVal = t2->getUserPriority();
            else if (auto t3 = packet->findTag<inet::PcpInd>()) pcpVal = t3->getPcp();
            // VLAN
            int vlanIdCsv = -1; if (auto v1 = packet->findTag<inet::VlanInd>()) vlanIdCsv = v1->getVlanId(); else if (auto v2 = packet->findTag<inet::VlanReq>()) vlanIdCsv = v2->getVlanId();
            // Bytes
            long lenB = (long)(packet->getTotalLength().get() / 8);

            // Fallback: derive PCP (and VLAN) from 802.1Q header if tags missing
            if (vlanIdCsv < 0 || pcpVal < 0) {
                try {
                    auto ethHdr2 = packet->peekAtFront<inet::EthernetMacHeader>();
                    // Attempt fallback only if INET provides the EPD header type (older INETs may not)
                    #ifdef INET_WITH_IEEE8021Q
                    auto vlanHdr2 = packet->peekDataAt<inet::Ieee8021qTagEpdHeader>(ethHdr2->getChunkLength());
                    if (vlanHdr2 != nullptr) {
                        if (vlanIdCsv < 0) vlanIdCsv = vlanHdr2->getVid();
                        if (pcpVal < 0) pcpVal = vlanHdr2->getPcp();
                    }
                    #endif
                } catch (...) {}
            }

            // CSV units: t [s], lenB [bytes], qLenBits [bits], gateState {0,1}; txPk_node/rxPk_node are per-window counters.
            // Final slim CSV row: seconds/bytes/bits
            csv.newRow();
            const std::string runId = currentConfigName + "-#" + std::to_string(currentRepetition);
            csv.add(runId);                 // run
            csv.add(ts);                    // t [s]
            csv.add(streamId);              // streamName
            csv.add((long)srcMacDec);       // srcMACdec
            csv.add((long)dstMacDec);       // dstMACdec
            csv.add(pcpVal<0?0:pcpVal);     // pcp
            csv.add(vlanIdCsv<0?0:vlanIdCsv); // vid
            csv.add((long)lenB);            // lenB [bytes]
            csv.add(qBits);                 // qLenBits [bits]
            csv.add(gateState);             // gateState 0/1
            csv.add(meter_conform);         // meter_conform
            csv.add(meter_exceed);          // meter_exceed
            csv.add(meter_filtered);        // meter_filtered
            csv.writeToFile();

            // Clear caches for this packet
            lastMeterColorByTreeId.erase(packet->getTreeId());
            filteredTreeIds.erase(packet->getTreeId());
            dropReasonByTreeId.erase(packet->getTreeId());

            recordSignalEvent(source, signalID, value ? value->str() : "");
            return;
        }
        // Vantage tx accumulation strictly from packetSentToLower
        if (isVantageMac && signalName == "packetSentToLower") {
            if (includeControlFramesInThroughput || !isControlFrame(packet)) {
                int pcpVal = getPcp(packet);
                w_txBits += bits;
                if (pcpVal>=0 && pcpVal<8) w_txBitsPcp[pcpVal] += bits;
                if (diag && sampleMacEvents < 50) {
                    EV_INFO << "[SAMPLE][MAC] t=" << simTime() << ", sig=packetSentToLower"
                            << ", path=" << modulePath << ", bits=" << bits << ", pcp=" << pcpVal << "\n";
                    sampleMacEvents++;
                }
            }
        }
        // PSFP meters roll-up using LabelsTag colors (any switch)
        if (modulePath.find(".bridging.streamFilter.ingress.meter[") != std::string::npos) {
            std::string key = modulePath + ":" + signalName;
            if (diag && meterSeenCount < 20 && meterSeenPairs.insert(key).second) {
                EV_WARN << "[PSFP meter signal] " << key << "\n";
                meterSeenCount++;
            }
            if (signalName == "packetPushedOut" || signalName == "packetPushed") {
                std::string mname = source->getFullPath().c_str();
                auto &mc = meterCountersByName[mname];
                int color = -1; // 0=green,1=yellow,2=red
                if (auto lab = packet->findTag<inet::LabelsTag>()) {
                    for (int i=0;i<lab->getLabelsArraySize();++i) {
                        auto s = lab->getLabels(i);
                        if (s == std::string("green")) { color = 0; break; }
                        if (s == std::string("yellow")) { color = 1; break; }
                        if (s == std::string("red")) { color = 2; break; }
                    }
                }
                if (color==0) { mc.ccp++; psfp_ccp_sum++; }
                else if (color==1) { mc.cnp++; psfp_cnp_sum++; }
                else if (color==2) { mc.ecp++; psfp_ecp_sum++; }
                // annotate latest color for this packet treeId
                lastMeterColorByTreeId[packet->getTreeId()] = color;
                // do not write any CSV row here; defer to MAC egress
            }
        }
        // PSFP filter: handled above with immediate main-CSV write
        // Track gate/queue index by parsing queue path when packet enters/leaves queues
        if ((signalName == "packetPushStarted" || signalName == "packetPushEnded" || signalName == "packetPulled" || signalName == "packetRemoved") && isVantageQueue) {
            std::string qpath = modulePath;
            size_t qi = qpath.find(".queue[");
            if (qi != std::string::npos) {
                size_t lb = qpath.find('[', qi); size_t rb = qpath.find(']', lb);
                if (lb!=std::string::npos && rb!=std::string::npos) {
                    int idx = -1; try { idx = std::stoi(qpath.substr(lb+1, rb-lb-1)); } catch(...) { idx=-1; }
                    if (idx >= 0) gateIndexByTreeId[packet->getTreeId()] = idx;
                }
            }
        }
    }
    // Non-packet signals: count and print a few lines
    if (!packet && source != nullptr) {
        eventsSeenBySignal[signalName]++;
        int &printed = debugEventPrintCountBySignal[signalName];
        if (printed < debugMaxEventPrints) {
            EV_WARN << "[EV] sig=" << signalName << " path=" << source->getFullPath() << " t=" << simTime() << "\n";
            printed++;
        }
    }
    // Application sink packetReceived: derive sink-side E2E delay/jitter using CreationTimeTag
    if (!packet && std::string(source->getFullPath().c_str()).find(".app[") != std::string::npos && signalName == "packetReceived") {
        // details may be Packet* for packetReceived; OMNeT++ signals sometimes deliver Packet* as cObject
        auto pkt = dynamic_cast<inet::Packet*>(const_cast<cObject*>(details));
        if (pkt) {
            if (auto ct = pkt->findTag<inet::CreationTimeTag>()) {
                double e2e = SIMTIME_DBL(simTime() - ct->getCreationTime());
                w_sinkE2eSum += e2e;
                w_sinkE2eSumSq += e2e * e2e;
                if (e2e > w_sinkE2eMax) w_sinkE2eMax = e2e;
                w_sinkE2eCount++;
                e2e_samples++;
            }
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
    
    // Aggregate into current window metrics (vantage-only)
    bool isVantageMac = source && std::string(source->getFullPath().c_str()).find(vantageMacPrefix) != std::string::npos;
    bool isVantageQueue = source && std::string(source->getFullPath().c_str()).find(vantageQueuePrefix) != std::string::npos;
    if (isVantageMac && signalName == "packetSentToLower") { w_packetsSent++; totalPacketsSent++; }
    else if (isVantageMac && (signalName == "rxPkOk" || signalName == "packetReceivedFromLower")) {
        w_packetsReceived++;
        if (signalName == "rxPkOk") w_rxGood++;
        totalPacketsReceived++;
    }
    else if (isVantageQueue && signalName == "packetDropped") { w_packetsDropped++; totalPacketsDropped++; }
    else if (isVantageQueue && signalName == "packetPushEnded") {
        std::string q = source->getFullPath().c_str();
        // queue length integral update (+1)
        updateQueueLenIntegral(q, +1, SIMTIME_DBL(simTime()));
        auto &st = q_len_state_by_path[q];
        if (st.len > w_queueLenMax) w_queueLenMax = st.len;
        // Update per-PCP max using sub-queue index if available
        size_t qi = q.find(".queue[");
        if (qi != std::string::npos) {
            size_t lb = q.find('[', qi); size_t rb = q.find(']', lb);
            if (lb!=std::string::npos && rb!=std::string::npos) {
                int p = -1; try { p = std::stoi(q.substr(lb+1, rb-lb-1)); } catch(...) { p=-1; }
                if (p>=0 && p<8 && st.len > w_queueLenMaxPcp[p]) w_queueLenMaxPcp[p] = st.len;
            }
        }
    }
    else if (isVantageQueue && (signalName == "packetPulled" || signalName == "packetRemoved")) {
        std::string q = source->getFullPath().c_str();
        // queue length integral update (-1)
        updateQueueLenIntegral(q, -1, SIMTIME_DBL(simTime()));
    }
    // Count per-port queue/MAC drops (per-window) on centralSwitch
    if (signalName == "packetDropped") {
        std::string modPath = source ? source->getFullPath().c_str() : std::string();
        if (modPath.rfind("MinimalAttackNetwork.centralSwitch.eth[", 0) == 0) {
            if (modPath.find(".macLayer.queue") != std::string::npos) {
                int portIdxDrop = parsePortIndexFromPath(modPath);
                if (portIdxDrop >= 0) dropQueueByPort[portIdxDrop]++;
            } else if (modPath.find(".macLayer") != std::string::npos && modPath.find(".macLayer.queue") == std::string::npos) {
                int portIdxDrop = parsePortIndexFromPath(modPath);
                if (portIdxDrop >= 0) dropMacByPort[portIdxDrop]++;
            }
        }
    }
    else if (signalName == "localTime") { /* clock time seen; not aggregated */ }
    else if (signalName == "timeDifference") {
        double v = 0.0; try { v = std::stod(value); } catch(...) { v = 0.0; }
        w_gptpOffsetSum += v; w_gptpOffsetMax = std::max(w_gptpOffsetMax, v); w_gptpOffsetCount++; ptp_samples++;
    }
    else if (signalName == "rateRatio") {
        double v = 0.0; try { v = std::stod(value); } catch(...) { v = 0.0; }
        w_rateRatioSum += v; w_rateRatioCount++; ptp_samples++;
    }
    else if (signalName == "peerDelay") {
        double v = 0.0; try { v = std::stod(value); } catch(...) { v = 0.0; }
        w_peerDelaySum += v; w_peerDelayCount++; ptp_samples++;
    }
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
    w_txBits = w_rxBits = 0;
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
        // Reset q_bit_by_path to clear snapshot per window as requested
        q_bit_by_path.clear();
    }
    w_queueLenMax = 0;
    w_queueBitlenMax = 0;
    w_queueingTimeSum = 0.0; w_queueingTimeCount = 0;
    w_e2eSum = 0.0; w_e2eMax = 0.0; w_e2eCount = 0;
    w_sinkE2eSum = 0.0; w_sinkE2eSumSq = 0.0; w_sinkE2eMax = 0.0; w_sinkE2eCount = 0;
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
    ptp_samples = 0;
    e2e_samples = 0;
    // Reset per-PCP integrals to window baseline
    for (int p=0;p<8;p++) {
        qlenPcpIntegral[p] = 0.0;
        qlenPcpLastChange[p] = currentWindowStart;
        w_queueLenMaxPcp[p] = 0;
        w_queueLenIntegralPcp[p] = 0.0;
    }
    hadQueueEventThisWindow = false;
    // Make per-port values per-window
    txPkByPort.clear();
    rxPkByPort.clear();
    txBytesByPort.clear();
    rxBytesByPort.clear();
    dropQueueByPort.clear();
    dropMacByPort.clear();
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
