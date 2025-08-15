#include "DataCollector.h"
#include <iostream>
#include <iomanip>
#include <cmath>
#include <fstream>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <limits>

// OMNeT++ includes
#include <omnetpp.h>

// INET includes
#include "inet/common/packet/Packet.h"
#include "inet/common/TimeTag_m.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/Simsignals.h"

using namespace inet;
using namespace omnetpp;

DataCollector::DataCollector()
{
    EV << "🚨 [DATACOLLECTOR] CONSTRUCTOR EXECUTED!" << endl;
    
    // Initialize CSV output with configuration-specific filename
    std::string configName = getEnvir()->getConfigEx()->getActiveConfigName();
    csvOutputFile = "ml_models/tsn_attack_features_" + configName + ".csv";
    
    // Debug module state
    EV << "🚨 [DATACOLLECTOR] Module name: " << getFullName() << endl;
    EV << "🚨 [DATACOLLECTOR] Module path: " << getFullPath() << endl;
    EV << "🚨 [DATACOLLECTOR] Module type: " << getClassName() << endl;
    EV << "🚨 [DATACOLLECTOR] Is initialized: " << (initialized() ? "YES" : "NO") << endl;
    EV << "🚨 [DATACOLLECTOR] Configuration: " << configName << endl;
    EV << "🚨 [DATACOLLECTOR] CSV file: " << csvOutputFile << endl;
    
    EV_INFO << "🎯 [DATACOLLECTOR] Constructor completed successfully!" << endl;
    EV_INFO << "📊 Will capture ALL signals: packetSent, packetReceived, packetDropped, packetCreated, packetRecorded" << endl;
}

DataCollector::~DataCollector()
{
    EV << "🚨 [DATACOLLECTOR] DESTRUCTOR CALLED!" << endl;
    if (csvFile.is_open()) {
        csvFile.close();
    }
}

void DataCollector::initialize()
{
    EV << "🚨 [DATACOLLECTOR] INITIALIZE CALLED!" << endl;
    EV_INFO << "🎯 [DATACOLLECTOR] Initializing Complete Signal Capture for TSN/PSFP ML" << endl;
    EV_INFO << "📊 Capturing ALL signals without time windows - every event recorded!" << endl;
    
    // Subscribe to ONLY the 4 confirmed available signals
    subscribeToSignals();
    
    // Open CSV file and write header
    csvFile.open(csvOutputFile);
    writeCSVHeader();
    
    EV_INFO << "✅ [DATACOLLECTOR] Initialized successfully!" << endl;
    EV_INFO << "📁 Output file: " << csvOutputFile << endl;
}

void DataCollector::initialize(int stage)
{
    EV << "🚨 [DATACOLLECTOR] initialize(int stage=" << stage << ") CALLED!" << endl;
    EV_INFO << "🎯 [DATACOLLECTOR] Stage-based initialization called with stage " << stage << endl;
    
    if (stage == 0) {
        EV_INFO << "📡 [DATACOLLECTOR] Stage 0 initialization - subscribing to signals" << endl;
        subscribeToSignals();
    }
    
    if (stage == 1) {
        EV_INFO << "📡 [DATACOLLECTOR] Stage 1 initialization - opening CSV file" << endl;
        csvFile.open(csvOutputFile);
        writeCSVHeader();
        EV_INFO << "✅ [DATACOLLECTOR] Stage-based initialization completed!" << endl;
        EV_INFO << "📁 Output file: " << csvOutputFile << endl;
    }
}

void DataCollector::subscribeToSignals()
{
    EV_INFO << "📡 [DATACOLLECTOR] Starting signal subscription for 5 CONFIRMED signals..." << endl;
    
    // Get the network module
    cModule *networkModule = getSimulation()->getSystemModule();
    EV_INFO << "🌐 Network module: " << networkModule->getFullPath() << endl;
    
    // Find all key modules in the network
    cModule *criticalSensor = networkModule->getSubmodule("criticalSensor");
    cModule *mainECU = networkModule->getSubmodule("mainECU");
    cModule *display = networkModule->getSubmodule("display");
    cModule *centralSwitch = networkModule->getSubmodule("centralSwitch");
    cModule *attackerExternal = networkModule->getSubmodule("attackerExternal");
    cModule *compromisedNode = networkModule->getSubmodule("compromisedNode");
    cModule *masterClock = networkModule->getSubmodule("masterClock");
    
    EV_INFO << "🔍 Module discovery results:" << endl;
    EV_INFO << "   - criticalSensor: " << (criticalSensor ? criticalSensor->getFullPath() : "NOT FOUND") << endl;
    EV_INFO << "   - mainECU: " << (mainECU ? mainECU->getFullPath() : "NOT FOUND") << endl;
    EV_INFO << "   - display: " << (display ? display->getFullPath() : "NOT FOUND") << endl;
    EV_INFO << "   - centralSwitch: " << (centralSwitch ? centralSwitch->getFullPath() : "NOT FOUND") << endl;
    EV_INFO << "   - attackerExternal: " << (attackerExternal ? attackerExternal->getFullPath() : "NOT FOUND") << endl;
    EV_INFO << "   - compromisedNode: " << (compromisedNode ? compromisedNode->getFullPath() : "NOT FOUND") << endl;
    EV_INFO << "   - masterClock: " << (masterClock ? masterClock->getFullPath() : "NOT FOUND") << endl;
    
    int totalSubscriptions = 0;
    
    // ONLY the 5 confirmed available signals
    std::vector<std::string> signalNames = {
        "packetSent",      // ✅ CONFIRMED AVAILABLE
        "packetReceived",  // ✅ CONFIRMED AVAILABLE  
        "packetDropped",   // ✅ CONFIRMED AVAILABLE
        "packetCreated",   // ✅ CONFIRMED AVAILABLE
        "packetRecorded"   // ✅ CONFIRMED AVAILABLE (from PcapRecorder)
    };
    
    // Subscribe to signals from all device modules
    std::vector<cModule*> deviceModules = {criticalSensor, mainECU, display, attackerExternal, compromisedNode, masterClock};
    
    for (auto device : deviceModules) {
        if (device) {
            EV_INFO << "🔍 Processing device: " << device->getFullPath() << endl;
            subscribeToModuleSignals(device, signalNames, totalSubscriptions);
        }
    }
    
    // Subscribe to central switch signals
    if (centralSwitch) {
        EV_INFO << "🔍 Processing central switch: " << centralSwitch->getFullPath() << endl;
        subscribeToModuleSignals(centralSwitch, signalNames, totalSubscriptions);
    }
    
    // Subscribe to PcapRecorder signals
    std::vector<cModule*> pcapModules;
    findModulesByType("PcapRecorder", pcapModules);
    
    for (auto pcapModule : pcapModules) {
        EV_INFO << "📡 Found PcapRecorder: " << pcapModule->getFullPath() << endl;
        
        try {
            pcapModule->subscribe("packetRecorded", this);
            EV_INFO << "✅ Subscribed to packetRecorded signal from " << pcapModule->getFullPath() << endl;
            totalSubscriptions++;
        } catch (const cRuntimeError& e) {
            EV_WARN << "⚠️ Failed to subscribe to packetRecorded: " << e.what() << endl;
        }
    }
    
    EV_INFO << "🎯 [DATACOLLECTOR] Signal subscription completed!" << endl;
    EV_INFO << "📊 Total subscriptions: " << totalSubscriptions << endl;
}

void DataCollector::subscribeToModuleSignals(cModule *module, const std::vector<std::string>& signalNames, int& totalSubscriptions)
{
    // Subscribe to signals from the module itself
    for (const auto& signalName : signalNames) {
        try {
            module->subscribe(signalName.c_str(), this);
            EV_INFO << "✅ Subscribed to " << signalName << " from " << module->getFullPath() << endl;
            totalSubscriptions++;
        } catch (const cRuntimeError& e) {
            // Signal doesn't exist, continue
        }
    }
    
    // Recursively subscribe to signals from all submodules
    for (cModule::SubmoduleIterator it(module); !it.end(); ++it) {
        cModule *submodule = *it;
        EV_DEBUG << "🔍 Processing submodule: " << submodule->getFullPath() << endl;
        
        // Subscribe to signals from this submodule
        for (const auto& signalName : signalNames) {
            try {
                submodule->subscribe(signalName.c_str(), this);
                EV_DEBUG << "✅ Subscribed to " << signalName << " from " << submodule->getFullPath() << endl;
                totalSubscriptions++;
            } catch (const cRuntimeError& e) {
                // Signal doesn't exist, continue
            }
        }
        
        // Recursively process submodules of this submodule
        subscribeToModuleSignals(submodule, signalNames, totalSubscriptions);
    }
}

void DataCollector::findModulesByType(const std::string& moduleType, std::vector<cModule*>& modules)
{
    cModule *networkModule = getSimulation()->getSystemModule();
    findModulesByTypeRecursive(networkModule, moduleType, modules);
}

void DataCollector::findModulesByTypeRecursive(cModule *module, const std::string& moduleType, std::vector<cModule*>& modules)
{
    if (module->getClassName() == moduleType) {
        modules.push_back(module);
    }
    
    for (cModule::SubmoduleIterator it(module); !it.end(); ++it) {
        findModulesByTypeRecursive(*it, moduleType, modules);
    }
}

// cIListener interface implementations - RECORD EVERY SIGNAL EVENT
void DataCollector::receiveSignal(cComponent *source, simsignal_t signalID, bool value, cObject *details)
{
    std::string signalName = cComponent::getSignalName(signalID);
    double timestamp = simTime().dbl();
    std::string sourcePath = source->getFullPath();
    
    EV_DEBUG << "📡 [DATACOLLECTOR] Received bool signal: " << signalName << " = " << (value ? "true" : "false") 
             << " from " << sourcePath << " at " << timestamp << endl;
    
    // Record this signal event immediately
    recordSignalEvent(signalName, value ? 1.0 : 0.0, timestamp, sourcePath, "bool");
}

void DataCollector::receiveSignal(cComponent *source, simsignal_t signalID, intval_t value, cObject *details)
{
    std::string signalName = cComponent::getSignalName(signalID);
    double timestamp = simTime().dbl();
    std::string sourcePath = source->getFullPath();
    
    EV_DEBUG << "📡 [DATACOLLECTOR] Received int signal: " << signalName << " = " << value 
             << " from " << sourcePath << " at " << timestamp << endl;
    
    // Record this signal event immediately
    recordSignalEvent(signalName, static_cast<double>(value), timestamp, sourcePath, "int");
}

void DataCollector::receiveSignal(cComponent *source, simsignal_t signalID, uintval_t value, cObject *details)
{
    std::string signalName = cComponent::getSignalName(signalID);
    double timestamp = simTime().dbl();
    std::string sourcePath = source->getFullPath();
    
    EV_DEBUG << "📡 [DATACOLLECTOR] Received uint signal: " << signalName << " = " << value 
             << " from " << sourcePath << " at " << timestamp << endl;
    
    // Record this signal event immediately
    recordSignalEvent(signalName, static_cast<double>(value), timestamp, sourcePath, "uint");
}

void DataCollector::receiveSignal(cComponent *source, simsignal_t signalID, double value, cObject *details)
{
    std::string signalName = cComponent::getSignalName(signalID);
    double timestamp = simTime().dbl();
    std::string sourcePath = source->getFullPath();
    
    EV_DEBUG << "📡 [DATACOLLECTOR] Received double signal: " << signalName << " = " << value 
             << " from " << sourcePath << " at " << timestamp << endl;
    
    // Record this signal event immediately
    recordSignalEvent(signalName, value, timestamp, sourcePath, "double");
}

void DataCollector::receiveSignal(cComponent *source, simsignal_t signalID, const SimTime& value, cObject *details)
{
    std::string signalName = cComponent::getSignalName(signalID);
    double timestamp = simTime().dbl();
    std::string sourcePath = source->getFullPath();
    
    EV_DEBUG << "📡 [DATACOLLECTOR] Received SimTime signal: " << signalName << " = " << value 
             << " from " << sourcePath << " at " << timestamp << endl;
    
    // Record this signal event immediately
    recordSignalEvent(signalName, value.dbl(), timestamp, sourcePath, "SimTime");
}

void DataCollector::receiveSignal(cComponent *source, simsignal_t signalID, const char *value, cObject *details)
{
    std::string signalName = cComponent::getSignalName(signalID);
    double timestamp = simTime().dbl();
    std::string sourcePath = source->getFullPath();
    
    EV_DEBUG << "📡 [DATACOLLECTOR] Received string signal: " << signalName << " = " << (value ? value : "null") 
             << " from " << sourcePath << " at " << timestamp << endl;
    
    // For string signals, use the length as a numeric value
    recordSignalEvent(signalName, value ? static_cast<double>(strlen(value)) : 0.0, timestamp, sourcePath, "string");
}

void DataCollector::receiveSignal(cComponent *source, simsignal_t signalID, cObject *value, cObject *details)
{
    std::string signalName = cComponent::getSignalName(signalID);
    double timestamp = simTime().dbl();
    std::string sourcePath = source->getFullPath();
    
    EV_DEBUG << "📡 [DATACOLLECTOR] Received object signal: " << signalName 
             << " from " << sourcePath << " at " << timestamp << endl;
    
    // For object signals, use 1.0 as a numeric value (packet was processed)
    recordSignalEvent(signalName, 1.0, timestamp, sourcePath, "object");
}

void DataCollector::recordSignalEvent(const std::string& signalName, double value, double timestamp, const std::string& sourcePath, const std::string& dataType)
{
    // Determine phase based on timestamp
    std::string phase;
    if (timestamp < 0.1) { 
        phase = "normal"; 
    } else if (timestamp >= 0.1 && timestamp < 0.4) { 
        phase = "attack"; 
    } else { 
        phase = "reaction"; 
    }
    
    // Extract module name from source path
    std::string moduleName = sourcePath;
    size_t lastDot = sourcePath.find_last_of('.');
    if (lastDot != std::string::npos) {
        moduleName = sourcePath.substr(lastDot + 1);
    }
    
    // Write this signal event immediately to CSV
    if (csvFile.is_open()) {
        csvFile << timestamp << ","
                << signalName << ","
                << value << ","
                << sourcePath << ","
                << moduleName << ","
                << phase << ","
                << dataType << std::endl;
        csvFile.flush(); // Ensure immediate write
    }
    
    // Update counters
    if (signalName == "packetSent") packetsSentCount++;
    else if (signalName == "packetReceived") packetsReceivedCount++;
    else if (signalName == "packetDropped") packetsDroppedCount++;
}

void DataCollector::writeCSVHeader()
{
    EV_INFO << "📝 [DATACOLLECTOR] Writing CSV header to: " << csvOutputFile << endl;
    
    if (!csvFile.is_open()) {
        EV_ERROR << "❌ [DATACOLLECTOR] CSV file not open for header writing!" << endl;
        return;
    }
    
    csvFile << "timestamp,signal_name,value,source_path,module_name,phase,data_type" << endl;
    csvFile.flush();  // Ensure header is written immediately
    
    EV_INFO << "📝 CSV header written - recording ALL signal events!" << endl;
}

std::string DataCollector::getScenarioLabel()
{
    std::string configName = getEnvir()->getConfigEx()->getActiveConfigName();

    // Map configuration names to standard ML labels
    if (configName == "Baseline") return "normal";
    else if (configName == "DoSAttack") return "dos_attack";
    else if (configName == "TimingAttack") return "timing_attack";
    else if (configName == "SpoofingAttack") return "spoofing_attack";
    else return configName; // Use original name if not recognized
}

void DataCollector::finish()
{
    EV_INFO << "🏁 [DATACOLLECTOR] Complete signal capture completed!" << endl;
    EV_INFO << "📁 Data saved to: " << csvOutputFile << endl;
    
    if (csvFile.is_open()) {
        csvFile.close();
    }
    
    // Print summary
    EV_INFO << "📊 Collection Summary:" << endl;
    EV_INFO << "   Signals captured: packetSent, packetReceived, packetDropped, packetCreated, packetRecorded" << endl;
    EV_INFO << "   Total packetSent events: " << packetsSentCount << endl;
    EV_INFO << "   Total packetReceived events: " << packetsReceivedCount << endl;
    EV_INFO << "   Total packetDropped events: " << packetsDroppedCount << endl;
    EV_INFO << "   Recording mode: ALL events captured (no time windows)" << endl;
    EV_INFO << "   CSV format: timestamp,signal_name,value,source_path,module_name,phase,data_type" << endl;
}

Define_Module(DataCollector);

