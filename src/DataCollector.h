#ifndef __MINIMALPSFPATTACKML_DATACOLLECTOR_H
#define __MINIMALPSFPATTACKML_DATACOLLECTOR_H

#include <omnetpp.h>
#include <fstream>
#include <string>
#include <vector>
#include <map>

using namespace omnetpp;

class DataCollector : public cSimpleModule, public cIListener
{
private:
    // Data collection
    std::string csvOutputFile;
    std::ofstream csvFile;
    
    // Signal counters for statistics
    long packetsSentCount = 0;
    long packetsReceivedCount = 0;
    long packetsDroppedCount = 0;
    
public:
    DataCollector();
    virtual ~DataCollector();
    
protected:
    virtual void initialize() override;
    virtual void initialize(int stage) override;
    virtual void finish() override;
    
    // cIListener interface methods
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, bool value, cObject *details) override;
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, intval_t value, cObject *details) override;
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, uintval_t value, cObject *details) override;
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, double value, cObject *details) override;
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, const SimTime& value, cObject *details) override;
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, const char *value, cObject *details) override;
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, cObject *value, cObject *details) override;
    
private:
    void subscribeToSignals();
    void subscribeToModuleSignals(cModule *module, const std::vector<std::string>& signalNames, int& totalSubscriptions);
    void recordSignalEvent(const std::string& signalName, double value, double timestamp, const std::string& sourcePath, const std::string& dataType);
    void writeCSVHeader();
    void findModulesByType(const std::string& moduleType, std::vector<cModule*>& modules);
    void findModulesByTypeRecursive(cModule *module, const std::string& moduleType, std::vector<cModule*>& modules);
    
    // Utility functions
    std::string getScenarioLabel();
};

#endif
