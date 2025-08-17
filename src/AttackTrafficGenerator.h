#ifndef __PSFP_ATTACKTRAFFICGENERATOR_H
#define __PSFP_ATTACKTRAFFICGENERATOR_H

#include <omnetpp.h>
#include <inet/applications/base/ApplicationBase.h>
#include <inet/transportlayer/contract/udp/UdpSocket.h>
#include <inet/networklayer/common/L3Address.h>
#include <inet/common/packet/Packet.h>

using namespace omnetpp;
using namespace inet;

/**
 * Attack Traffic Generator for TSN Intrusion Detection Testing
 * 
 * Generates predetermined attack scenarios with precise timing for:
 * - Creating labeled training/testing/validation datasets
 * - Testing ML-based intrusion detection systems
 * - Evaluating TSN network resilience under attacks
 */
class AttackTrafficGenerator : public ApplicationBase
{
public:
    enum AttackType {
        DOS_FLOODING,
        SPOOFING, 
        TIMING_ATTACK,
        MIXED
    };

protected:
    // Configuration parameters
    AttackType attackType;
    std::string targetDestination;
    int targetPort;
    simtime_t startTime;
    simtime_t duration;
    simtime_t rampUpTime;
    
    // Attack intensity
    double normalRate;
    double attackRate;
    int attackPacketSize;
    
    // Spoofing parameters
    L3Address spoofSourceAddress;
    std::string spoofSourceName;
    
    // Traffic patterns
    bool enableBurstyTraffic;
    simtime_t burstDuration;
    simtime_t burstInterval;
    
    // Labeling and logging
    std::string attackLabel;
    bool enableAttackLogging;
    
    // State tracking
    UdpSocket socket;
    cMessage *attackStartEvent;
    cMessage *attackStopEvent;
    cMessage *sendPacketEvent;
    cMessage *burstEvent;
    
    bool attackActive;
    bool inBurst;
    long packetsGenerated;
    long maliciousPacketsSent;
    
    // Performance tracking
    simtime_t lastPacketTime;
    double currentRate;

protected:
    virtual void initialize(int stage) override;
    virtual void handleMessageWhenUp(cMessage *msg) override;
    virtual void finish() override;
    
    // Attack lifecycle
    virtual void startAttack();
    virtual void stopAttack();
    virtual void sendAttackPacket();
    
    // Attack type implementations
    virtual void sendDosFloodingPacket();
    virtual void sendSpoofingPacket();
    virtual void sendTimingAttackPacket();
    virtual void sendMixedAttackPacket();
    
    // Burst management
    virtual void startBurst();
    virtual void stopBurst();
    
    // Utility functions
    virtual double calculateCurrentRate();
    virtual Packet* createAttackPacket(const char* name, int size);
    virtual void logAttackEvent(const char* event, const char* details = "");
    
    // Network helper functions
    virtual L3Address resolveDestination(const std::string& dest);
    virtual void setupSocket();

public:
    // Statistics for ML feature extraction
    virtual long getPacketsGenerated() const { return packetsGenerated; }
    virtual long getMaliciousPacketsSent() const { return maliciousPacketsSent; }
    virtual double getCurrentAttackRate() const { return currentRate; }
    virtual bool isAttackActive() const { return attackActive; }
    virtual std::string getAttackType() const;
};

#endif // __PSFP_ATTACKTRAFFICGENERATOR_H 