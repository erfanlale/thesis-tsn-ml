package simulations;

import inet.networks.base.TsnNetworkBase;
import inet.node.tsn.TsnDevice;
import inet.node.tsn.TsnSwitch;
import inet.node.tsn.TsnClock;
import inet.node.ethernet.Eth100M;
import inet.node.ethernet.Eth1G;
import src.DataCollector;
import src.TSNMLInferenceEngine;

//
// Minimal TSN Attack Network for ML-based Intrusion Detection
// 
// This minimal topology contains only essential components:
// - 1 master clock for TSN synchronization
// - 1 central TSN switch
// - 3 legitimate devices (ECU, sensor, display)
// - 2 attack nodes (external attacker, compromised node)
//
// Total: 7 nodes
//
network MinimalAttackNetwork extends TsnNetworkBase
{
    parameters:
        @display("bgi=background/car;bgb=1280,720");

    submodules:
        // ML Feature Collector - ENABLED for real-time data collection
        dataCollector: DataCollector {
            @display("p=150,520;i=block/blackboard;is=32");
        }

        // ML Inference Engine
        mlInferenceEngine: TSNMLInferenceEngine {
            @display("p=150,420;i=block/cogwheel;is=32");
        }

        // Master clock for TSN time synchronization
        masterClock: TsnClock {
            @display("p=600,410;i=device/clock;is=32");
        }

        // Single central TSN switch
        centralSwitch: TsnSwitch {
            @display("p=600,340;i=device/switch;is=36");
        }

        // Essential legitimate devices
        mainECU: TsnDevice {
            @display("p=599,249;i=device/server;is=32");
        }

        criticalSensor: TsnDevice {
            @display("p=798,482;i=device/card;is=32");
        }

        display: TsnDevice {
            @display("p=800,250;i=device/card;is=32");
        }

        // Attack components for testing
        attackerExternal: TsnDevice {
            @display("p=1100,300;i=device/laptop,red;is=32");
        }

        compromisedNode: TsnDevice {
            @display("p=799,360;i=device/laptop,orange;is=32");
        }

    connections:
        // Master clock connection (TSN time synchronization)
        masterClock.ethg++ <--> Eth100M <--> centralSwitch.ethg++;

        // Legitimate device connections
        centralSwitch.ethg++ <--> Eth1G <--> mainECU.ethg++;
        centralSwitch.ethg++ <--> Eth100M <--> criticalSensor.ethg++;
        centralSwitch.ethg++ <--> Eth100M <--> display.ethg++;

        // Attack component connections
        centralSwitch.ethg++ <--> Eth100M <--> attackerExternal.ethg++;
        centralSwitch.ethg++ <--> Eth100M <--> compromisedNode.ethg++;
}
