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
// Total: 7 nodes (compared to 22 in the complex version)
//
network MinimalAttackNetwork extends TsnNetworkBase
{
    parameters:
        @display("bgi=background/car_simple;bgb=800,600");

    submodules:
        // ML Feature Collector - ENABLED for real-time data collection
        dataCollector: DataCollector {
            @display("p=50,350;i=block/process");
        }
        
        // ML Inference Engine
        mlInferenceEngine: TSNMLInferenceEngine {
            @display("p=50,250;i=block/cogwheel");
        }
        
        // Master clock for TSN time synchronization
        masterClock: TsnClock {
            @display("p=400,300;i=device/card");
        }
        
        // Single central TSN switch
        centralSwitch: TsnSwitch {
            @display("p=400,200");
        }
        
        // Essential legitimate devices
        mainECU: TsnDevice {
            @display("p=300,100;i=device/server");
        }
        
        criticalSensor: TsnDevice {
            @display("p=500,100;i=device/sensor");
        }
        
        display: TsnDevice {
            @display("p=400,100;i=device/monitor");
        }
        
        // Attack components for testing
        attackerExternal: TsnDevice {
            @display("p=200,200;i=device/laptop,red");
        }
        
        compromisedNode: TsnDevice {
            @display("p=600,200;i=device/laptop,orange");
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