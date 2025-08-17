package simulations;

import inet.networks.base.TsnNetworkBase;
import inet.node.tsn.TsnDevice;
import inet.node.tsn.TsnSwitch;
import inet.node.tsn.TsnClock;
import inet.node.ethernet.Eth100M;
import inet.node.ethernet.Eth1G;
import src.DataCollector;
import src.TSNMLInferenceEngine;

network AttackScenarioNetwork extends TsnNetworkBase
{
    parameters:
        @display("bgi=background/car;bgb=1280,720");

    submodules:
        // Master clock for time synchronization
        masterClock: TsnClock {
            @display("p=640,360;i=device/card");
        }
        
        // TSN switches for vehicle zones
        frontSwitch: TsnSwitch {
            @display("p=750,300");
        }
        
        rearSwitch: TsnSwitch {
            @display("p=530,300");
        }
        
        frontLeftSwitch: TsnSwitch {
            @display("p=850,220");
        }
        
        frontRightSwitch: TsnSwitch {
            @display("p=850,380");
        }
        
        rearLeftSwitch: TsnSwitch {
            @display("p=430,220");
        }
        
        rearRightSwitch: TsnSwitch {
            @display("p=430,380");
        }
        
        // Central processing units
        mainECU: TsnDevice {
            @display("p=640,300");
        }
        
        obu: TsnDevice {
            @display("p=580,200");
        }
        
        hud: TsnDevice {
            @display("p=700,200");
        }
        
        rearDisplay: TsnDevice {
            @display("p=640,400");
        }
        
        // Control systems
        steering: TsnDevice {
            @display("p=750,200");
        }
        
        engineActuator: TsnDevice {
            @display("p=640,450");
        }
        
        // Wheel controllers
        frontLeftWheel: TsnDevice {
            @display("p=900,150");
        }
        
        frontRightWheel: TsnDevice {
            @display("p=900,450");
        }
        
        rearLeftWheel: TsnDevice {
            @display("p=380,150");
        }
        
        rearRightWheel: TsnDevice {
            @display("p=380,450");
        }
        
        // Sensors
        lidar: TsnDevice {
            @display("p=750,250");
        }
        
        // Cameras
        frontLeftCamera: TsnDevice {
            @display("p=950,200");
        }
        
        frontRightCamera: TsnDevice {
            @display("p=950,400");
        }
        
        rearLeftCamera: TsnDevice {
            @display("p=330,200");
        }
        
        rearRightCamera: TsnDevice {
            @display("p=330,400");
        }
        
        // Attack components
        attackerExternal: TsnDevice {
            @display("p=200,300;i=device/laptop,red");
        }
        
        compromisedNode: TsnDevice {
            @display("p=1080,300;i=device/laptop,orange");
        }

        // ML support modules (standalone; no wiring needed)
        dataCollector: src.DataCollector {
            @display("p=120,60;i=block/process");
        }
        mlInferenceEngine: src.TSNMLInferenceEngine {
            @display("p=120,120;i=block/cogwheel");
        }

    connections:
        // Master clock for TSN time synchronization
        masterClock.ethg++ <--> Eth100M <--> frontSwitch.ethg++ if exists(masterClock);
        
        // Inter-switch backbone (high-speed 1Gbps)
        frontSwitch.ethg++ <--> Eth1G <--> rearSwitch.ethg++;
        frontSwitch.ethg++ <--> Eth1G <--> frontLeftSwitch.ethg++;
        frontSwitch.ethg++ <--> Eth1G <--> frontRightSwitch.ethg++;
        rearSwitch.ethg++ <--> Eth1G <--> rearLeftSwitch.ethg++;
        rearSwitch.ethg++ <--> Eth1G <--> rearRightSwitch.ethg++;
        
        // Central processing units
        frontSwitch.ethg++ <--> Eth1G <--> mainECU.ethg++;
        frontSwitch.ethg++ <--> Eth100M <--> obu.ethg++;
        frontSwitch.ethg++ <--> Eth100M <--> hud.ethg++;
        rearSwitch.ethg++ <--> Eth100M <--> rearDisplay.ethg++;
        
        // Control systems
        frontSwitch.ethg++ <--> Eth100M <--> steering.ethg++;
        rearSwitch.ethg++ <--> Eth100M <--> engineActuator.ethg++;
        
        // Wheel controllers
        frontLeftSwitch.ethg++ <--> Eth100M <--> frontLeftWheel.ethg++;
        frontRightSwitch.ethg++ <--> Eth100M <--> frontRightWheel.ethg++;
        rearLeftSwitch.ethg++ <--> Eth100M <--> rearLeftWheel.ethg++;
        rearRightSwitch.ethg++ <--> Eth100M <--> rearRightWheel.ethg++;
        
        // Sensors
        frontSwitch.ethg++ <--> Eth1G <--> lidar.ethg++;
        
        // Cameras
        frontLeftSwitch.ethg++ <--> Eth100M <--> frontLeftCamera.ethg++;
        frontRightSwitch.ethg++ <--> Eth100M <--> frontRightCamera.ethg++;
        rearLeftSwitch.ethg++ <--> Eth100M <--> rearLeftCamera.ethg++;
        rearRightSwitch.ethg++ <--> Eth100M <--> rearRightCamera.ethg++;
        
        // Attack components
        frontSwitch.ethg++ <--> Eth100M <--> attackerExternal.ethg++;
        rearSwitch.ethg++ <--> Eth100M <--> compromisedNode.ethg++;
} 