package src;

//
// DataCollector Module for TSN Signal Capture
// 
// This module subscribes to packetSent and packetReceived signals
// from all network components and outputs them in JSON format
// for ML pipeline consumption.
//
simple DataCollector
{
    parameters:
        @node();
        @display("i=block/process");
        
        // Output file configuration
        string outputFile = default("results_flat/tsn_signals.csv");
        
        // Time-windowed aggregation configuration
        double windowLength @unit(s) = default(5ms);   // Time window size for aggregation
        bool emitCSV = default(true);                  // Output CSV format for ML
        bool emitRaw = default(false);                 // Output raw JSON per event (debug only)
        bool emitNDJSON = default(false);              // Output newline-delimited JSON
        bool emitPerStreamRows = default(false);       // Also write per-stream aggregate rows per window
        
        // Signal capture configuration  
        bool enableSignalCapture = default(true);
        bool capturePacketSent = default(true);
        bool capturePacketReceived = default(true);
        bool capturePacketDropped = default(true);
        
        // Simulation info
        string scenario = default("unknown");
        
    gates:
        input in[];
        output out[];
} 