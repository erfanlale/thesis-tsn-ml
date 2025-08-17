package src;

//
// TSNMLInferenceEngine Module for Real-time ML Inference
// 
// This module performs real-time anomaly/intrusion detection
// using trained ML models on TSN network data.
//
simple TSNMLInferenceEngine
{
    parameters:
        @node();
        @display("i=block/cogwheel");
        
        // ML model paths (unified results dir)
        string modelPath = default("simulations/results/tsn_minimal7_fdeep.json");
        string normPath = default("simulations/results/tsn_minimal7_norm.json");
        
        // Inference configuration
        bool enableInference = default(true);
        double inferenceInterval @unit(s) = default(10ms);
        
        // Thresholds for anomaly detection
        double anomalyThreshold = default(0.7);
        double intrusionThreshold = default(0.8);
        
    gates:
        input in[];
        output out[];
} 