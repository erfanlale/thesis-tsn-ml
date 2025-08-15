package simulations;

//
// TSN ML Inference Engine
//
// Real-time anomaly detection module for TSN networks
// Integrates with frugally-deep for neural network inference
//
simple TSNMLInferenceEngine
{
    parameters:
        @display("i=block/cogwheel");
        string modelPath = default("ml_models/test_model.json");  // Path to ML model file
        double inferenceInterval @unit(s) = default(1ms);        // How often to perform inference
        @signal[anomalyScore](type=double);                      // Emitted anomaly score
        @statistic[anomalyScore](title="Anomaly Score"; record=vector,stats);
}