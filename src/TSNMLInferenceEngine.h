#ifndef __MINIMALPSFPATTACKML_TSNMLINFERENCEENGINE_H
#define __MINIMALPSFPATTACKML_TSNMLINFERENCEENGINE_H

#include <omnetpp.h>
#include <string>
#include <vector>
#include <map>
#include <memory>

// Eigen includes (required for Frugally-Deep)
#include <Eigen/Dense>
#include <Eigen/Core>

// Frugally-Deep includes
#include <fdeep/fdeep.hpp>

using namespace omnetpp;

class TSNMLInferenceEngine : public cSimpleModule
{
private:
    // ML model and metadata
    std::unique_ptr<fdeep::model> ml_model;
    std::vector<std::string> feature_columns;
    std::vector<std::string> label_classes;
    
    // Feature extraction buffers
    std::map<std::string, double> current_features;
    std::map<std::string, std::vector<double>> feature_history;
    
    // Configuration
    std::string model_path;
    bool model_loaded;
    double inference_threshold;
    
    // Statistics
    simsignal_t attack_detected_signal;
    simsignal_t inference_latency_signal;
    simsignal_t confidence_signal;
    
    // Attack detection state
    bool attack_detected;
    std::string detected_attack_type;
    double detection_confidence;
    
    // Performance tracking
    simtime_t last_inference_time;
    long total_inferences;
    double total_inference_time;

public:
    TSNMLInferenceEngine();
    virtual ~TSNMLInferenceEngine();

protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;
    
private:
    // ML model management
    bool load_ml_model();
    bool initialize_feature_columns();
    
    // Feature extraction
    void extract_real_time_features();
    void update_feature_history(const std::string& feature_name, double value);
    std::vector<double> prepare_feature_vector();
    
    // ML inference
    bool perform_inference();
    std::string predict_attack_type(const std::vector<double>& features);
    double calculate_confidence(const std::vector<double>& features);
    
    // Attack detection
    void detect_attack();
    void emit_attack_signal();
    
    // Utility functions
    double get_feature_value(const std::string& feature_name);
    void log_inference_results(const std::string& prediction, double confidence);
};

#endif