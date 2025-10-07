#ifndef __MINIMALPSFPATTACKML_TSNMLINFERENCEENGINE_H
#define __MINIMALPSFPATTACKML_TSNMLINFERENCEENGINE_H

#include <omnetpp.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <fstream>

// Eigen includes (real Eigen library)
// Eigen used by frugally-deep internally; we avoid direct heavy use here

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
    std::string norm_path;
    bool model_loaded;
    double inference_threshold;
    
    // Statistics
    simsignal_t attack_detected_signal;
    simsignal_t inference_latency_signal;
    simsignal_t confidence_signal;
    simsignal_t inferenceResult_signal;
    
    // Attack detection state
    bool attack_detected;
    std::string detected_attack_type;
    double detection_confidence;
    
    // Performance tracking
    simtime_t last_inference_time;
    long total_inferences;
    double total_inference_time;
    cMessage *inferenceTimer = nullptr;

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

public:
    struct MinimalFeatures {
        double packets_sent;
        double packets_received;
        double packets_dropped;
        double loss_rate;
        double queue_len_max;
        double queueing_time_avg;
        double e2e_delay_avg;
        double avg_rate_ratio;
    };

    struct InferenceResult { std::string label; double confidence; };

    InferenceResult inferMinimal(const MinimalFeatures& f);

    // Option A: pull features from DataCollector
    bool pullAndInferWindow();

    // normalization
    std::vector<double> norm_mean; // zscore mean aligned to F7 order
    std::vector<double> norm_std;  // zscore std aligned to F7 order
    std::ofstream inferenceLog;
    
    // Helper to pull minimal 7-feature window from DataCollector
    bool pullF7FromCollector(std::array<double,7>& f7, simtime_t& t0, simtime_t& t1);

    // Deduplicate processing within same window
    simtime_t lastWindowEndProcessed = SIMTIME_ZERO;
};

#endif