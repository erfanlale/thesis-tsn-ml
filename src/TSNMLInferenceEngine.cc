#include "TSNMLInferenceEngine.h"
#include <iostream>
#include <fstream>
#include <chrono>

Define_Module(TSNMLInferenceEngine);

TSNMLInferenceEngine::TSNMLInferenceEngine()
{
    model_loaded = false;
    attack_detected = false;
    detected_attack_type = "normal";
    detection_confidence = 0.0;
    total_inferences = 0;
    total_inference_time = 0.0;
    inference_threshold = 0.7;
    ml_model = nullptr;
}

TSNMLInferenceEngine::~TSNMLInferenceEngine()
{
    // Cleanup handled in finish()
}

void TSNMLInferenceEngine::initialize()
{
    EV_INFO << "🎯 [TSNMLInferenceEngine] Initializing ML-based Attack Detection Engine" << endl;
    
    // Get configuration parameters
    model_path = par("modelPath").stringValue();
    inference_threshold = par("inferenceThreshold").doubleValue();
    
    EV_INFO << "📂 Model path: " << model_path << endl;
    EV_INFO << "🎯 Inference threshold: " << inference_threshold << endl;
    
    // Register signals
    attack_detected_signal = registerSignal("attackDetected");
    inference_latency_signal = registerSignal("inferenceLatency");
    confidence_signal = registerSignal("detectionConfidence");
    
    // Initialize feature columns (hardcoded for now, should be loaded from metadata)
    feature_columns = {
        "total_packets_sent", "total_packets_received", "total_packets_dropped",
        "packet_loss_rate", "max_queue_length", "avg_queue_length",
        "avg_queueing_time", "max_end_to_end_delay"
    };
    
    label_classes = {"normal", "dos_attack", "timing_attack", "spoofing_attack"};
    
    // Load ML model
    if (load_ml_model()) {
        EV_INFO << "✅ ML model loaded successfully!" << endl;
        model_loaded = true;
    } else {
        EV_ERROR << "❌ Failed to load ML model!" << endl;
        model_loaded = false;
    }
    
    // Initialize feature buffers
    for (const auto& feature : feature_columns) {
        current_features[feature] = 0.0;
        feature_history[feature] = std::vector<double>();
    }
    
    EV_INFO << "🎯 TSN ML Inference Engine ready for real-time attack detection!" << endl;
}

void TSNMLInferenceEngine::handleMessage(cMessage *msg)
{
    // Extract features from incoming message
    extract_real_time_features();
    
    // Perform ML inference
    if (model_loaded && perform_inference()) {
        // Attack detected
        emit_attack_signal();
    }
    
    // Clean up message
    delete msg;
}

void TSNMLInferenceEngine::finish()
{
    EV_INFO << "🏁 TSN ML Inference Engine finishing..." << endl;
    
    if (total_inferences > 0) {
        double avg_inference_time = total_inference_time / total_inferences;
        EV_INFO << "📊 Inference Statistics:" << endl;
        EV_INFO << "   Total inferences: " << total_inferences << endl;
        EV_INFO << "   Average inference time: " << avg_inference_time << " ms" << endl;
        EV_INFO << "   Attacks detected: " << (attack_detected ? "YES" : "NO") << endl;
        if (attack_detected) {
            EV_INFO << "   Attack type: " << detected_attack_type << endl;
            EV_INFO << "   Confidence: " << detection_confidence << endl;
        }
    }
}

bool TSNMLInferenceEngine::load_ml_model()
{
    try {
        EV_INFO << "📂 Loading ML model from: " << model_path << endl;
        
        // Load the Frugally-Deep model
        ml_model = std::make_unique<fdeep::model>(fdeep::load_model(model_path));
        
        EV_INFO << "✅ Model loaded successfully!" << endl;
        return true;
        
    } catch (const std::exception& e) {
        EV_ERROR << "❌ Error loading model: " << e.what() << endl;
        return false;
    }
}

void TSNMLInferenceEngine::extract_real_time_features()
{
    // This is a simplified feature extraction
    // In a real implementation, you would extract features from network statistics
    
    // Simulate feature extraction from network data
    current_features["total_packets_sent"] = get_feature_value("total_packets_sent");
    current_features["total_packets_received"] = get_feature_value("total_packets_received");
    current_features["total_packets_dropped"] = get_feature_value("total_packets_dropped");
    current_features["packet_loss_rate"] = get_feature_value("packet_loss_rate");
    current_features["max_queue_length"] = get_feature_value("max_queue_length");
    current_features["avg_queue_length"] = get_feature_value("avg_queue_length");
    current_features["avg_queueing_time"] = get_feature_value("avg_queueing_time");
    current_features["max_end_to_end_delay"] = get_feature_value("max_end_to_end_delay");
    
    // Update feature history
    for (const auto& feature : feature_columns) {
        update_feature_history(feature, current_features[feature]);
    }
}

double TSNMLInferenceEngine::get_feature_value(const std::string& feature_name)
{
    // This is a placeholder - in real implementation, get from network statistics
    // For now, return simulated values based on current simulation state
    
    // Simulate different attack patterns
    simtime_t current_time = simTime();
    
    if (feature_name == "total_packets_sent") {
        return 1000.0 + (current_time.dbl() * 100.0);
    } else if (feature_name == "total_packets_received") {
        return 950.0 + (current_time.dbl() * 95.0);
    } else if (feature_name == "total_packets_dropped") {
        return 50.0 + (current_time.dbl() * 5.0);
    } else if (feature_name == "packet_loss_rate") {
        return 0.05 + current_time.dbl() * 0.01;
    } else if (feature_name == "max_queue_length") {
        return 10.0 + (current_time.dbl() * 2.0);
    } else if (feature_name == "avg_queue_length") {
        return 5.0 + current_time.dbl();
    } else if (feature_name == "avg_queueing_time") {
        return 0.001 + current_time.dbl() * 0.0001;
    } else if (feature_name == "max_end_to_end_delay") {
        return 0.01 + current_time.dbl() * 0.001;
    }
    
    return 0.0;
}

void TSNMLInferenceEngine::update_feature_history(const std::string& feature_name, double value)
{
    feature_history[feature_name].push_back(value);
    
    // Keep only last 100 values
    if (feature_history[feature_name].size() > 100) {
        feature_history[feature_name].erase(feature_history[feature_name].begin());
    }
}

std::vector<double> TSNMLInferenceEngine::prepare_feature_vector()
{
    std::vector<double> features;
    
    for (const auto& feature_name : feature_columns) {
        features.push_back(current_features[feature_name]);
    }
    
    return features;
}

bool TSNMLInferenceEngine::perform_inference()
{
    if (!model_loaded || !ml_model) {
        return false;
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    try {
        // Prepare feature vector
        std::vector<double> features = prepare_feature_vector();
        
        // Convert to Frugally-Deep tensor with proper shape
        std::vector<float> float_features(features.begin(), features.end());
        fdeep::tensor input_tensor(fdeep::tensor_shape(static_cast<size_t>(float_features.size())), float_features);
        
        // Perform inference
        const auto result = ml_model->predict({input_tensor});
        
        // Process results
        if (!result.empty()) {
            const auto& output_tensor = result[0];
            const auto& output_values = output_tensor.to_vector();
            
            // Find the class with highest probability
            auto max_it = std::max_element(output_values.begin(), output_values.end());
            int predicted_class = std::distance(output_values.begin(), max_it);
            double confidence = *max_it;
            
            // Update detection state
            if (confidence > inference_threshold) {
                attack_detected = true;
                detected_attack_type = label_classes[predicted_class];
                detection_confidence = confidence;
                
                EV_INFO << "🚨 ATTACK DETECTED: " << detected_attack_type 
                        << " (confidence: " << confidence << ")" << endl;
            } else {
                attack_detected = false;
                detected_attack_type = "normal";
                detection_confidence = confidence;
            }
            
            // Update statistics
            auto end_time = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
            total_inference_time += duration.count() / 1000.0; // Convert to milliseconds
            total_inferences++;
            
            return attack_detected;
        }
        
    } catch (const std::exception& e) {
        EV_ERROR << "❌ Inference error: " << e.what() << endl;
    }
    
    return false;
}

std::string TSNMLInferenceEngine::predict_attack_type(const std::vector<double>& features)
{
    // This is a simplified rule-based prediction
    // In a real implementation, this would use the ML model output
    
    double packet_loss = features[3]; // packet_loss_rate
    double queue_length = features[4]; // max_queue_length
    double delay = features[7]; // max_end_to_end_delay
    
    if (packet_loss > 0.1) {
        return "dos_attack";
    } else if (delay > 0.05) {
        return "timing_attack";
    } else if (queue_length > 20) {
        return "spoofing_attack";
    }
    
    return "normal";
}

double TSNMLInferenceEngine::calculate_confidence(const std::vector<double>& features)
{
    // This is a simplified confidence calculation
    // In a real implementation, this would use the ML model probabilities
    
    double packet_loss = features[3];
    double queue_length = features[4];
    double delay = features[7];
    
    // Simple confidence based on feature values
    double confidence = 0.5;
    
    if (packet_loss > 0.05) confidence += 0.2;
    if (queue_length > 10) confidence += 0.15;
    if (delay > 0.01) confidence += 0.15;
    
    return std::min(confidence, 1.0);
}

void TSNMLInferenceEngine::detect_attack()
{
    if (!model_loaded) {
        return;
    }
    
    // Perform inference
    if (perform_inference()) {
        emit_attack_signal();
    }
}

void TSNMLInferenceEngine::emit_attack_signal()
{
    if (attack_detected) {
        // Emit attack detection signal
        emit(attack_detected_signal, 1);
        emit(confidence_signal, detection_confidence);
        
        EV_INFO << "🚨 EMITTING ATTACK SIGNAL: " << detected_attack_type 
                << " (confidence: " << detection_confidence << ")" << endl;
    }
}

void TSNMLInferenceEngine::log_inference_results(const std::string& prediction, double confidence)
{
    EV_INFO << "📊 ML Inference Result: " << prediction << " (confidence: " << confidence << ")" << endl;
}