#include "TSNMLInferenceEngine.h"
#include "DataCollector.h"
#include <iostream>
#include <fstream>
#include <chrono>
#include <cmath>

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
    if (hasPar("normPath")) norm_path = par("normPath").stringValue();
    inference_threshold = par("anomalyThreshold").doubleValue();
    
    EV_INFO << "📂 Model path: " << model_path << endl;
    EV_INFO << "🎯 Inference threshold: " << inference_threshold << endl;
    
    // Register signals
    attack_detected_signal = registerSignal("attackDetected");
    inference_latency_signal = registerSignal("inferenceLatency");
    confidence_signal = registerSignal("detectionConfidence");
    
    // Extended 15-feature order aligned with training feature_order
    // [throughput_bps_tx, packets_sent, packets_received, packets_dropped, drop_rate, queue_length_max,
    //  ptp_offset_mean, ptp_offset_max, rate_ratio_mean, peer_delay_mean,
    //  e2e_delay_avg, e2e_delay_max, e2e_delay_std, has_ptp, has_e2e]
    feature_columns = {
        "throughput_bps_tx",
        "packets_sent","packets_received","packets_dropped","drop_rate",
        "queue_length_max",
        "ptp_offset_mean","ptp_offset_max","rate_ratio_mean","peer_delay_mean",
        "e2e_delay_avg","e2e_delay_max","e2e_delay_std",
        "has_ptp","has_e2e"
    };
    
    label_classes = {"normal", "dos_attack", "timing_attack", "spoofing_attack"};
    
    // Load ML model
    if (load_ml_model()) {
        EV_INFO << "✅ ML model loaded successfully!" << endl;
        model_loaded = true;
        // Open inference log
        std::string cfg = getEnvir()->getConfigEx()->getVariable("configname");
        if (cfg.empty()) cfg = "run";
        std::string rep = getEnvir()->getConfigEx()->getVariable("repetition");
        if (rep.empty()) rep = "0";
        std::string runId = cfg + "-#" + rep;
        // Place inference logs next to the model file directory (usually project-root/ml_models)
        std::string outDir;
        {
            outDir = model_path;
            auto pos = outDir.find_last_of('/');
            if (pos != std::string::npos) outDir = outDir.substr(0, pos);
            else outDir = ".";
        }
        std::string outPath = outDir + "/inference_" + runId + ".csv";
        // Ensure directory exists before opening (relative to current working dir)
        {
            std::string cmd = std::string("mkdir -p ") + outDir;
            int rc = system(cmd.c_str()); (void)rc;
        }
        inferenceLog.open(outPath);
        if (inferenceLog.is_open()) {
            inferenceLog << "ts,t0,t1,p_normal,p_anomaly,pred_label,gt_label,"
                         << "f0_thr_tx,f1_pkts_sent,f2_pkts_recv,f3_pkts_drop,f4_drop_rate,f5_queue_len_max,"
                         << "f6_ptp_off_mean,f7_ptp_off_max,f8_rate_ratio_mean,f9_peer_delay_mean,f10_e2e_avg,f11_e2e_max,f12_e2e_std,f13_has_ptp,f14_has_e2e,threshold\n";
        }
    } else {
        EV_ERROR << "❌ Failed to load ML model!" << endl;
        model_loaded = false;
    }
    
    // Initialize feature buffers
    for (const auto& feature : feature_columns) {
        current_features[feature] = 0.0;
        feature_history[feature] = std::vector<double>();
    }
    
    // Load normalization stats (if present)
    try {
        if (!norm_path.empty()) {
            std::ifstream jf(norm_path);
            if (jf.good()) {
                std::string s((std::istreambuf_iterator<char>(jf)), std::istreambuf_iterator<char>());
                // naive parse without dependency
                auto get_array = [&](const std::string &key){
                    std::vector<double> v; size_t p=s.find("\""+key+"\""); if(p==std::string::npos) return v; p=s.find('[',p); size_t e=s.find(']',p); if(e==std::string::npos) return v; std::string a=s.substr(p+1,e-p-1); size_t i=0; while(i<a.size()){ size_t j=a.find(',',i); std::string t=a.substr(i,(j==std::string::npos? a.size():j)-i); try{ v.push_back(std::stod(t)); }catch(...){} if(j==std::string::npos) break; i=j+1;} return v; };
                norm_mean = get_array("mean");
                norm_std  = get_array("std");
                // optional: read recommended threshold if present
                auto get_num = [&](const std::string &key){ size_t p=s.find("\""+key+"\""); if(p==std::string::npos) return 0.0; p=s.find(':',p); if(p==std::string::npos) return 0.0; size_t e=p+1; while(e<s.size() && (s[e]==' '||s[e]=='\t')) e++; size_t e2=e; while(e2<s.size() && (isdigit(s[e2])||s[e2]=='.')) e2++; try{ return std::stod(s.substr(e,e2-e)); }catch(...){return 0.0;}};
                double thrRec = get_num("recommended_threshold");
                if (thrRec > 0.0 && thrRec < 1.0) inference_threshold = thrRec;
            }
        }
    } catch (...) {}

    // Start periodic inference timer
    if (!inferenceTimer) {
        inferenceTimer = new cMessage("inferenceTimer");
    }
    scheduleAt(simTime() + par("inferenceInterval"), inferenceTimer);

    EV_INFO << "🎯 TSN ML Inference Engine ready for real-time attack detection!" << endl;
}

void TSNMLInferenceEngine::handleMessage(cMessage *msg)
{
    if (msg == inferenceTimer) {
        // Pull current window from DataCollector and infer at fixed cadence
        pullAndInferWindow();
        scheduleAt(simTime() + par("inferenceInterval"), inferenceTimer);
    } else {
        delete msg;
    }
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
    if (inferenceTimer) {
        cancelAndDelete(inferenceTimer);
        inferenceTimer = nullptr;
    }
    if (inferenceLog.is_open()) inferenceLog.close();
}

TSNMLInferenceEngine::InferenceResult TSNMLInferenceEngine::inferMinimal(const MinimalFeatures& f)
{
    InferenceResult r{"unknown", 0.0};
    try {
        if (!ml_model) return r;
        std::vector<float> v = {
            static_cast<float>(f.packets_sent),
            static_cast<float>(f.packets_received),
            static_cast<float>(f.packets_dropped),
            static_cast<float>(f.loss_rate),
            static_cast<float>(f.queue_len_max),
            static_cast<float>(f.queueing_time_avg),
            static_cast<float>(f.e2e_delay_avg),
            static_cast<float>(f.avg_rate_ratio)
        };
        const auto input = fdeep::tensor(fdeep::tensor_shape(static_cast<std::size_t>(v.size())), v);
        const auto t0 = std::chrono::high_resolution_clock::now();
        const auto out = ml_model->predict({input});
        const auto t1 = std::chrono::high_resolution_clock::now();
        const auto out_vec = out.front().to_vector();
        std::size_t argmax = 0; float best = out_vec[0];
        for (std::size_t i=1;i<out_vec.size();++i) if (out_vec[i] > best) { best = out_vec[i]; argmax = i; }
        r.confidence = best;
        r.label = (argmax < label_classes.size()) ? label_classes[argmax] : std::string("class_") + std::to_string(argmax);
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0);
        emit(inference_latency_signal, duration.count()/1000.0);
        return r;
    } catch (...) {
        return r;
    }
}

bool TSNMLInferenceEngine::pullAndInferWindow()
{
    try {
        if (!model_loaded || !ml_model) return false;
        // Pull from DataCollector
        cModule *sys = getSystemModule();
        if (!sys) return false;
        auto *dc = dynamic_cast<DataCollector*>(sys->getSubmodule("dataCollector"));
        if (!dc) return false;
        const auto &w = dc->getLastWindow();
        const auto &we = dc->getLastWindowExtended();
        if (!w.ready && !we.ready) return false;
        std::vector<float> in;
        if (we.ready) {
            // Copy and apply missing-value semantics: timing features -1.0 => NaN
            double tmp[15];
            for (int i=0;i<15;i++) tmp[i] = we.f[i];
            for (int i=6;i<=12;i++) if (tmp[i] < 0.0) tmp[i] = std::numeric_limits<double>::quiet_NaN();
            // Normalize and impute NaNs to 0 after z-score, matching trainer
            in.reserve(15);
            if (norm_mean.size() == 15 && norm_std.size() == 15) {
                for (int i=0;i<15;i++) {
                    if (std::isnan(tmp[i])) { in.push_back(0.0f); continue; }
                    double denom = (norm_std[i] == 0.0 ? 1.0 : norm_std[i]);
                    float v = static_cast<float>((tmp[i] - norm_mean[i]) / denom);
                    if (std::isnan(v) || !std::isfinite(v)) v = 0.0f;
                    in.push_back(v);
                }
            } else {
                for (int i=0;i<15;i++) {
                    float v = std::isnan(tmp[i]) ? 0.0f : static_cast<float>(tmp[i]);
                    in.push_back(v);
                }
            }
        } else {
            in.reserve(7);
            for (int i=0;i<7;i++) in.push_back(static_cast<float>(w.f[i]));
            if (norm_mean.size() == 7 && norm_std.size() == 7) {
                for (int i=0;i<7;i++) {
                    double denom = (norm_std[i] == 0.0 ? 1.0 : norm_std[i]);
                    in[i] = static_cast<float>((w.f[i] - norm_mean[i]) / denom);
                }
            }
        }
        const auto t0 = std::chrono::high_resolution_clock::now();
        const auto input = fdeep::tensor(fdeep::tensor_shape(static_cast<std::size_t>(in.size())), in);
        const auto out = ml_model->predict({input});
        const auto t1 = std::chrono::high_resolution_clock::now();
        double p_normal = 0.0, p_anomaly = 0.0;
        if (!out.empty()) {
            const auto vec = out.front().to_vector();
            if (vec.size() >= 2) {
                p_normal = vec[0];
                p_anomaly = vec[1];
            } else if (vec.size() == 1) {
                p_anomaly = vec[0];
                p_normal = 1.0 - p_anomaly;
            }
        }
        double thr = par("anomalyThreshold");
        bool is_anomaly = p_anomaly > thr;
        auto dur = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0);
        total_inference_time += dur.count() / 1000.0;
        total_inferences++;
        emit(inference_latency_signal, dur.count()/1000.0);
        emit(confidence_signal, p_anomaly);
        attack_detected = is_anomaly;
        detected_attack_type = is_anomaly ? std::string("anomaly") : std::string("normal");
        detection_confidence = p_anomaly;
        if (inferenceLog.is_open()) {
            auto labelFor = [&](double t0d, double t1d)->std::string{
                std::string cfg = getEnvir()->getConfigEx()->getVariable("configname");
                if (cfg == "Baseline") return "normal";
                auto overlaps = [](double ws, double we, double as, double ae){ const double eps=1e-12; return (ws < ae - eps) && (we > as + eps); };
                if (cfg == "DoSAttack") return overlaps(t0d, t1d, 0.100, 0.400) ? std::string("dos_attack") : std::string("normal");
                if (cfg == "TimingAttack") return overlaps(t0d, t1d, 0.050, 0.450) ? std::string("timing_attack") : std::string("normal");
                if (cfg == "SpoofingAttack") return overlaps(t0d, t1d, 0.150, 0.350) ? std::string("spoofing_attack") : std::string("normal");
                return std::string("normal");
            };
            const double tnow = SIMTIME_DBL(simTime());
            const double t0d = we.ready ? we.t0.dbl() : w.t0.dbl();
            const double t1d = we.ready ? we.t1.dbl() : w.t1.dbl();
            std::string gt = labelFor(t0d, t1d);
            std::string predLabel = is_anomaly ? std::string("anomaly") : std::string("normal");
            inferenceLog << tnow << "," << t0d << "," << t1d << ","
                         << p_normal << "," << p_anomaly << "," << predLabel << "," << gt << ","
                         << (we.ready? we.f[0]: w.f[0]) << "," << (we.ready? we.f[1]: w.f[1]) << "," << (we.ready? we.f[2]: w.f[2]) << "," << (we.ready? we.f[3]: w.f[3]) << ","
                         << (we.ready? we.f[4]: w.f[4]) << "," << (we.ready? we.f[5]: w.f[5]) << "," << (we.ready? we.f[6]: w.f[6]) << "," << thr << "\n";
        }
        return true;
    } catch (...) {
        return false;
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