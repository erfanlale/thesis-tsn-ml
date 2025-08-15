#!/usr/bin/env python3
"""
🎯 TSN/PSFP Attack Detection - Real-time Inference Engine
=========================================================
Real-time attack detection for live OMNeT++ simulations
"""

import pandas as pd
import numpy as np
import json
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime
import joblib
from sklearn.pipeline import Pipeline

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('real_time_inference.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class RealTimeAttackDetector:
    """Real-time TSN Attack Detection Engine"""
    
    def __init__(self, models_dir: str, model_name: str = 'random_forest'):
        self.models_dir = Path(models_dir)
        self.model_name = model_name
        
        # Load model and metadata
        self.model = None
        self.metadata = None
        self.feature_columns = []
        self.label_classes = []
        
        self._load_model()
        
        logger.info(f"🎯 Real-time Attack Detector initialized")
        logger.info(f"🤖 Using model: {model_name}")
        logger.info(f"📁 Models directory: {models_dir}")
    
    def _load_model(self):
        """Load the trained ML model and metadata"""
        logger.info("📂 Loading trained model...")
        
        # Load model
        model_path = self.models_dir / f"{self.model_name}_model.joblib"
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")
        
        self.model = joblib.load(model_path)
        logger.info(f"✅ Loaded model from: {model_path}")
        
        # Load metadata
        metadata_path = self.models_dir / "model_metadata.json"
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                self.metadata = json.load(f)
            
            self.feature_columns = self.metadata.get('feature_columns', [])
            self.label_classes = self.metadata.get('label_classes', [])
            
            logger.info(f"📋 Loaded metadata: {len(self.feature_columns)} features, {len(self.label_classes)} classes")
        else:
            logger.warning("⚠️ Metadata not found, using default feature columns")
            # Default feature columns based on the training data
            self.feature_columns = [
                'total_packets_sent', 'total_packets_received', 'total_packets_dropped',
                'packet_loss_rate', 'max_queue_length', 'avg_queue_length',
                'avg_queueing_time', 'max_end_to_end_delay'
            ]
    
    def extract_features_from_data(self, data: Dict[str, Any]) -> np.ndarray:
        """Extract features from real-time data"""
        features = []
        
        for feature in self.feature_columns:
            if feature in data:
                features.append(float(data[feature]))
            else:
                # Use default value if feature not available
                features.append(0.0)
                logger.warning(f"⚠️ Feature '{feature}' not found in data, using 0.0")
        
        return np.array(features).reshape(1, -1)
    
    def detect_attack(self, features: np.ndarray) -> Dict[str, Any]:
        """Perform real-time attack detection"""
        try:
            # Make prediction
            prediction = self.model.predict(features)[0]
            probabilities = self.model.predict_proba(features)[0]
            
            # Get prediction details
            predicted_class = self.label_classes[prediction]
            confidence = probabilities[prediction]
            
            # Get all class probabilities
            class_probabilities = dict(zip(self.label_classes, probabilities))
            
            # Determine if attack is detected
            is_attack = predicted_class != 'normal'
            attack_type = predicted_class if is_attack else 'none'
            
            result = {
                'timestamp': datetime.now().isoformat(),
                'predicted_class': predicted_class,
                'confidence': float(confidence),
                'is_attack': is_attack,
                'attack_type': attack_type,
                'class_probabilities': class_probabilities,
                'features_used': len(features[0])
            }
            
            # Log detection result
            if is_attack:
                logger.warning(f"🚨 ATTACK DETECTED: {attack_type} (confidence: {confidence:.3f})")
            else:
                logger.info(f"✅ Normal traffic detected (confidence: {confidence:.3f})")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Error during attack detection: {str(e)}")
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'predicted_class': 'unknown',
                'confidence': 0.0,
                'is_attack': False,
                'attack_type': 'unknown'
            }
    
    def process_real_time_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process real-time data and return detection results"""
        logger.debug(f"📊 Processing real-time data: {len(data)} features")
        
        # Extract features
        features = self.extract_features_from_data(data)
        
        # Detect attack
        result = self.detect_attack(features)
        
        # Add input data summary
        result['input_data_summary'] = {
            'total_features_received': len(data),
            'features_processed': len(features[0]),
            'data_keys': list(data.keys())
        }
        
        return result
    
    def batch_detect(self, data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process multiple data points in batch"""
        logger.info(f"📦 Processing batch of {len(data_list)} data points")
        
        results = []
        for i, data in enumerate(data_list):
            logger.debug(f"Processing data point {i+1}/{len(data_list)}")
            result = self.process_real_time_data(data)
            results.append(result)
        
        # Summary statistics
        attack_count = sum(1 for r in results if r['is_attack'])
        normal_count = len(results) - attack_count
        
        logger.info(f"📊 Batch processing complete:")
        logger.info(f"   • Total samples: {len(results)}")
        logger.info(f"   • Attacks detected: {attack_count}")
        logger.info(f"   • Normal traffic: {normal_count}")
        
        return results
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the loaded model"""
        return {
            'model_name': self.model_name,
            'feature_columns': self.feature_columns,
            'label_classes': self.label_classes,
            'total_features': len(self.feature_columns),
            'total_classes': len(self.label_classes),
            'model_type': type(self.model).__name__,
            'metadata_loaded': self.metadata is not None
        }

class CppIntegrationHelper:
    """Helper class for C++ integration with Frugally-Deep"""
    
    def __init__(self, models_dir: str):
        self.models_dir = Path(models_dir)
        self.detector = RealTimeAttackDetector(models_dir)
        
        logger.info("🔧 C++ Integration Helper initialized")
    
    def export_model_for_cpp(self, output_dir: str = None):
        """Export model in format suitable for C++ integration"""
        if output_dir is None:
            output_dir = self.models_dir / "cpp_export"
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"📤 Exporting model for C++ integration to: {output_path}")
        
        # Export feature information
        feature_info = {
            'feature_columns': self.detector.feature_columns,
            'label_classes': self.detector.label_classes,
            'feature_count': len(self.detector.feature_columns),
            'class_count': len(self.detector.label_classes)
        }
        
        feature_info_path = output_path / "feature_info.json"
        with open(feature_info_path, 'w') as f:
            json.dump(feature_info, f, indent=2)
        
        # Export sample data for testing
        sample_features = np.zeros(len(self.detector.feature_columns))
        sample_data = dict(zip(self.detector.feature_columns, sample_features))
        
        sample_data_path = output_path / "sample_input.json"
        with open(sample_data_path, 'w') as f:
            json.dump(sample_data, f, indent=2)
        
        # Export expected output format
        expected_output = {
            'predicted_class': 'normal',
            'confidence': 1.0,
            'is_attack': False,
            'attack_type': 'none',
            'class_probabilities': dict(zip(self.detector.label_classes, [0.0] * len(self.detector.label_classes)))
        }
        
        expected_output_path = output_path / "expected_output.json"
        with open(expected_output_path, 'w') as f:
            json.dump(expected_output, f, indent=2)
        
        logger.info(f"✅ C++ export files created:")
        logger.info(f"   • {feature_info_path}")
        logger.info(f"   • {sample_data_path}")
        logger.info(f"   • {expected_output_path}")
        
        return output_path
    
    def generate_cpp_integration_code(self, output_dir: str = None):
        """Generate C++ integration code template"""
        if output_dir is None:
            output_dir = self.models_dir / "cpp_integration"
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate C++ header file
        cpp_header = f"""#ifndef TSN_ATTACK_DETECTOR_H
#define TSN_ATTACK_DETECTOR_H

#include <vector>
#include <string>
#include <map>

class TSNAttackDetector {{
private:
    std::vector<std::string> feature_columns_;
    std::vector<std::string> label_classes_;
    
public:
    TSNAttackDetector();
    ~TSNAttackDetector();
    
    // Initialize with model files
    bool initialize(const std::string& model_path);
    
    // Real-time detection
    struct DetectionResult {{
        std::string predicted_class;
        double confidence;
        bool is_attack;
        std::string attack_type;
        std::map<std::string, double> class_probabilities;
    }};
    
    DetectionResult detect_attack(const std::vector<double>& features);
    
    // Feature extraction helpers
    std::vector<double> extract_features(const std::map<std::string, double>& data);
    
    // Model information
    int get_feature_count() const {{ return feature_columns_.size(); }}
    int get_class_count() const {{ return label_classes_.size(); }}
    std::vector<std::string> get_feature_names() const {{ return feature_columns_; }}
    std::vector<std::string> get_class_names() const {{ return label_classes_; }}
}};

#endif // TSN_ATTACK_DETECTOR_H
"""
        
        header_path = output_path / "TSNAttackDetector.h"
        with open(header_path, 'w') as f:
            f.write(cpp_header)
        
        # Generate C++ implementation template
        cpp_impl = f"""#include "TSNAttackDetector.h"
#include <iostream>
#include <fstream>
#include <algorithm>

TSNAttackDetector::TSNAttackDetector() {{
    // Initialize with feature columns from training
    feature_columns_ = {{
{chr(10).join(f'        "{col}",' for col in self.detector.feature_columns)}
    }};
    
    // Initialize with label classes from training
    label_classes_ = {{
{chr(10).join(f'        "{cls}",' for cls in self.detector.label_classes)}
    }};
}}

TSNAttackDetector::~TSNAttackDetector() {{
    // Cleanup if needed
}}

bool TSNAttackDetector::initialize(const std::string& model_path) {{
    // TODO: Load Frugally-Deep model
    // This is where you would integrate with the actual ML model
    std::cout << "🎯 TSN Attack Detector initialized with " 
              << feature_columns_.size() << " features and "
              << label_classes_.size() << " classes" << std::endl;
    return true;
}}

TSNAttackDetector::DetectionResult TSNAttackDetector::detect_attack(
    const std::vector<double>& features) {{
    
    DetectionResult result;
    
    // TODO: Implement actual ML inference using Frugally-Deep
    // For now, return a placeholder result
    
    if (features.size() != feature_columns_.size()) {{
        result.predicted_class = "error";
        result.confidence = 0.0;
        result.is_attack = false;
        result.attack_type = "unknown";
        return result;
    }}
    
    // Placeholder logic - replace with actual ML inference
    result.predicted_class = "normal";
    result.confidence = 0.95;
    result.is_attack = false;
    result.attack_type = "none";
    
    // Initialize class probabilities
    for (const auto& cls : label_classes_) {{
        result.class_probabilities[cls] = 0.0;
    }}
    result.class_probabilities["normal"] = 0.95;
    
    return result;
}}

std::vector<double> TSNAttackDetector::extract_features(
    const std::map<std::string, double>& data) {{
    
    std::vector<double> features;
    features.reserve(feature_columns_.size());
    
    for (const auto& feature_name : feature_columns_) {{
        auto it = data.find(feature_name);
        if (it != data.end()) {{
            features.push_back(it->second);
        }} else {{
            features.push_back(0.0); // Default value
        }}
    }}
    
    return features;
}}
"""
        
        impl_path = output_path / "TSNAttackDetector.cpp"
        with open(impl_path, 'w') as f:
            f.write(cpp_impl)
        
        # Generate usage example
        usage_example = f"""#include "TSNAttackDetector.h"
#include <iostream>

int main() {{
    // Initialize detector
    TSNAttackDetector detector;
    if (!detector.initialize("path/to/model.json")) {{
        std::cerr << "Failed to initialize detector" << std::endl;
        return 1;
    }}
    
    // Example real-time data
    std::map<std::string, double> real_time_data = {{
        {{"total_packets_sent", 1000.0}},
        {{"total_packets_received", 950.0}},
        {{"total_packets_dropped", 50.0}},
        {{"packet_loss_rate", 0.05}},
        {{"max_queue_length", 10.0}},
        {{"avg_queue_length", 5.0}},
        {{"avg_queueing_time", 0.001}},
        {{"max_end_to_end_delay", 0.01}}
    }};
    
    // Extract features
    auto features = detector.extract_features(real_time_data);
    
    // Detect attack
    auto result = detector.detect_attack(features);
    
    // Print results
    std::cout << "🎯 Attack Detection Results:" << std::endl;
    std::cout << "Predicted class: " << result.predicted_class << std::endl;
    std::cout << "Confidence: " << result.confidence << std::endl;
    std::cout << "Is attack: " << (result.is_attack ? "YES" : "NO") << std::endl;
    std::cout << "Attack type: " << result.attack_type << std::endl;
    
    return 0;
}}
"""
        
        example_path = output_path / "example_usage.cpp"
        with open(example_path, 'w') as f:
            f.write(usage_example)
        
        logger.info(f"✅ C++ integration files created:")
        logger.info(f"   • {header_path}")
        logger.info(f"   • {impl_path}")
        logger.info(f"   • {example_path}")
        
        return output_path

def main():
    """Main execution function for testing real-time inference"""
    print("🚀 TSN/PSFP Attack Detection - Real-time Inference Testing")
    print("="*60)
    
    # Paths
    current_dir = Path(__file__).parent
    models_dir = current_dir.parent / "ml_models" / "trained_models"
    
    try:
        # Initialize detector
        detector = RealTimeAttackDetector(models_dir)
        
        # Test with sample data
        sample_data = {
            'total_packets_sent': 1000.0,
            'total_packets_received': 950.0,
            'total_packets_dropped': 50.0,
            'packet_loss_rate': 0.05,
            'max_queue_length': 10.0,
            'avg_queue_length': 5.0,
            'avg_queueing_time': 0.001,
            'max_end_to_end_delay': 0.01
        }
        
        print("\n🧪 Testing real-time detection...")
        result = detector.process_real_time_data(sample_data)
        
        print(f"📊 Detection Result:")
        print(f"   Predicted class: {result['predicted_class']}")
        print(f"   Confidence: {result['confidence']:.3f}")
        print(f"   Is attack: {result['is_attack']}")
        print(f"   Attack type: {result['attack_type']}")
        
        # Test C++ integration helper
        print("\n🔧 Testing C++ integration helper...")
        cpp_helper = CppIntegrationHelper(models_dir)
        
        # Export for C++
        cpp_export_dir = cpp_helper.export_model_for_cpp()
        print(f"📤 C++ export created in: {cpp_export_dir}")
        
        # Generate C++ integration code
        cpp_integration_dir = cpp_helper.generate_cpp_integration_code()
        print(f"📝 C++ integration code created in: {cpp_integration_dir}")
        
        print("\n✅ Real-time inference testing completed successfully!")
        
    except Exception as e:
        logger.error(f"❌ Testing failed: {str(e)}")
        raise

if __name__ == "__main__":
    main() 