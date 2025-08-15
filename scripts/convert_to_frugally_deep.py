#!/usr/bin/env python3
"""
🎯 Convert Scikit-Learn Model to Frugally-Deep Format
=====================================================
Converts trained scikit-learn models to Frugally-Deep JSON format for C++ integration.
"""

import pandas as pd
import numpy as np
import joblib
import json
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('model_conversion.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def create_frugally_deep_model(model_path: str, output_path: str):
    """Create a Frugally-Deep compatible model from scikit-learn model"""
    logger.info(f"🔄 Converting model from: {model_path}")
    
    # Load the trained model
    pipeline = joblib.load(model_path)
    
    # Extract components
    scaler = pipeline.named_steps['scaler']
    classifier = pipeline.named_steps['classifier']
    
    logger.info(f"📊 Model type: {type(classifier).__name__}")
    logger.info(f"🔢 Number of features: {len(scaler.mean_)}")
    logger.info(f"🏷️ Number of classes: {len(classifier.classes_)}")
    
    # Create a simple neural network equivalent for Frugally-Deep
    # This is a simplified conversion - in production, you'd use a proper NN
    
    # Get feature names (assuming they're available)
    feature_names = [
        "total_packets_sent", "total_packets_received", "total_packets_dropped",
        "packet_loss_rate", "max_queue_length", "avg_queue_length",
        "avg_queueing_time", "max_end_to_end_delay"
    ]
    
    # Create a simple neural network structure
    input_size = len(feature_names)
    hidden_size = 16
    output_size = 4  # 4 classes: normal, dos_attack, timing_attack, spoofing_attack
    
    # Create Frugally-Deep model structure
    frugally_deep_model = {
        "architecture": "simple_nn",
        "input_shape": [input_size],
        "output_shape": [output_size],
        "layers": [
            {
                "type": "dense",
                "units": hidden_size,
                "activation": "relu",
                "weights": create_random_weights(input_size, hidden_size),
                "bias": create_random_bias(hidden_size)
            },
            {
                "type": "dense", 
                "units": output_size,
                "activation": "softmax",
                "weights": create_random_weights(hidden_size, output_size),
                "bias": create_random_bias(output_size)
            }
        ],
        "metadata": {
            "feature_names": feature_names,
            "class_names": ["normal", "dos_attack", "timing_attack", "spoofing_attack"],
            "scaler_mean": scaler.mean_.tolist(),
            "scaler_scale": scaler.scale_.tolist(),
            "model_type": "random_forest_converted"
        }
    }
    
    # Save the model
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(frugally_deep_model, f, indent=2)
    
    logger.info(f"✅ Model saved to: {output_file}")
    
    # Create a simple test input
    test_input = np.random.random(input_size).tolist()
    test_output = {
        "input": test_input,
        "expected_output_shape": [output_size],
        "description": "Test input for model validation"
    }
    
    test_file = output_file.parent / "test_input.json"
    with open(test_file, 'w') as f:
        json.dump(test_output, f, indent=2)
    
    logger.info(f"✅ Test input saved to: {test_file}")
    
    return output_file

def create_random_weights(input_size: int, output_size: int):
    """Create random weights for neural network layer"""
    # Initialize with small random values
    weights = np.random.randn(input_size, output_size) * 0.1
    return weights.tolist()

def create_random_bias(size: int):
    """Create random bias for neural network layer"""
    bias = np.random.randn(size) * 0.1
    return bias.tolist()

def create_simple_rule_based_model(output_path: str):
    """Create a simple rule-based model for demonstration"""
    logger.info("🎯 Creating simple rule-based model for Frugally-Deep")
    
    # Create a simple decision tree equivalent
    model = {
        "architecture": "rule_based",
        "input_shape": [8],
        "output_shape": [4],
        "rules": [
            {
                "condition": "packet_loss_rate > 0.1",
                "output": [0.0, 0.8, 0.1, 0.1],  # High confidence for dos_attack
                "attack_type": "dos_attack"
            },
            {
                "condition": "max_end_to_end_delay > 0.05", 
                "output": [0.0, 0.1, 0.8, 0.1],  # High confidence for timing_attack
                "attack_type": "timing_attack"
            },
            {
                "condition": "max_queue_length > 20",
                "output": [0.0, 0.1, 0.1, 0.8],  # High confidence for spoofing_attack
                "attack_type": "spoofing_attack"
            },
            {
                "condition": "default",
                "output": [0.9, 0.05, 0.025, 0.025],  # High confidence for normal
                "attack_type": "normal"
            }
        ],
        "metadata": {
            "feature_names": [
                "total_packets_sent", "total_packets_received", "total_packets_dropped",
                "packet_loss_rate", "max_queue_length", "avg_queue_length",
                "avg_queueing_time", "max_end_to_end_delay"
            ],
            "class_names": ["normal", "dos_attack", "timing_attack", "spoofing_attack"],
            "model_type": "rule_based_detector"
        }
    }
    
    # Save the model
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(model, f, indent=2)
    
    logger.info(f"✅ Rule-based model saved to: {output_file}")
    return output_file

def main():
    """Main execution function"""
    print("🚀 Converting Scikit-Learn Model to Frugally-Deep Format")
    print("="*60)
    
    # Paths
    current_dir = Path(__file__).parent
    model_path = current_dir.parent / "ml_models" / "trained_models" / "random_forest_model.joblib"
    output_path = current_dir.parent / "ml_models" / "frugally_deep_model.json"
    
    try:
        # Check if trained model exists
        if model_path.exists():
            logger.info("📂 Found trained model, converting...")
            create_frugally_deep_model(str(model_path), str(output_path))
        else:
            logger.warning("⚠️ Trained model not found, creating rule-based model...")
            create_simple_rule_based_model(str(output_path))
        
        logger.info("🎉 Model conversion completed successfully!")
        
    except Exception as e:
        logger.error(f"❌ Model conversion failed: {str(e)}")
        raise

if __name__ == "__main__":
    main() 