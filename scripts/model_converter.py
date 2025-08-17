#!/usr/bin/env python3
"""
Keras to Frugally-Deep Model Converter
=====================================

This utility script converts Keras models to frugally-deep JSON format
for use in C++ applications. It also saves the scaler parameters for
feature normalization.

Usage:
  python model_converter.py --model path/to/model.h5 --scaler path/to/scaler.pkl --output path/to/output/directory
"""

import os
import sys
import argparse
import json
import numpy as np
import tensorflow as tf
from tensorflow import keras
from pathlib import Path
import pickle
import subprocess

def find_frugally_deep_converter():
    """Find the frugally-deep conversion script"""
    # Try common locations
    possible_paths = [
        Path('../../frugally-deep/keras_export/convert_model.py'),
        Path('../../../frugally-deep/keras_export/convert_model.py'),
        Path('/home/eriloo/omnetpp-ml-workspace/frugally-deep/keras_export/convert_model.py')
    ]
    
    for path in possible_paths:
        if path.exists():
            return path
    
    return None

def convert_model(model_path, output_dir, scaler_path=None):
    """
    Convert a Keras model to frugally-deep format and save scaler parameters
    
    Args:
        model_path: Path to the Keras model (.h5)
        output_dir: Directory to save the converted model and scaler
        scaler_path: Optional path to a scikit-learn scaler (.pkl)
    
    Returns:
        bool: True if conversion was successful
    """
    # Ensure output directory exists
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Load the model to verify it's valid
    try:
        model = keras.models.load_model(model_path)
        print(f"Loaded model: {model_path}")
        print(f"Model summary:")
        model.summary()
    except Exception as e:
        print(f"Error loading model: {e}")
        return False
    
    # Find the frugally-deep conversion script
    convert_script = find_frugally_deep_converter()
    if not convert_script:
        print("Error: Could not find frugally-deep conversion script")
        return False
    
    # Convert to frugally-deep format
    output_path = output_dir / 'tsn_model.json'
    cmd = [sys.executable, str(convert_script), str(model_path), str(output_path)]
    
    try:
        print(f"Converting model to frugally-deep format...")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"Model successfully exported to {output_path}")
        else:
            print(f"Error converting model: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error during conversion: {e}")
        return False
    
    # Handle scaler if provided
    if scaler_path:
        try:
            with open(scaler_path, 'rb') as f:
                scaler = pickle.load(f)
            
            # Extract scaler parameters
            scaler_params = {
                'mean': scaler.mean_.tolist(),
                'std': scaler.scale_.tolist()
            }
            
            # Save as JSON
            scaler_json_path = output_dir / 'tsn_scaler.json'
            with open(scaler_json_path, 'w') as f:
                json.dump(scaler_params, f, indent=2)
            
            print(f"Scaler parameters saved to {scaler_json_path}")
        except Exception as e:
            print(f"Error processing scaler: {e}")
            print("Continuing without scaler parameters...")
    
    return True

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Convert Keras model to frugally-deep format')
    parser.add_argument('--model', required=True, help='Path to Keras model (.h5)')
    parser.add_argument('--output', default='../ml_models/trained_models', help='Output directory')
    parser.add_argument('--scaler', help='Path to scikit-learn scaler (.pkl)')
    
    args = parser.parse_args()
    
    success = convert_model(args.model, args.output, args.scaler)
    
    if success:
        print("\n✅ Conversion complete!")
        print(f"Model and scaler saved to {args.output}")
    else:
        print("\n❌ Conversion failed.")
        sys.exit(1)

if __name__ == "__main__":
    main() 