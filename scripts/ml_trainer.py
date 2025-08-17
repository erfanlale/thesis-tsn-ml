#!/usr/bin/env python3
"""
Smart ML Trainer for TSN Attack Detection
==========================================

This script intelligently samples from huge CSV files and creates trainable
features without loading all 100M+ rows into memory.

Key Features:
- Intelligent data sampling (not all 100M rows!)
- Memory-efficient chunk processing  
- Statistical feature engineering
- Sliding window attack detection

Author: AI Assistant
Date: 2025-07-23
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
from pathlib import Path
import argparse
import psutil
import gc
import time
from collections import defaultdict

# Attack timing windows from omnetpp.ini configurations
ATTACK_WINDOWS = {
    'Baseline': [],  # No attacks
    'General': [],   # No attacks
    'DoSFlooding': [
        {'start': 1.0, 'end': 2.0, 'type': 'dos_flooding'}
    ],
    'SpoofingAttack': [
        {'start': 0.5, 'end': 1.5, 'type': 'spoofing'}
    ],
    'MixedAttacks': [
        {'start': 0.5, 'end': 2.0, 'type': 'spoofing'},
        {'start': 1.0, 'end': 2.5, 'type': 'dos_flooding'},
        {'start': 1.5, 'end': 2.5, 'type': 'timing_disruption'}
    ],
    'TimingAttack': [
        {'start': 0.1, 'end': 3.0, 'type': 'timing_attack'}
    ]
}

class SmartMLTrainer:
    def __init__(self, data_dir, output_dir="ml_models", sample_rate=0.01, max_memory_gb=8):
        """
        Initialize Smart ML Trainer
        
        Args:
            data_dir: Directory with CSV files
            output_dir: Where to save models
            sample_rate: Fraction of data to sample (0.01 = 1%)
            max_memory_gb: Maximum memory to use
        """
        self.data_dir = Path(data_dir)
        self.output_dir = Path(output_dir)
        self.sample_rate = sample_rate
        self.max_memory_bytes = max_memory_gb * 1024**3
        self.output_dir.mkdir(exist_ok=True)
        
        print(f"🧠 SMART ML TRAINER INITIALIZED")
        print(f"📂 Data: {data_dir}")
        print(f"📊 Sample rate: {sample_rate*100:.1f}% (to keep memory manageable)")
        print(f"💾 Max memory: {max_memory_gb}GB")
        
    def get_memory_usage(self):
        """Get current memory usage in MB"""
        process = psutil.Process()
        return process.memory_info().rss / 1024**2
        
    def smart_sample_csv(self, csv_file, sample_rate):
        """
        Intelligently sample from huge CSV file without loading all data
        """
        print(f"📁 Processing {csv_file.name} (sample rate: {sample_rate*100:.1f}%)")
        
        # Count lines first
        with open(csv_file, 'r') as f:
            total_lines = sum(1 for _ in f) - 1  # Exclude header
            
        # Calculate step size for sampling
        step_size = max(1, int(1 / sample_rate))
        
        print(f"   📊 Total lines: {total_lines:,} → Sampling every {step_size} rows")
        
        # Read header
        header = pd.read_csv(csv_file, nrows=0).columns
        
        # Sample data in chunks
        sampled_data = []
        chunk_size = 50000
        
        for chunk_num, chunk in enumerate(pd.read_csv(csv_file, chunksize=chunk_size, skiprows=lambda x: x > 0 and x % step_size != 1)):
            sampled_data.append(chunk)
            
            # Memory check
            if self.get_memory_usage() > self.max_memory_bytes / 1024**2:
                print(f"   ⚠️  Memory limit reached, stopping at chunk {chunk_num}")
                break
                
            if chunk_num % 10 == 0:
                print(f"   📈 Processed {(chunk_num+1)*chunk_size:,} lines, Memory: {self.get_memory_usage():.1f}MB")
        
        if sampled_data:
            result = pd.concat(sampled_data, ignore_index=True)
            print(f"   ✅ Sampled {len(result):,} rows from {csv_file.name}")
            return result
        else:
            print(f"   ❌ No data sampled from {csv_file.name}")
            return pd.DataFrame()
    
    def create_temporal_labels(self, df):
        """Create attack/normal labels based on timing windows"""
        df['label'] = 'normal'
        df['attack_type'] = 'none'
        
        for _, row in df.iterrows():
            scenario = row['scenario']
            sim_time = row['sim_time']
            
            if scenario in ATTACK_WINDOWS:
                for attack in ATTACK_WINDOWS[scenario]:
                    if attack['start'] <= sim_time <= attack['end']:
                        df.loc[df.index == row.name, 'label'] = 'attack'
                        df.loc[df.index == row.name, 'attack_type'] = attack['type']
                        break
        
        return df
    
    def engineer_features(self, df):
        """Create ML features from time-series data"""
        print("🔧 Engineering features...")
        
        # Group by scenario and node for time-series features
        features = []
        
        for (scenario, node), group in df.groupby(['scenario', 'node_name']):
            if len(group) < 10:  # Skip tiny groups
                continue
                
            # Sort by time
            group = group.sort_values('sim_time')
            
            # Time windows (0.1s windows)
            time_windows = np.arange(0, group['sim_time'].max() + 0.1, 0.1)
            
            for window_start in time_windows:
                window_end = window_start + 0.1
                window_data = group[(group['sim_time'] >= window_start) & 
                                   (group['sim_time'] < window_end)]
                
                if len(window_data) == 0:
                    continue
                
                # Statistical features for this time window
                feature_row = {
                    'scenario': scenario,
                    'node_name': node,
                    'time_window': window_start,
                    'value_mean': window_data['value'].mean(),
                    'value_std': window_data['value'].std(),
                    'value_min': window_data['value'].min(),
                    'value_max': window_data['value'].max(),
                    'value_count': len(window_data),
                    'value_range': window_data['value'].max() - window_data['value'].min(),
                    'label': window_data['label'].mode()[0] if len(window_data['label'].mode()) > 0 else 'normal'
                }
                
                features.append(feature_row)
        
        feature_df = pd.DataFrame(features)
        print(f"   ✅ Created {len(feature_df):,} feature windows")
        return feature_df
    
    def train_model(self, features_df):
        """Train the ML model"""
        print("🎯 Training model...")
        
        # Prepare features and labels
        feature_cols = ['value_mean', 'value_std', 'value_min', 'value_max', 
                       'value_count', 'value_range']
        
        X = features_df[feature_cols].fillna(0)
        y = features_df['label']
        
        print(f"   📊 Features shape: {X.shape}")
        print(f"   🎯 Label distribution: {y.value_counts()}")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train model
        model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"   ✅ Model trained! Accuracy: {accuracy:.3f}")
        print("\n📊 Classification Report:")
        print(classification_report(y_test, y_pred))
        
        # Save model and scaler
        model_file = self.output_dir / f"tsn_attack_model_{time.strftime('%Y%m%d_%H%M%S')}.joblib"
        scaler_file = self.output_dir / f"tsn_scaler_{time.strftime('%Y%m%d_%H%M%S')}.joblib"
        
        joblib.dump(model, model_file)
        joblib.dump(scaler, scaler_file)
        
        print(f"   💾 Model saved: {model_file}")
        print(f"   💾 Scaler saved: {scaler_file}")
        
        return model, scaler, accuracy

    def run_training(self):
        """Main training pipeline"""
        print("🚀 STARTING SMART ML TRAINING\n")
        
        # Find CSV files
        csv_files = list(self.data_dir.glob("*_FINAL_*.csv"))
        if not csv_files:
            print("❌ No CSV files found!")
            return
            
        print(f"📁 Found {len(csv_files)} CSV files:")
        for f in csv_files:
            size_mb = f.stat().st_size / 1024**2
            print(f"   - {f.name} ({size_mb:.1f}MB)")
        
        # Process each CSV file
        all_data = []
        
        for csv_file in csv_files:
            # Skip if too big, focus on smaller ones first
            size_gb = csv_file.stat().st_size / 1024**3
            if size_gb > 2.0:  # Skip files bigger than 2GB for now
                print(f"⏭️  Skipping {csv_file.name} (too large: {size_gb:.1f}GB)")
                continue
                
            # Sample data
            sampled_df = self.smart_sample_csv(csv_file, self.sample_rate)
            if not sampled_df.empty:
                # Add labels
                labeled_df = self.create_temporal_labels(sampled_df)
                all_data.append(labeled_df)
                
            # Memory cleanup
            gc.collect()
        
        if not all_data:
            print("❌ No data processed successfully!")
            return
            
        # Combine all data
        print(f"\n📊 Combining {len(all_data)} datasets...")
        combined_df = pd.concat(all_data, ignore_index=True)
        print(f"   ✅ Combined dataset: {len(combined_df):,} rows")
        
        # Engineer features
        features_df = self.engineer_features(combined_df)
        
        # Train model
        model, scaler, accuracy = self.train_model(features_df)
        
        print(f"\n🎉 TRAINING COMPLETED!")
        print(f"   🎯 Final Accuracy: {accuracy:.3f}")
        print(f"   📁 Models saved in: {self.output_dir}")

def main():
    parser = argparse.ArgumentParser(description='Smart ML Trainer for TSN Attack Detection')
    parser.add_argument('--data', required=True, help='Directory with CSV files')
    parser.add_argument('--output', default='ml_models', help='Output directory for models')
    parser.add_argument('--sample-rate', type=float, default=0.01, help='Data sampling rate (0.01 = 1%)')
    parser.add_argument('--max-memory', type=int, default=8, help='Max memory usage in GB')
    
    args = parser.parse_args()
    
    trainer = SmartMLTrainer(
        data_dir=args.data,
        output_dir=args.output,
        sample_rate=args.sample_rate,
        max_memory_gb=args.max_memory
    )
    
    trainer.run_training()

if __name__ == "__main__":
    main() 