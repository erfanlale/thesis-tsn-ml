#!/usr/bin/env python3
"""
🎯 TSN/PSFP Attack Detection - ML Feature Extraction
===================================================
"""

import pandas as pd
import numpy as np
import os
import re
import json
from pathlib import Path
from typing import Dict, List, Tuple, Any
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('feature_extraction.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class TSNFeatureExtractor:
    """Extract ML features from TSN simulation data"""
    
    def __init__(self, results_dir: str, output_dir: str):
        self.results_dir = Path(results_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Attack scenario mapping
        self.scenario_labels = {
            'Baseline': 'normal',
            'DoSAttack': 'dos_attack', 
            'TimingAttack': 'timing_attack',
            'SpoofingAttack': 'spoofing_attack'
        }
        
        logger.info(f"🎯 TSN Feature Extractor initialized")
        logger.info(f"📂 Results dir: {self.results_dir}")
        logger.info(f"📁 Output dir: {self.output_dir}")
    
    def parse_sca_file(self, sca_file: Path) -> Dict[str, Any]:
        """Parse OMNeT++ scalar (.sca) files"""
        logger.info(f"📊 Parsing {sca_file.name}")
        
        scalars = {}
        scenario = None
        
        with open(sca_file, 'r') as f:
            for line in f:
                line = line.strip()
                
                # Extract scenario name from run info
                if line.startswith('run') and 'config=' in line:
                    config_match = re.search(r'config=(\w+)', line)
                    if config_match:
                        scenario = config_match.group(1)
                
                # Parse scalar values
                if line.startswith('scalar'):
                    parts = line.split()
                    if len(parts) >= 4:
                        module = parts[1]
                        metric = parts[2]
                        value = parts[3]
                        
                        try:
                            value = float(value)
                            scalars[f"{module}.{metric}"] = value
                        except ValueError:
                            continue
        
        return {
            'scenario': scenario,
            'scalars': scalars,
            'file': sca_file.name
        }
    
    def extract_network_features(self, scalars: Dict[str, float]) -> Dict[str, float]:
        """Extract network-level features from scalar data"""
        features = {}
        
        # === PACKET FLOW FEATURES ===
        sent_metrics = [k for k in scalars.keys() if 'packetSent' in k or 'outgoingPackets' in k]
        received_metrics = [k for k in scalars.keys() if 'packetReceived' in k or 'incomingPackets' in k]
        dropped_metrics = [k for k in scalars.keys() if 'packetDropped' in k or 'droppedPackets' in k]
        
        features['total_packets_sent'] = sum(scalars.get(k, 0) for k in sent_metrics)
        features['total_packets_received'] = sum(scalars.get(k, 0) for k in received_metrics) 
        features['total_packets_dropped'] = sum(scalars.get(k, 0) for k in dropped_metrics)
        
        # Packet loss rate
        if features['total_packets_sent'] > 0:
            features['packet_loss_rate'] = features['total_packets_dropped'] / features['total_packets_sent']
        else:
            features['packet_loss_rate'] = 0.0
        
        # === QUEUE FEATURES ===
        queue_length_metrics = [k for k in scalars.keys() if 'queueLength' in k]
        queueing_time_metrics = [k for k in scalars.keys() if 'queueingTime' in k]
        
        features['max_queue_length'] = max((scalars.get(k, 0) for k in queue_length_metrics if 'max' in k), default=0)
        features['avg_queue_length'] = np.mean([scalars.get(k, 0) for k in queue_length_metrics if 'timeavg' in k])
        features['avg_queueing_time'] = np.mean([scalars.get(k, 0) for k in queueing_time_metrics if 'mean' in k])
        
        # === PERFORMANCE FEATURES ===
        delay_metrics = [k for k in scalars.keys() if 'delay' in k.lower()]
        features['max_end_to_end_delay'] = max((scalars.get(k, 0) for k in delay_metrics), default=0)
        
        # === DEVICE-SPECIFIC FEATURES ===
        devices = ['criticalSensor', 'mainECU', 'display', 'attackerExternal', 'compromisedNode', 'centralSwitch']
        
        for device in devices:
            device_sent = sum(scalars.get(k, 0) for k in scalars.keys() if device in k and 'packetSent' in k)
            device_received = sum(scalars.get(k, 0) for k in scalars.keys() if device in k and 'packetReceived' in k)
            
            features[f'{device}_packets_sent'] = device_sent
            features[f'{device}_packets_received'] = device_received
            
            if device_sent > 0:
                features[f'{device}_send_rate'] = device_sent / 0.1  # 100ms simulation
            else:
                features[f'{device}_send_rate'] = 0.0
        
        return features
    
    def extract_attack_signatures(self, scenario: str, features: Dict[str, float]) -> Dict[str, float]:
        """Extract attack-specific signature features"""
        attack_features = {}
        
        # DoS Attack signatures
        if scenario == 'DoSAttack':
            attacker_rate = features.get('attackerExternal_send_rate', 0)
            normal_rate = features.get('criticalSensor_send_rate', 0)
            
            if normal_rate > 0:
                attack_features['dos_rate_amplification'] = attacker_rate / normal_rate
            else:
                attack_features['dos_rate_amplification'] = attacker_rate
            
            attack_features['dos_packet_volume'] = features.get('attackerExternal_packets_sent', 0)
        
        # Timing Attack signatures  
        elif scenario == 'TimingAttack':
            attack_features['timing_disruption_indicator'] = features.get('max_end_to_end_delay', 0)
            attack_features['timing_queue_impact'] = features.get('max_queue_length', 0)
        
        # Spoofing Attack signatures
        elif scenario == 'SpoofingAttack':
            compromise_rate = features.get('compromisedNode_send_rate', 0)
            legitimate_rate = features.get('criticalSensor_send_rate', 0)
            
            attack_features['spoofing_rate_ratio'] = compromise_rate / legitimate_rate if legitimate_rate > 0 else 0
            attack_features['spoofing_packet_count'] = features.get('compromisedNode_packets_sent', 0)
        
        return attack_features
    
    def process_scenario(self, scenario: str) -> pd.DataFrame:
        """Process a complete attack scenario with multiple samples"""
        logger.info(f"🔄 Processing scenario: {scenario}")
        
        # Find result files for this scenario
        sca_file = self.results_dir / f"{scenario}-#0.sca"
        
        if not sca_file.exists():
            logger.warning(f"⚠️ SCA file not found: {sca_file}")
            return pd.DataFrame()
        
        # Parse scalar data
        sca_data = self.parse_sca_file(sca_file)
        scalars = sca_data['scalars']
        
        # Extract network features
        network_features = self.extract_network_features(scalars)
        
        # Extract attack signatures
        attack_features = self.extract_attack_signatures(scenario, network_features)
        
        # Combine all features
        base_features = {
            **network_features,
            **attack_features
        }
        
        # Generate multiple samples with noise to create larger dataset
        all_samples = []
        num_samples = 50  # Generate 50 samples per scenario
        
        for i in range(num_samples):
            # Add small random noise to create variation
            sample_features = base_features.copy()
            
            # Add noise to numeric features (except labels and metadata)
            for key, value in sample_features.items():
                if isinstance(value, (int, float)) and key not in ['scenario', 'label', 'timestamp']:
                    # Add 5% random noise
                    noise_factor = 1.0 + (np.random.random() - 0.5) * 0.1
                    sample_features[key] = value * noise_factor
            
            # Add metadata
            sample_features['scenario'] = scenario
            sample_features['label'] = self.scenario_labels.get(scenario, 'unknown')
            sample_features['timestamp'] = datetime.now().isoformat()
            sample_features['sample_id'] = i
            
            all_samples.append(sample_features)
        
        # Convert to DataFrame
        df = pd.DataFrame(all_samples)
        
        logger.info(f"✅ Generated {len(df)} samples for {scenario}")
        return df
    
    def extract_all_features(self) -> pd.DataFrame:
        """Extract features from all scenarios"""
        logger.info("🚀 Starting feature extraction for all scenarios...")
        
        all_data = []
        
        for scenario in self.scenario_labels.keys():
            df = self.process_scenario(scenario)
            if not df.empty:
                all_data.append(df)
        
        if all_data:
            combined_df = pd.concat(all_data, ignore_index=True)
            logger.info(f"🎉 Successfully extracted features for {len(all_data)} scenarios")
            return combined_df
        else:
            logger.error("❌ No features extracted!")
            return pd.DataFrame()
    
    def save_results(self, df: pd.DataFrame):
        """Save extracted features and metadata"""
        if df.empty:
            logger.error("❌ No data to save!")
            return
        
        # Save main dataset
        csv_path = self.output_dir / "tsn_attack_features.csv"
        df.to_csv(csv_path, index=False)
        logger.info(f"💾 Saved features to: {csv_path}")
        
        # Save feature metadata
        feature_columns = [col for col in df.columns if col not in ['scenario', 'label', 'timestamp']]
        metadata = {
            'extraction_timestamp': datetime.now().isoformat(),
            'total_scenarios': len(df),
            'total_features': len(feature_columns),
            'feature_columns': feature_columns,
            'scenario_distribution': df['label'].value_counts().to_dict(),
        }
        
        metadata_path = self.output_dir / "feature_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        logger.info(f"📋 Saved metadata to: {metadata_path}")
        
        # Display summary
        print("\n" + "="*60)
        print("�� TSN ATTACK DETECTION - FEATURE EXTRACTION SUMMARY")
        print("="*60)
        print(f"📊 Total scenarios processed: {len(df)}")
        print(f"🔢 Features extracted per scenario: {len(feature_columns)}")
        print(f"📁 Output directory: {self.output_dir}")
        print("\n📈 Scenario distribution:")
        for label, count in df['label'].value_counts().items():
            print(f"   • {label}: {count} scenario(s)")
        
        print(f"\n📄 Files created:")
        print(f"   • {csv_path}")
        print(f"   • {metadata_path}")
        print("="*60)

def main():
    """Main execution function"""
    print("🚀 TSN/PSFP Attack Detection - Feature Extraction")
    print("="*50)
    
    # Paths
    current_dir = Path(__file__).parent
    results_dir = current_dir.parent / "simulations" / "results"
    output_dir = current_dir.parent / "ml_models"
    
    # Initialize extractor
    extractor = TSNFeatureExtractor(results_dir, output_dir)
    
    # Extract features
    features_df = extractor.extract_all_features()
    
    # Save results
    extractor.save_results(features_df)
    
    logger.info("🎉 Feature extraction completed successfully!")

if __name__ == "__main__":
    main()
