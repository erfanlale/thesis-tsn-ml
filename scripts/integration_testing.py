#!/usr/bin/env python3
"""
🎯 TSN/PSFP Attack Detection - Integration Testing
==================================================
Comprehensive testing of the entire ML pipeline
"""

import pandas as pd
import numpy as np
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Any
import joblib
from sklearn.metrics import accuracy_score, classification_report

# Import our modules
from real_time_inference import RealTimeAttackDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('integration_testing.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class IntegrationTester:
    """Comprehensive integration testing for TSN Attack Detection"""
    
    def __init__(self, project_dir: str):
        self.project_dir = Path(project_dir)
        self.results = {}
        
        # Define paths
        self.data_path = self.project_dir / "ml_models" / "tsn_attack_features.csv"
        self.models_dir = self.project_dir / "ml_models" / "trained_models"
        self.simulations_dir = self.project_dir / "simulations"
        
        logger.info(f"🎯 Integration Tester initialized")
        logger.info(f"📁 Project directory: {project_dir}")
    
    def test_data_integrity(self) -> Dict[str, Any]:
        """Test data integrity and quality"""
        logger.info("🔍 Testing data integrity...")
        
        results = {
            'test_name': 'data_integrity',
            'passed': False,
            'details': {}
        }
        
        try:
            # Check if data file exists
            if not self.data_path.exists():
                raise FileNotFoundError(f"Data file not found: {self.data_path}")
            
            # Load data
            df = pd.read_csv(self.data_path)
            results['details']['total_samples'] = len(df)
            results['details']['total_features'] = len(df.columns)
            
            # Check for required columns
            required_columns = ['scenario', 'label', 'timestamp']
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                raise ValueError(f"Missing required columns: {missing_columns}")
            
            # Check for missing values
            missing_values = df.isnull().sum()
            results['details']['missing_values'] = missing_values.to_dict()
            
            # Check class distribution
            class_distribution = df['label'].value_counts().to_dict()
            results['details']['class_distribution'] = class_distribution
            
            # Check feature statistics
            numeric_columns = df.select_dtypes(include=[np.number]).columns
            feature_stats = df[numeric_columns].describe()
            results['details']['feature_statistics'] = feature_stats.to_dict()
            
            results['passed'] = True
            logger.info("✅ Data integrity test passed")
            
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"❌ Data integrity test failed: {str(e)}")
        
        return results
    
    def test_model_loading(self) -> Dict[str, Any]:
        """Test model loading and validation"""
        logger.info("🤖 Testing model loading...")
        
        results = {
            'test_name': 'model_loading',
            'passed': False,
            'details': {}
        }
        
        try:
            # Check if models directory exists
            if not self.models_dir.exists():
                raise FileNotFoundError(f"Models directory not found: {self.models_dir}")
            
            # Check for required model files
            required_models = ['random_forest_model.joblib', 'model_metadata.json']
            missing_models = []
            
            for model_file in required_models:
                model_path = self.models_dir / model_file
                if not model_path.exists():
                    missing_models.append(model_file)
            
            if missing_models:
                raise FileNotFoundError(f"Missing model files: {missing_models}")
            
            # Load model and metadata
            model_path = self.models_dir / "random_forest_model.joblib"
            metadata_path = self.models_dir / "model_metadata.json"
            
            model = joblib.load(model_path)
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            results['details']['model_type'] = type(model).__name__
            results['details']['feature_count'] = metadata.get('feature_columns', [])
            results['details']['class_count'] = metadata.get('label_classes', [])
            
            results['passed'] = True
            logger.info("✅ Model loading test passed")
            
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"❌ Model loading test failed: {str(e)}")
        
        return results
    
    def test_real_time_inference(self) -> Dict[str, Any]:
        """Test real-time inference capabilities"""
        logger.info("⚡ Testing real-time inference...")
        
        results = {
            'test_name': 'real_time_inference',
            'passed': False,
            'details': {}
        }
        
        try:
            # Initialize detector
            detector = RealTimeAttackDetector(str(self.models_dir))
            
            # Test with sample data from each scenario
            test_scenarios = {
                'normal': {
                    'total_packets_sent': 1000.0,
                    'total_packets_received': 950.0,
                    'total_packets_dropped': 50.0,
                    'packet_loss_rate': 0.05,
                    'max_queue_length': 10.0,
                    'avg_queue_length': 5.0,
                    'avg_queueing_time': 0.001,
                    'max_end_to_end_delay': 0.01
                },
                'dos_attack': {
                    'total_packets_sent': 100000.0,
                    'total_packets_received': 50000.0,
                    'total_packets_dropped': 50000.0,
                    'packet_loss_rate': 0.5,
                    'max_queue_length': 1000.0,
                    'avg_queue_length': 500.0,
                    'avg_queueing_time': 0.1,
                    'max_end_to_end_delay': 1.0
                },
                'timing_attack': {
                    'total_packets_sent': 5000.0,
                    'total_packets_received': 4000.0,
                    'total_packets_dropped': 1000.0,
                    'packet_loss_rate': 0.2,
                    'max_queue_length': 100.0,
                    'avg_queue_length': 50.0,
                    'avg_queueing_time': 0.05,
                    'max_end_to_end_delay': 0.5
                }
            }
            
            inference_results = {}
            
            for scenario_name, test_data in test_scenarios.items():
                result = detector.process_real_time_data(test_data)
                inference_results[scenario_name] = {
                    'predicted_class': result['predicted_class'],
                    'confidence': result['confidence'],
                    'is_attack': result['is_attack'],
                    'attack_type': result['attack_type']
                }
            
            results['details']['inference_results'] = inference_results
            
            # Check if inference is working
            all_predictions = [r['predicted_class'] for r in inference_results.values()]
            if len(set(all_predictions)) > 1:  # Different predictions for different scenarios
                results['passed'] = True
                logger.info("✅ Real-time inference test passed")
            else:
                raise ValueError("All scenarios predicted same class - model may not be working correctly")
            
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"❌ Real-time inference test failed: {str(e)}")
        
        return results
    
    def test_model_performance(self) -> Dict[str, Any]:
        """Test model performance on training data"""
        logger.info("📊 Testing model performance...")
        
        results = {
            'test_name': 'model_performance',
            'passed': False,
            'details': {}
        }
        
        try:
            # Load data and model
            df = pd.read_csv(self.data_path)
            detector = RealTimeAttackDetector(str(self.models_dir))
            
            # Prepare test data
            exclude_columns = ['scenario', 'label', 'timestamp']
            feature_columns = [col for col in df.columns if col not in exclude_columns]
            
            predictions = []
            actual_labels = []
            
            # Test each sample
            for idx, row in df.iterrows():
                # Prepare feature data
                feature_data = {}
                for col in feature_columns:
                    if pd.notna(row[col]):
                        feature_data[col] = float(row[col])
                    else:
                        feature_data[col] = 0.0
                
                # Get prediction
                result = detector.process_real_time_data(feature_data)
                predictions.append(result['predicted_class'])
                actual_labels.append(row['label'])
            
            # Calculate performance metrics
            accuracy = accuracy_score(actual_labels, predictions)
            classification_rep = classification_report(actual_labels, predictions, output_dict=True)
            
            results['details']['accuracy'] = accuracy
            results['details']['classification_report'] = classification_rep
            results['details']['predictions'] = list(zip(actual_labels, predictions))
            
            # Check if accuracy is reasonable (should be high for training data)
            if accuracy >= 0.75:  # 75% accuracy threshold
                results['passed'] = True
                logger.info(f"✅ Model performance test passed (accuracy: {accuracy:.3f})")
            else:
                raise ValueError(f"Model accuracy too low: {accuracy:.3f}")
            
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"❌ Model performance test failed: {str(e)}")
        
        return results
    
    def test_cpp_integration_files(self) -> Dict[str, Any]:
        """Test C++ integration file generation"""
        logger.info("🔧 Testing C++ integration files...")
        
        results = {
            'test_name': 'cpp_integration_files',
            'passed': False,
            'details': {}
        }
        
        try:
            # Check for C++ export files
            cpp_export_dir = self.models_dir / "cpp_export"
            cpp_integration_dir = self.models_dir / "cpp_integration"
            
            required_files = [
                cpp_export_dir / "feature_info.json",
                cpp_export_dir / "sample_input.json",
                cpp_export_dir / "expected_output.json",
                cpp_integration_dir / "TSNAttackDetector.h",
                cpp_integration_dir / "TSNAttackDetector.cpp",
                cpp_integration_dir / "example_usage.cpp"
            ]
            
            missing_files = []
            for file_path in required_files:
                if not file_path.exists():
                    missing_files.append(str(file_path))
            
            if missing_files:
                raise FileNotFoundError(f"Missing C++ integration files: {missing_files}")
            
            # Validate JSON files
            feature_info_path = cpp_export_dir / "feature_info.json"
            with open(feature_info_path, 'r') as f:
                feature_info = json.load(f)
            
            results['details']['feature_count'] = feature_info.get('feature_count', 0)
            results['details']['class_count'] = feature_info.get('class_count', 0)
            results['details']['cpp_files_generated'] = len(required_files)
            
            results['passed'] = True
            logger.info("✅ C++ integration files test passed")
            
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"❌ C++ integration files test failed: {str(e)}")
        
        return results
    
    def test_end_to_end_pipeline(self) -> Dict[str, Any]:
        """Test the complete end-to-end pipeline"""
        logger.info("🔄 Testing end-to-end pipeline...")
        
        results = {
            'test_name': 'end_to_end_pipeline',
            'passed': False,
            'details': {}
        }
        
        try:
            # Test data loading
            df = pd.read_csv(self.data_path)
            
            # Test model loading
            detector = RealTimeAttackDetector(str(self.models_dir))
            
            # Test inference on all scenarios
            pipeline_results = {}
            
            for idx, row in df.iterrows():
                scenario = row['scenario']
                expected_label = row['label']
                
                # Prepare feature data
                exclude_columns = ['scenario', 'label', 'timestamp']
                feature_columns = [col for col in df.columns if col not in exclude_columns]
                
                feature_data = {}
                for col in feature_columns:
                    if pd.notna(row[col]):
                        feature_data[col] = float(row[col])
                    else:
                        feature_data[col] = 0.0
                
                # Get prediction
                result = detector.process_real_time_data(feature_data)
                
                pipeline_results[scenario] = {
                    'expected': expected_label,
                    'predicted': result['predicted_class'],
                    'confidence': result['confidence'],
                    'is_attack': result['is_attack'],
                    'correct': expected_label == result['predicted_class']
                }
            
            # Calculate overall accuracy
            correct_predictions = sum(1 for r in pipeline_results.values() if r['correct'])
            total_predictions = len(pipeline_results)
            overall_accuracy = correct_predictions / total_predictions
            
            results['details']['pipeline_results'] = pipeline_results
            results['details']['overall_accuracy'] = overall_accuracy
            results['details']['correct_predictions'] = correct_predictions
            results['details']['total_predictions'] = total_predictions
            
            # Check if pipeline is working
            if overall_accuracy >= 0.75:
                results['passed'] = True
                logger.info(f"✅ End-to-end pipeline test passed (accuracy: {overall_accuracy:.3f})")
            else:
                raise ValueError(f"Pipeline accuracy too low: {overall_accuracy:.3f}")
            
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"❌ End-to-end pipeline test failed: {str(e)}")
        
        return results
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all integration tests"""
        logger.info("🚀 Starting comprehensive integration testing...")
        
        test_functions = [
            self.test_data_integrity,
            self.test_model_loading,
            self.test_real_time_inference,
            self.test_model_performance,
            self.test_cpp_integration_files,
            self.test_end_to_end_pipeline
        ]
        
        all_results = {}
        passed_tests = 0
        total_tests = len(test_functions)
        
        for test_func in test_functions:
            test_name = test_func.__name__
            logger.info(f"\n{'='*50}")
            logger.info(f"Running test: {test_name}")
            logger.info(f"{'='*50}")
            
            result = test_func()
            all_results[test_name] = result
            
            if result['passed']:
                passed_tests += 1
                logger.info(f"✅ {test_name}: PASSED")
            else:
                logger.error(f"❌ {test_name}: FAILED")
                if 'error' in result:
                    logger.error(f"   Error: {result['error']}")
        
        # Generate summary
        summary = {
            'timestamp': datetime.now().isoformat(),
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'failed_tests': total_tests - passed_tests,
            'success_rate': passed_tests / total_tests,
            'all_results': all_results
        }
        
        # Save results
        results_path = self.project_dir / "ml_models" / "integration_test_results.json"
        with open(results_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Print summary
        print(f"\n{'='*60}")
        print("🎯 INTEGRATION TESTING SUMMARY")
        print(f"{'='*60}")
        print(f"📊 Total tests: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {total_tests - passed_tests}")
        print(f"📈 Success rate: {summary['success_rate']:.1%}")
        print(f"📁 Results saved to: {results_path}")
        
        if passed_tests == total_tests:
            print("\n🎉 ALL TESTS PASSED! Integration testing completed successfully!")
        else:
            print(f"\n⚠️ {total_tests - passed_tests} test(s) failed. Check logs for details.")
        
        print(f"{'='*60}")
        
        return summary

def main():
    """Main execution function"""
    print("🚀 TSN/PSFP Attack Detection - Integration Testing")
    print("="*55)
    
    # Initialize tester
    project_dir = Path(__file__).parent.parent
    tester = IntegrationTester(str(project_dir))
    
    # Run all tests
    summary = tester.run_all_tests()
    
    # Exit with appropriate code
    if summary['success_rate'] == 1.0:
        logger.info("🎉 All integration tests passed!")
        return 0
    else:
        logger.error(f"❌ {summary['failed_tests']} test(s) failed!")
        return 1

if __name__ == "__main__":
    exit(main()) 