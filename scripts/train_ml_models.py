#!/usr/bin/env python3
"""
🎯 TSN/PSFP Attack Detection - ML Model Training
================================================
Trains and validates ML models for real-time attack detection
"""

import pandas as pd
import numpy as np
import os
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Any

# ML Libraries
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
from sklearn.pipeline import Pipeline
import joblib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ml_training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class TSNAttackDetector:
    """ML-based TSN Attack Detection System"""
    
    def __init__(self, data_path: str, models_dir: str):
        self.data_path = Path(data_path)
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.models = {}
        self.feature_columns = []
        
        logger.info(f"🎯 TSN Attack Detector initialized")
        logger.info(f"📂 Data path: {self.data_path}")
        logger.info(f"📁 Models dir: {self.models_dir}")
    
    def load_and_preprocess_data(self) -> pd.DataFrame:
        """Load and preprocess the training data"""
        logger.info("📊 Loading training data...")
        
        if not self.data_path.exists():
            raise FileNotFoundError(f"Training data not found: {self.data_path}")
        
        # Load data
        df = pd.read_csv(self.data_path)
        logger.info(f"📈 Loaded {len(df)} samples with {len(df.columns)} features")
        
        # Check for missing values
        missing_values = df.isnull().sum()
        if missing_values.sum() > 0:
            logger.warning(f"⚠️ Found missing values: {missing_values[missing_values > 0]}")
            # Fill missing values with 0 for numeric columns
            numeric_columns = df.select_dtypes(include=[np.number]).columns
            df[numeric_columns] = df[numeric_columns].fillna(0)
        
        # Remove non-feature columns
        exclude_columns = ['scenario', 'label', 'timestamp']
        self.feature_columns = [col for col in df.columns if col not in exclude_columns]
        
        logger.info(f"🔢 Using {len(self.feature_columns)} features for training")
        logger.info(f"📋 Feature columns: {self.feature_columns}")
        
        # CRITICAL WARNING: Small dataset
        if len(df) < 10:
            logger.error(f"🚨 CRITICAL: Very small dataset ({len(df)} samples)!")
            logger.error(f"🚨 This will lead to severe overfitting and unreliable results!")
            logger.error(f"🚨 For production use, you need at least 100+ samples per class!")
            logger.error(f"🚨 Current dataset is only suitable for demonstration purposes!")
        
        return df
    
    def prepare_features_and_labels(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare features and labels for training"""
        logger.info("🔧 Preparing features and labels...")
        
        # Extract features
        X = df[self.feature_columns].values
        
        # Encode labels
        y = self.label_encoder.fit_transform(df['label'])
        
        # Log class distribution
        unique_labels, counts = np.unique(y, return_counts=True)
        label_names = self.label_encoder.classes_
        logger.info("📊 Class distribution:")
        for label, count in zip(label_names, counts):
            logger.info(f"   • {label}: {count} samples")
        
        return X, y
    
    def train_models(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """Train multiple ML models"""
        logger.info("🤖 Training ML models...")
        
        # Define models
        model_configs = {
            'random_forest': {
                'model': RandomForestClassifier(
                    n_estimators=100,
                    max_depth=10,
                    random_state=42,
                    n_jobs=-1
                ),
                'name': 'Random Forest'
            },
            'gradient_boosting': {
                'model': GradientBoostingClassifier(
                    n_estimators=100,
                    max_depth=6,
                    random_state=42
                ),
                'name': 'Gradient Boosting'
            },
            'svm': {
                'model': SVC(
                    kernel='rbf',
                    C=1.0,
                    random_state=42,
                    probability=True
                ),
                'name': 'Support Vector Machine'
            }
        }
        
        # Train each model
        for model_key, config in model_configs.items():
            logger.info(f"🔄 Training {config['name']}...")
            
            # Create pipeline with scaling
            pipeline = Pipeline([
                ('scaler', StandardScaler()),
                ('classifier', config['model'])
            ])
            
            # Train the model
            pipeline.fit(X, y)
            
            # Store the model
            self.models[model_key] = pipeline
            
            logger.info(f"✅ {config['name']} training completed")
        
        return self.models
    
    def evaluate_models(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Dict[str, float]]:
        """Evaluate model performance using cross-validation"""
        logger.info("📊 Evaluating model performance...")
        
        results = {}
        
        # Adjust cross-validation based on dataset size
        n_samples = len(X)
        if n_samples < 5:
            logger.warning(f"⚠️ Small dataset ({n_samples} samples), using leave-one-out cross-validation")
            from sklearn.model_selection import LeaveOneOut
            cv = LeaveOneOut()
        else:
            cv = StratifiedKFold(n_splits=min(5, n_samples), shuffle=True, random_state=42)
        
        for model_key, pipeline in self.models.items():
            logger.info(f"🔍 Evaluating {model_key}...")
            
            # Cross-validation scores
            cv_scores = cross_val_score(pipeline, X, y, cv=cv, scoring='accuracy')
            
            # For small datasets, use leave-one-out cross-validation for final evaluation
            if n_samples < 5:
                logger.warning(f"⚠️ Very small dataset ({n_samples} samples) - using leave-one-out CV for evaluation")
                
                # Use leave-one-out cross-validation for final evaluation
                from sklearn.model_selection import LeaveOneOut
                loo = LeaveOneOut()
                
                # Get predictions using leave-one-out
                y_pred_loo = []
                for train_idx, test_idx in loo.split(X):
                    X_train_loo, X_test_loo = X[train_idx], X[test_idx]
                    y_train_loo, y_test_loo = y[train_idx], y[test_idx]
                    
                    # Train on training fold
                    pipeline.fit(X_train_loo, y_train_loo)
                    # Predict on test fold
                    y_pred_loo.append(pipeline.predict(X_test_loo)[0])
                
                # Calculate metrics on leave-one-out predictions
                accuracy = accuracy_score(y, y_pred_loo)
                precision, recall, f1, _ = precision_recall_fscore_support(
                    y, y_pred_loo, average='weighted'
                )
                
                results[model_key] = {
                    'cv_mean_accuracy': cv_scores.mean(),
                    'cv_std_accuracy': cv_scores.std(),
                    'test_accuracy': accuracy,
                    'test_precision': precision,
                    'test_recall': recall,
                    'test_f1': f1
                }
                
                logger.info(f"📈 {model_key} Results (leave-one-out CV):")
                logger.info(f"   CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
                logger.info(f"   LOO Accuracy: {accuracy:.4f}")
                logger.info(f"   LOO F1-Score: {f1:.4f}")
                logger.info(f"   ⚠️  Note: Small dataset may lead to overfitting")
            else:
                # Detailed evaluation on a single train/test split
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=0.2, random_state=42, stratify=y
                )
                
                # Train and predict
                pipeline.fit(X_train, y_train)
                y_pred = pipeline.predict(X_test)
                
                # Calculate metrics
                accuracy = accuracy_score(y_test, y_pred)
                precision, recall, f1, _ = precision_recall_fscore_support(
                    y_test, y_pred, average='weighted'
                )
                
                results[model_key] = {
                    'cv_mean_accuracy': cv_scores.mean(),
                    'cv_std_accuracy': cv_scores.std(),
                    'test_accuracy': accuracy,
                    'test_precision': precision,
                    'test_recall': recall,
                    'test_f1': f1
                }
                
                logger.info(f"📈 {model_key} Results:")
                logger.info(f"   CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
                logger.info(f"   Test Accuracy: {accuracy:.4f}")
                logger.info(f"   Test F1-Score: {f1:.4f}")
        
        return results
    
    def save_models_and_metadata(self, results: Dict[str, Dict[str, float]]):
        """Save trained models and metadata"""
        logger.info("💾 Saving models and metadata...")
        
        # Save each model
        for model_key, pipeline in self.models.items():
            model_path = self.models_dir / f"{model_key}_model.joblib"
            joblib.dump(pipeline, model_path)
            logger.info(f"💾 Saved {model_key} to: {model_path}")
        
        # Save metadata
        metadata = {
            'training_timestamp': datetime.now().isoformat(),
            'feature_columns': self.feature_columns,
            'label_classes': self.label_encoder.classes_.tolist(),
            'model_performance': results,
            'data_info': {
                'total_samples': len(self.feature_columns),
                'total_features': len(self.feature_columns),
                'feature_names': self.feature_columns
            }
        }
        
        metadata_path = self.models_dir / "model_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        logger.info(f"📋 Saved metadata to: {metadata_path}")
        
        # Save feature importance for tree-based models
        for model_key, pipeline in self.models.items():
            if hasattr(pipeline.named_steps['classifier'], 'feature_importances_'):
                importances = pipeline.named_steps['classifier'].feature_importances_
                feature_importance = dict(zip(self.feature_columns, importances))
                
                # Sort by importance
                sorted_importance = sorted(
                    feature_importance.items(), 
                    key=lambda x: x[1], 
                    reverse=True
                )
                
                importance_path = self.models_dir / f"{model_key}_feature_importance.json"
                with open(importance_path, 'w') as f:
                    json.dump(dict(sorted_importance), f, indent=2)
                logger.info(f"📊 Saved feature importance to: {importance_path}")
    
    def generate_training_report(self, results: Dict[str, Dict[str, float]]):
        """Generate comprehensive training report"""
        logger.info("📄 Generating training report...")
        
        # Find best model
        best_model = max(results.keys(), key=lambda k: results[k]['test_f1'])
        best_f1 = results[best_model]['test_f1']
        
        report = f"""
🎯 TSN/PSFP ATTACK DETECTION - ML TRAINING REPORT
=================================================
Training completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📊 DATASET INFORMATION
----------------------
• Total features: {len(self.feature_columns)}
• Feature columns: {', '.join(self.feature_columns[:5])}...
• Label classes: {', '.join(self.label_encoder.classes_)}

🤖 MODEL PERFORMANCE
--------------------
"""
        
        for model_key, metrics in results.items():
            report += f"""
{model_key.upper().replace('_', ' ')}:
• Cross-validation accuracy: {metrics['cv_mean_accuracy']:.4f} (±{metrics['cv_std_accuracy']:.4f})
• Test accuracy: {metrics['test_accuracy']:.4f}
• Test precision: {metrics['test_precision']:.4f}
• Test recall: {metrics['test_recall']:.4f}
• Test F1-score: {metrics['test_f1']:.4f}
"""
        
        report += f"""
🏆 BEST MODEL
-------------
Best performing model: {best_model}
Best F1-score: {best_f1:.4f}

📁 SAVED FILES
--------------
• Models: {self.models_dir}/*_model.joblib
• Metadata: {self.models_dir}/model_metadata.json
• Feature importance: {self.models_dir}/*_feature_importance.json

✅ TRAINING COMPLETED SUCCESSFULLY!
"""
        
        # Save report
        report_path = self.models_dir / "training_report.txt"
        with open(report_path, 'w') as f:
            f.write(report)
        
        # Print to console
        print(report)
        logger.info(f"📄 Training report saved to: {report_path}")

def main():
    """Main execution function"""
    print("🚀 TSN/PSFP Attack Detection - ML Model Training")
    print("="*55)
    
    # Paths
    current_dir = Path(__file__).parent
    data_path = current_dir.parent / "ml_models" / "tsn_attack_features.csv"
    models_dir = current_dir.parent / "ml_models" / "trained_models"
    
    try:
        # Initialize detector
        detector = TSNAttackDetector(data_path, models_dir)
        
        # Load and preprocess data
        df = detector.load_and_preprocess_data()
        
        # Prepare features and labels
        X, y = detector.prepare_features_and_labels(df)
        
        # Train models
        models = detector.train_models(X, y)
        
        # Evaluate models
        results = detector.evaluate_models(X, y)
        
        # Save models and metadata
        detector.save_models_and_metadata(results)
        
        # Generate report
        detector.generate_training_report(results)
        
        logger.info("🎉 ML training completed successfully!")
        
    except Exception as e:
        logger.error(f"❌ Training failed: {str(e)}")
        raise

if __name__ == "__main__":
    main() 