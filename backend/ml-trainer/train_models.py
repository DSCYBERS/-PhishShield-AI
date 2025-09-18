"""
PhishShield AI - ML Model Training Pipeline
Trains multiple models for phishing detection at different layers
"""

import os
import logging
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Any
import joblib
import json
from datetime import datetime
from pathlib import Path

# ML Libraries
import tensorflow as tf
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import xgboost as xgb
import lightgbm as lgb

# Custom modules
from data_collector import PhishingDataCollector
from feature_extractor import FeatureExtractor
from model_trainer import ModelTrainer
from model_converter import TensorFlowLiteConverter

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PhishingMLPipeline:
    """Complete ML pipeline for phishing detection"""
    
    def __init__(self, config_path: str = "config.json"):
        """Initialize the ML pipeline"""
        self.config = self._load_config(config_path)
        self.data_collector = PhishingDataCollector(self.config)
        self.feature_extractor = FeatureExtractor(self.config)
        self.model_trainer = ModelTrainer(self.config)
        self.converter = TensorFlowLiteConverter(self.config)
        
        # Create output directories
        self.models_dir = Path("models")
        self.models_dir.mkdir(exist_ok=True)
        
        self.results_dir = Path("results")
        self.results_dir.mkdir(exist_ok=True)
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning("Config file not found, using defaults")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            "data": {
                "phishing_urls": 50000,
                "legitimate_urls": 50000,
                "test_size": 0.2,
                "validation_size": 0.1
            },
            "features": {
                "url_features": True,
                "domain_features": True,
                "content_features": True,
                "behavioral_features": True
            },
            "models": {
                "lightgbm": {
                    "enabled": True,
                    "params": {
                        "objective": "binary",
                        "metric": "binary_logloss",
                        "boosting_type": "gbdt",
                        "num_leaves": 31,
                        "learning_rate": 0.05,
                        "feature_fraction": 0.9
                    }
                },
                "tensorflow": {
                    "enabled": True,
                    "architecture": "deep",
                    "epochs": 100,
                    "batch_size": 256
                },
                "xgboost": {
                    "enabled": True,
                    "params": {
                        "objective": "binary:logistic",
                        "eval_metric": "logloss",
                        "max_depth": 6,
                        "learning_rate": 0.1
                    }
                }
            }
        }
    
    def run_full_pipeline(self):
        """Run the complete ML training pipeline"""
        logger.info("Starting PhishShield AI ML Training Pipeline")
        
        # Step 1: Data Collection
        logger.info("Step 1: Collecting training data...")
        dataset = self.data_collector.collect_training_data()
        logger.info(f"Collected {len(dataset)} samples")
        
        # Step 2: Feature Extraction
        logger.info("Step 2: Extracting features...")
        features, labels = self.feature_extractor.extract_features(dataset)
        logger.info(f"Extracted {features.shape[1]} features")
        
        # Step 3: Data Splitting
        logger.info("Step 3: Splitting data...")
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, 
            test_size=self.config["data"]["test_size"],
            random_state=42,
            stratify=labels
        )
        
        # Step 4: Model Training
        logger.info("Step 4: Training models...")
        models = self.train_all_models(X_train, X_test, y_train, y_test)
        
        # Step 5: Model Evaluation
        logger.info("Step 5: Evaluating models...")
        evaluation_results = self.evaluate_models(models, X_test, y_test)
        
        # Step 6: Model Conversion
        logger.info("Step 6: Converting models for deployment...")
        self.convert_models_for_deployment(models)
        
        # Step 7: Generate Report
        logger.info("Step 7: Generating training report...")
        self.generate_training_report(evaluation_results)
        
        logger.info("ML Training Pipeline completed successfully!")
        
    def train_all_models(self, X_train, X_test, y_train, y_test) -> Dict[str, Any]:
        """Train all configured models"""
        models = {}
        
        # LightGBM Model (Primary on-device model)
        if self.config["models"]["lightgbm"]["enabled"]:
            logger.info("Training LightGBM model...")
            lgb_model = self.train_lightgbm_model(X_train, X_test, y_train, y_test)
            models["lightgbm"] = lgb_model
        
        # TensorFlow Deep Learning Model
        if self.config["models"]["tensorflow"]["enabled"]:
            logger.info("Training TensorFlow model...")
            tf_model = self.train_tensorflow_model(X_train, X_test, y_train, y_test)
            models["tensorflow"] = tf_model
        
        # XGBoost Model (Backup model)
        if self.config["models"]["xgboost"]["enabled"]:
            logger.info("Training XGBoost model...")
            xgb_model = self.train_xgboost_model(X_train, X_test, y_train, y_test)
            models["xgboost"] = xgb_model
        
        return models
    
    def train_lightgbm_model(self, X_train, X_test, y_train, y_test):
        """Train LightGBM model optimized for mobile deployment"""
        params = self.config["models"]["lightgbm"]["params"]
        
        # Create datasets
        train_data = lgb.Dataset(X_train, label=y_train)
        valid_data = lgb.Dataset(X_test, label=y_test, reference=train_data)
        
        # Train model
        model = lgb.train(
            params,
            train_data,
            valid_sets=[valid_data],
            num_boost_round=1000,
            callbacks=[lgb.early_stopping(50), lgb.log_evaluation(100)]
        )
        
        # Save model
        model.save_model(str(self.models_dir / "lightgbm_phishing_detector.txt"))
        
        return model
    
    def train_tensorflow_model(self, X_train, X_test, y_train, y_test):
        """Train TensorFlow deep learning model"""
        # Create neural network architecture
        model = tf.keras.Sequential([
            tf.keras.layers.Dense(512, activation='relu', input_shape=(X_train.shape[1],)),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(256, activation='relu'),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dropout(0.1),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        
        # Compile model
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        # Train model
        history = model.fit(
            X_train, y_train,
            batch_size=self.config["models"]["tensorflow"]["batch_size"],
            epochs=self.config["models"]["tensorflow"]["epochs"],
            validation_data=(X_test, y_test),
            callbacks=[
                tf.keras.callbacks.EarlyStopping(patience=10, restore_best_weights=True),
                tf.keras.callbacks.ReduceLROnPlateau(factor=0.5, patience=5)
            ],
            verbose=1
        )
        
        # Save model
        model.save(str(self.models_dir / "tensorflow_phishing_detector.h5"))
        
        return {"model": model, "history": history}
    
    def train_xgboost_model(self, X_train, X_test, y_train, y_test):
        """Train XGBoost model"""
        params = self.config["models"]["xgboost"]["params"]
        
        # Create DMatrix
        dtrain = xgb.DMatrix(X_train, label=y_train)
        dtest = xgb.DMatrix(X_test, label=y_test)
        
        # Train model
        model = xgb.train(
            params,
            dtrain,
            num_boost_round=1000,
            evals=[(dtest, 'eval')],
            early_stopping_rounds=50,
            verbose_eval=100
        )
        
        # Save model
        model.save_model(str(self.models_dir / "xgboost_phishing_detector.json"))
        
        return model
    
    def evaluate_models(self, models: Dict[str, Any], X_test, y_test) -> Dict[str, Dict]:
        """Evaluate all trained models"""
        results = {}
        
        for model_name, model in models.items():
            logger.info(f"Evaluating {model_name} model...")
            
            if model_name == "lightgbm":
                y_pred = model.predict(X_test)
                y_pred_binary = (y_pred > 0.5).astype(int)
            elif model_name == "tensorflow":
                y_pred = model["model"].predict(X_test).flatten()
                y_pred_binary = (y_pred > 0.5).astype(int)
            elif model_name == "xgboost":
                dtest = xgb.DMatrix(X_test)
                y_pred = model.predict(dtest)
                y_pred_binary = (y_pred > 0.5).astype(int)
            
            # Calculate metrics
            auc_score = roc_auc_score(y_test, y_pred)
            classification_rep = classification_report(y_test, y_pred_binary, output_dict=True)
            
            results[model_name] = {
                "auc_score": auc_score,
                "classification_report": classification_rep,
                "confusion_matrix": confusion_matrix(y_test, y_pred_binary).tolist()
            }
            
            logger.info(f"{model_name} AUC Score: {auc_score:.4f}")
        
        return results
    
    def convert_models_for_deployment(self, models: Dict[str, Any]):
        """Convert models for deployment"""
        # Convert TensorFlow model to TensorFlow Lite
        if "tensorflow" in models:
            self.converter.convert_tensorflow_to_tflite(
                models["tensorflow"]["model"],
                str(self.models_dir / "phishing_detector.tflite")
            )
        
        # Convert LightGBM to ONNX format for mobile
        if "lightgbm" in models:
            self.converter.convert_lightgbm_to_mobile(
                models["lightgbm"],
                str(self.models_dir / "lightgbm_mobile.txt")
            )
    
    def generate_training_report(self, evaluation_results: Dict[str, Dict]):
        """Generate comprehensive training report"""
        report = {
            "training_date": datetime.now().isoformat(),
            "config": self.config,
            "model_performance": evaluation_results,
            "recommendations": self._generate_recommendations(evaluation_results)
        }
        
        # Save report
        with open(self.results_dir / "training_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        # Generate summary
        self._print_training_summary(evaluation_results)
    
    def _generate_recommendations(self, results: Dict[str, Dict]) -> List[str]:
        """Generate model recommendations based on performance"""
        recommendations = []
        
        # Find best performing model
        best_model = max(results.keys(), key=lambda k: results[k]["auc_score"])
        best_auc = results[best_model]["auc_score"]
        
        recommendations.append(f"Best performing model: {best_model} (AUC: {best_auc:.4f})")
        
        if best_auc > 0.95:
            recommendations.append("Excellent model performance - ready for production")
        elif best_auc > 0.90:
            recommendations.append("Good model performance - consider additional tuning")
        else:
            recommendations.append("Model performance needs improvement - collect more data")
        
        return recommendations
    
    def _print_training_summary(self, results: Dict[str, Dict]):
        """Print training summary to console"""
        print("\n" + "="*50)
        print("PHISHSHIELD AI - TRAINING SUMMARY")
        print("="*50)
        
        for model_name, metrics in results.items():
            print(f"\n{model_name.upper()} MODEL:")
            print(f"  AUC Score: {metrics['auc_score']:.4f}")
            print(f"  Precision: {metrics['classification_report']['1']['precision']:.4f}")
            print(f"  Recall: {metrics['classification_report']['1']['recall']:.4f}")
            print(f"  F1-Score: {metrics['classification_report']['1']['f1-score']:.4f}")
        
        print("\n" + "="*50)

def main():
    """Main training function"""
    try:
        # Initialize and run pipeline
        pipeline = PhishingMLPipeline()
        pipeline.run_full_pipeline()
        
    except Exception as e:
        logger.error(f"Training pipeline failed: {e}")
        raise

if __name__ == "__main__":
    main()
