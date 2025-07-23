#!/usr/bin/env python3
"""
AI-Enhanced ML Training for PQSwitch
Incorporates AI evaluation feedback as ground truth for model training
"""

import json
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import os
from datetime import datetime
from typing import Dict, List, Any, Tuple
import warnings
warnings.filterwarnings('ignore')

class AIEnhancedTrainer:
    """AI-Enhanced ML trainer that uses AI evaluation feedback as ground truth."""
    
    def __init__(self, ai_evaluation_file: str = "../ai_evaluation/ai_evaluations.json"):
        self.ai_evaluation_file = ai_evaluation_file
        self.models = {}
        self.encoders = {}
        self.scalers = {}
        self.training_report = {}
        
    def load_ai_evaluations(self) -> Dict[str, Any]:
        """Load AI evaluation results as ground truth."""
        if not os.path.exists(self.ai_evaluation_file):
            raise FileNotFoundError(f"AI evaluation file not found: {self.ai_evaluation_file}")
        
        with open(self.ai_evaluation_file, 'r') as f:
            ai_data = json.load(f)
        
        # Handle both list format and object format
        if isinstance(ai_data, list):
            evaluations = ai_data
            ai_data = {'evaluations': evaluations}
        else:
            evaluations = ai_data.get('evaluations', [])
        
        print(f"📊 Loaded AI evaluations: {len(evaluations)} findings")
        return ai_data
    
    def load_scan_results(self, scan_results_file: str = "../combined_scan_results.json") -> Dict[str, Any]:
        """Load original scan results."""
        if not os.path.exists(scan_results_file):
            raise FileNotFoundError(f"Scan results file not found: {scan_results_file}")
        
        with open(scan_results_file, 'r') as f:
            scan_data = json.load(f)
        
        # Handle both list format (combined_scan_results.json) and object format
        if isinstance(scan_data, list):
            findings = scan_data
            scan_data = {'crypto_findings': findings}
        else:
            findings = scan_data.get('crypto_findings', [])
        
        print(f"📊 Loaded scan results: {len(findings)} findings")
        return scan_data
    
    def extract_features(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from a finding for ML training."""
        features = {
            # Basic finding attributes
            'algorithm': finding.get('algorithm', 'unknown'),
            'severity': finding.get('severity', 'unknown'),
            'confidence': finding.get('confidence', 0.0),
            'crypto_type': finding.get('crypto_type', 'unknown'),
            'language': finding.get('language', 'unknown'),
            'rule_id': finding.get('rule_id', 'unknown'),
            'line_number': finding.get('line', 0),
            
            # File and context features
            'file_extension': finding.get('file', '').split('.')[-1] if finding.get('file') else 'unknown',
            'file_path_depth': len(finding.get('file', '').split('/')) if finding.get('file') else 0,
            'filename_length': len(os.path.basename(finding.get('file', ''))),
            
            # Context analysis
            'is_test_file': 'test' in finding.get('file', '').lower(),
            'is_crypto_library': any(lib in finding.get('file', '').lower() for lib in ['crypto', 'ssl', 'tls', 'hash']),
            'is_low_level': finding.get('file', '').endswith(('.c', '.cpp', '.h', '.hpp')),
            
            # Pattern analysis
            'pattern_complexity': len(finding.get('pattern', '')),
            'has_function_call': '(' in finding.get('pattern', ''),
            'has_import_statement': 'import' in finding.get('pattern', '').lower(),
            
            # Algorithm-specific features
            'is_hash_algorithm': finding.get('crypto_type', '') == 'hash',
            'is_symmetric_crypto': finding.get('crypto_type', '') == 'symmetric',
            'is_asymmetric_crypto': finding.get('crypto_type', '') == 'asymmetric',
            'is_legacy_algorithm': finding.get('algorithm', '') in ['md5', 'sha1', 'des', 'rc4'],
            'is_modern_algorithm': finding.get('algorithm', '') in ['sha256', 'sha512', 'aes', 'chacha20'],
            
            # Severity features
            'is_critical': finding.get('severity', '') == 'critical',
            'is_high': finding.get('severity', '') == 'high',
            'is_medium': finding.get('severity', '') == 'medium',
            'is_low': finding.get('severity', '') == 'low',
            'is_info': finding.get('severity', '') == 'info',
            
            # Language features
            'is_c_cpp': finding.get('language', '') in ['c', 'cpp', 'c++'],
            'is_high_level_lang': finding.get('language', '') in ['python', 'java', 'javascript', 'go'],
            'is_systems_lang': finding.get('language', '') in ['c', 'cpp', 'rust', 'go'],
        }
        
        return features
    
    def prepare_training_data(self, ai_evaluations: Dict[str, Any], scan_results: Dict[str, Any]) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Prepare training data by combining scan results with AI evaluations."""
        
        # Create mapping of findings to AI evaluations
        ai_eval_map = {}
        for eval_data in ai_evaluations.get('evaluations', []):
            finding_id = eval_data.get('finding_id', '')
            ai_eval_map[finding_id] = eval_data
        
        # Process all findings
        training_data = []
        ai_labels = []
        
        for i, finding in enumerate(scan_results.get('crypto_findings', [])):
            # Use the actual finding ID from the scan result if available
            finding_id = finding.get('id', f"finding_{i}")
            
            # Extract features
            features = self.extract_features(finding)
            features['finding_id'] = finding_id
            
            # Get AI evaluation if available (try both the actual ID and the sequential ID)
            ai_eval = ai_eval_map.get(finding_id) or ai_eval_map.get(f"finding_{i}")
            if ai_eval:
                # Use AI evaluation as ground truth
                # Handle both 'is_valid' and 'is_valid_finding' field names
                is_valid = ai_eval.get('is_valid_finding', ai_eval.get('is_valid', False))
                features['ai_is_valid'] = is_valid
                features['ai_confidence'] = ai_eval.get('confidence', 0.0)
                features['ai_severity'] = ai_eval.get('severity', 'unknown')
                features['has_ai_evaluation'] = True
                
                ai_labels.append({
                    'finding_id': finding_id,
                    'is_valid': is_valid,
                    'confidence': ai_eval.get('confidence', 0.0),
                    'severity': ai_eval.get('severity', 'unknown'),
                    'is_false_positive': not is_valid,
                })
            else:
                # No AI evaluation available
                features['ai_is_valid'] = None
                features['ai_confidence'] = None
                features['ai_severity'] = None
                features['has_ai_evaluation'] = False
            
            training_data.append(features)
        
        df_features = pd.DataFrame(training_data)
        df_labels = pd.DataFrame(ai_labels)
        
        print(f"📊 Prepared training data: {len(df_features)} samples")
        print(f"🎯 AI-evaluated samples: {len(df_labels)} samples")
        
        return df_features, df_labels
    
    def encode_categorical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Encode categorical features for ML training."""
        df_encoded = df.copy()
        
        categorical_columns = [
            'algorithm', 'severity', 'crypto_type', 'language', 
            'rule_id', 'file_extension', 'ai_severity'
        ]
        
        for col in categorical_columns:
            if col in df_encoded.columns:
                if col not in self.encoders:
                    self.encoders[col] = LabelEncoder()
                
                # Handle missing values
                df_encoded[col] = df_encoded[col].fillna('unknown')
                
                # Fit encoder if not already fitted
                if not hasattr(self.encoders[col], 'classes_'):
                    self.encoders[col].fit(df_encoded[col])
                
                df_encoded[col] = self.encoders[col].transform(df_encoded[col])
        
        return df_encoded
    
    def train_false_positive_detector(self, df_features: pd.DataFrame, df_labels: pd.DataFrame) -> Dict[str, Any]:
        """Train a model to detect false positives based on AI evaluations."""
        
        # Filter to AI-evaluated samples only
        ai_evaluated = df_features[df_features['has_ai_evaluation'] == True].copy()
        
        if len(ai_evaluated) == 0:
            print("⚠️  No AI-evaluated samples found for false positive detection")
            return {}
        
        # Prepare features
        feature_columns = [col for col in ai_evaluated.columns if col not in [
            'finding_id', 'ai_is_valid', 'ai_confidence', 'ai_severity', 'has_ai_evaluation'
        ]]
        
        X = ai_evaluated[feature_columns]
        y = ai_evaluated['ai_is_valid'].astype(int)  # 1 for valid, 0 for false positive
        
        # Encode categorical features
        X_encoded = self.encode_categorical_features(X)
        
        # Handle missing values
        X_encoded = X_encoded.fillna(0)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_encoded, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train model
        model = LogisticRegression(random_state=42, max_iter=1000)
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test)[:, 1]
        
        # Calculate metrics
        accuracy = model.score(X_test, y_test)
        auc_score = roc_auc_score(y_test, y_pred_proba)
        
        # Cross-validation
        cv_scores = cross_val_score(model, X_encoded, y, cv=5, scoring='roc_auc')
        
        results = {
            'model': model,
            'feature_columns': feature_columns,
            'accuracy': accuracy,
            'auc_score': auc_score,
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'classification_report': classification_report(y_test, y_pred),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'feature_importance': dict(zip(feature_columns, model.coef_[0])),
            'training_samples': len(X_train),
            'test_samples': len(X_test),
        }
        
        self.models['false_positive_detector'] = model
        
        print(f"✅ False Positive Detector trained:")
        print(f"   - Accuracy: {accuracy:.3f}")
        print(f"   - AUC Score: {auc_score:.3f}")
        print(f"   - CV Score: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
        
        return results
    
    def train_confidence_predictor(self, df_features: pd.DataFrame, df_labels: pd.DataFrame) -> Dict[str, Any]:
        """Train a model to predict confidence scores based on AI evaluations."""
        
        # Filter to AI-evaluated samples only
        ai_evaluated = df_features[df_features['has_ai_evaluation'] == True].copy()
        
        if len(ai_evaluated) == 0:
            print("⚠️  No AI-evaluated samples found for confidence prediction")
            return {}
        
        # Prepare features
        feature_columns = [col for col in ai_evaluated.columns if col not in [
            'finding_id', 'ai_is_valid', 'ai_confidence', 'ai_severity', 'has_ai_evaluation'
        ]]
        
        X = ai_evaluated[feature_columns]
        y = ai_evaluated['ai_confidence']
        
        # Encode categorical features
        X_encoded = self.encode_categorical_features(X)
        
        # Handle missing values
        X_encoded = X_encoded.fillna(0)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_encoded, y, test_size=0.2, random_state=42
        )
        
        # Train model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        
        # Convert confidence to categories for classification
        y_train_cat = pd.cut(y_train, bins=[0, 0.5, 0.8, 1.0], labels=['low', 'medium', 'high'])
        y_test_cat = pd.cut(y_test, bins=[0, 0.5, 0.8, 1.0], labels=['low', 'medium', 'high'])
        
        model.fit(X_train, y_train_cat)
        
        # Evaluate
        y_pred = model.predict(X_test)
        accuracy = model.score(X_test, y_test_cat)
        
        # Cross-validation on full encoded dataset with categorical labels
        y_cat = pd.cut(y, bins=[0, 0.5, 0.8, 1.0], labels=['low', 'medium', 'high'])
        cv_scores = cross_val_score(model, X_encoded, y_cat, cv=5, scoring='accuracy')
        
        results = {
            'model': model,
            'feature_columns': feature_columns,
            'accuracy': accuracy,
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'classification_report': classification_report(y_test_cat, y_pred),
            'feature_importance': dict(zip(feature_columns, model.feature_importances_)),
            'training_samples': len(X_train),
            'test_samples': len(X_test),
        }
        
        self.models['confidence_predictor'] = model
        
        print(f"✅ Confidence Predictor trained:")
        print(f"   - Accuracy: {accuracy:.3f}")
        print(f"   - CV Score: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
        
        return results
    
    def train_severity_classifier(self, df_features: pd.DataFrame, df_labels: pd.DataFrame) -> Dict[str, Any]:
        """Train a model to predict severity based on AI evaluations."""
        
        # Filter to AI-evaluated samples only
        ai_evaluated = df_features[df_features['has_ai_evaluation'] == True].copy()
        
        if len(ai_evaluated) == 0:
            print("⚠️  No AI-evaluated samples found for severity classification")
            return {}
        
        # Prepare features
        feature_columns = [col for col in ai_evaluated.columns if col not in [
            'finding_id', 'ai_is_valid', 'ai_confidence', 'ai_severity', 'has_ai_evaluation'
        ]]
        
        X = ai_evaluated[feature_columns]
        y = ai_evaluated['ai_severity']
        
        # Encode categorical features
        X_encoded = self.encode_categorical_features(X)
        
        # Handle missing values
        X_encoded = X_encoded.fillna(0)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_encoded, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test)
        accuracy = model.score(X_test, y_test)
        
        # Cross-validation - handle case where we might have too few samples for 5-fold CV
        cv_folds = min(5, len(set(y)))  # Use fewer folds if we have few unique classes
        if cv_folds < 2:
            cv_folds = 2
        cv_scores = cross_val_score(model, X_encoded, y, cv=cv_folds, scoring='accuracy')
        
        results = {
            'model': model,
            'feature_columns': feature_columns,
            'accuracy': accuracy,
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'classification_report': classification_report(y_test, y_pred),
            'feature_importance': dict(zip(feature_columns, model.feature_importances_)),
            'training_samples': len(X_train),
            'test_samples': len(X_test),
        }
        
        self.models['severity_classifier'] = model
        
        print(f"✅ Severity Classifier trained:")
        print(f"   - Accuracy: {accuracy:.3f}")
        print(f"   - CV Score: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
        
        return results
    
    def save_models(self, output_dir: str = "trained_models"):
        """Save trained models and encoders."""
        os.makedirs(output_dir, exist_ok=True)
        
        # Save models
        for model_name, model in self.models.items():
            model_file = os.path.join(output_dir, f"{model_name}.joblib")
            joblib.dump(model, model_file)
            print(f"💾 Saved {model_name} to {model_file}")
        
        # Save encoders
        for encoder_name, encoder in self.encoders.items():
            encoder_file = os.path.join(output_dir, f"{encoder_name}_encoder.joblib")
            joblib.dump(encoder, encoder_file)
            print(f"💾 Saved {encoder_name} encoder to {encoder_file}")
        
        # Save training report
        report_file = os.path.join(output_dir, "ai_enhanced_training_report.json")
        with open(report_file, 'w') as f:
            json.dump(self.training_report, f, indent=2, default=str)
        print(f"📊 Saved training report to {report_file}")
    
    def run_training(self):
        """Run the complete AI-enhanced training pipeline."""
        print("🚀 Starting AI-Enhanced ML Training Pipeline")
        print("=" * 60)
        
        # Load data
        print("📊 Loading data...")
        ai_evaluations = self.load_ai_evaluations()
        scan_results = self.load_scan_results()
        
        # Prepare training data
        print("🔄 Preparing training data...")
        df_features, df_labels = self.prepare_training_data(ai_evaluations, scan_results)
        
        # Train models
        print("🧠 Training models...")
        
        # 1. False Positive Detector
        print("\n1. Training False Positive Detector...")
        fp_results = self.train_false_positive_detector(df_features, df_labels)
        
        # 2. Confidence Predictor
        print("\n2. Training Confidence Predictor...")
        conf_results = self.train_confidence_predictor(df_features, df_labels)
        
        # 3. Severity Classifier
        print("\n3. Training Severity Classifier...")
        sev_results = self.train_severity_classifier(df_features, df_labels)
        
        # Compile training report
        self.training_report = {
            'training_timestamp': datetime.now().isoformat(),
            'data_summary': {
                'total_findings': len(df_features),
                'ai_evaluated_findings': len(df_labels),
                'ai_evaluation_coverage': len(df_labels) / len(df_features) if len(df_features) > 0 else 0,
            },
            'model_results': {
                'false_positive_detector': fp_results,
                'confidence_predictor': conf_results,
                'severity_classifier': sev_results,
            },
            'feature_engineering': {
                'total_features': len(df_features.columns),
                'categorical_features': len(self.encoders),
                'feature_columns': list(df_features.columns),
            },
        }
        
        # Save models
        print("\n💾 Saving models...")
        self.save_models()
        
        # Print summary
        print("\n" + "=" * 60)
        print("✅ AI-Enhanced ML Training Complete!")
        print(f"📊 Training Summary:")
        print(f"   - Total Findings: {len(df_features)}")
        print(f"   - AI Evaluated: {len(df_labels)}")
        print(f"   - Coverage: {len(df_labels) / len(df_features) * 100:.1f}%")
        print(f"   - Models Trained: {len(self.models)}")
        print(f"   - Features Engineered: {len(df_features.columns)}")
        
        if fp_results:
            print(f"   - False Positive Detection AUC: {fp_results['auc_score']:.3f}")
        if conf_results:
            print(f"   - Confidence Prediction Accuracy: {conf_results['accuracy']:.3f}")
        if sev_results:
            print(f"   - Severity Classification Accuracy: {sev_results['accuracy']:.3f}")

def main():
    """Main function to run AI-enhanced training."""
    trainer = AIEnhancedTrainer()
    trainer.run_training()

if __name__ == "__main__":
    main() 