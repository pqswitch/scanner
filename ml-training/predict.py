#!/usr/bin/env python3
"""
ML Prediction Service for PQSwitch
Loads trained models and provides predictions for findings
"""

import json
import sys
import joblib
import pandas as pd
import numpy as np
from pathlib import Path

class MLPredictor:
    def __init__(self, models_dir="trained_models"):
        self.models_dir = Path(models_dir)
        self.models = {}
        self.encoders = {}
        self.load_models()
    
    def load_models(self):
        """Load all trained models and encoders."""
        # Load models
        model_files = {
            'false_positive_detector': 'false_positive_detector.joblib',
            'confidence_predictor': 'confidence_predictor.joblib',
            'severity_classifier': 'severity_classifier.joblib'
        }
        
        for name, filename in model_files.items():
            path = self.models_dir / filename
            if path.exists():
                self.models[name] = joblib.load(path)
                print(f"✅ Loaded {name}")
            else:
                print(f"⚠️  Model not found: {filename}")
        
        # Load encoders
        encoder_files = [
            'algorithm_encoder.joblib',
            'severity_encoder.joblib', 
            'crypto_type_encoder.joblib',
            'language_encoder.joblib',
            'rule_id_encoder.joblib',
            'file_extension_encoder.joblib'
        ]
        
        for filename in encoder_files:
            path = self.models_dir / filename
            if path.exists():
                encoder_name = filename.replace('_encoder.joblib', '')
                self.encoders[encoder_name] = joblib.load(path)
                print(f"✅ Loaded {encoder_name} encoder")
    
    def extract_features(self, finding):
        """Extract features from finding (same as training)."""
        features = {
            'algorithm': finding.get('algorithm', 'unknown'),
            'severity': finding.get('severity', 'unknown'),
            'confidence': finding.get('confidence', 0.0),
            'crypto_type': finding.get('crypto_type', 'unknown'),
            'language': finding.get('language', 'unknown'),
            'rule_id': finding.get('rule_id', 'unknown'),
            'line_number': finding.get('line', 0),
            'file_extension': finding.get('file', '').split('.')[-1] if finding.get('file') else 'unknown',
            'file_path_depth': len(finding.get('file', '').split('/')) if finding.get('file') else 0,
            'filename_length': len(finding.get('file', '').split('/')[-1]) if finding.get('file') else 0,
            'is_test_file': 'test' in finding.get('file', '').lower(),
            'is_crypto_library': any(lib in finding.get('file', '').lower() for lib in ['crypto', 'ssl', 'tls', 'hash']),
            'is_low_level': finding.get('file', '').endswith(('.c', '.cpp', '.h', '.hpp')),
            'pattern_complexity': len(finding.get('pattern', '')),
            'has_function_call': '(' in finding.get('pattern', ''),
            'has_import_statement': 'import' in finding.get('pattern', '').lower(),
            'is_hash_algorithm': finding.get('crypto_type', '') == 'hash',
            'is_symmetric_crypto': finding.get('crypto_type', '') == 'symmetric',
            'is_asymmetric_crypto': finding.get('crypto_type', '') == 'asymmetric',
            'is_legacy_algorithm': finding.get('algorithm', '') in ['md5', 'sha1', 'des', 'rc4'],
            'is_modern_algorithm': finding.get('algorithm', '') in ['sha256', 'sha512', 'aes', 'chacha20'],
            'is_critical': finding.get('severity', '') == 'critical',
            'is_high': finding.get('severity', '') == 'high',
            'is_medium': finding.get('severity', '') == 'medium',
            'is_low': finding.get('severity', '') == 'low',
            'is_info': finding.get('severity', '') == 'info',
            'is_c_cpp': finding.get('language', '') in ['c', 'cpp', 'c++'],
            'is_high_level_lang': finding.get('language', '') in ['python', 'java', 'javascript', 'go'],
            'is_systems_lang': finding.get('language', '') in ['c', 'cpp', 'rust', 'go'],
        }
        return features
    
    def encode_features(self, features_dict):
        """Encode categorical features using trained encoders."""
        df = pd.DataFrame([features_dict])
        
        for col, encoder in self.encoders.items():
            if col in df.columns:
                df[col] = df[col].fillna('unknown')
                # Handle unseen categories
                try:
                    df[col] = encoder.transform(df[col])
                except ValueError:
                    # Handle unseen categories by using the first class
                    if hasattr(encoder, 'classes_') and len(encoder.classes_) > 0:
                        df[col] = 0  # Use first class index
                    else:
                        df[col] = 0
        
        df = df.fillna(0)
        return df
    
    def predict(self, finding):
        """Make predictions for a single finding."""
        features = self.extract_features(finding)
        encoded_features = self.encode_features(features)
        
        predictions = {}
        
        # False positive prediction
        if 'false_positive_detector' in self.models:
            fp_prob = self.models['false_positive_detector'].predict_proba(encoded_features)[0]
            predictions['is_false_positive'] = bool(fp_prob[0] > 0.5)  # 0 = false positive
            predictions['false_positive_confidence'] = float(max(fp_prob))
        
        # Confidence level prediction  
        if 'confidence_predictor' in self.models:
            conf_pred = self.models['confidence_predictor'].predict(encoded_features)[0]
            predictions['confidence_level'] = str(conf_pred)
        
        # Severity prediction
        if 'severity_classifier' in self.models:
            sev_pred = self.models['severity_classifier'].predict(encoded_features)[0]
            predictions['adjusted_severity'] = str(sev_pred)
        
        return predictions

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 predict.py <finding_json>")
        print("Example: echo '{\"algorithm\": \"md5\"}' | python3 predict.py -")
        sys.exit(1)
    
    try:
        if sys.argv[1] == '-':
            # Read from stdin
            finding_json = sys.stdin.read()
        else:
            # Read from argument
            finding_json = sys.argv[1]
        
        finding = json.loads(finding_json)
        predictor = MLPredictor()
        prediction = predictor.predict(finding)
        print(json.dumps(prediction, indent=2))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

if __name__ == "__main__":
    main() 