#!/usr/bin/env python3
"""
Convert trained ML models to Go-compatible format
Exports model parameters and creates Go integration code
"""

import json
import joblib
import numpy as np
import os
from typing import Dict, Any, List

class ModelToGoConverter:
    """Converts scikit-learn models to Go-compatible format."""
    
    def __init__(self, models_dir: str = "trained_models"):
        self.models_dir = models_dir
        self.go_models = {}
        
    def convert_logistic_regression(self, model_file: str) -> Dict[str, Any]:
        """Convert logistic regression model to Go format."""
        model = joblib.load(os.path.join(self.models_dir, model_file))
        
        return {
            "model_type": "logistic_regression",
            "coefficients": model.coef_[0].tolist(),
            "intercept": float(model.intercept_[0]),
            "classes": model.classes_.tolist() if hasattr(model, 'classes_') else [0, 1],
            "n_features": len(model.coef_[0]),
        }
    
    def convert_random_forest(self, model_file: str) -> Dict[str, Any]:
        """Convert random forest model to simplified Go format."""
        model = joblib.load(os.path.join(self.models_dir, model_file))
        
        # For simplicity, we'll extract feature importances and create decision rules
        trees_data = []
        
        # Extract a simplified representation of the first few trees
        for i, tree in enumerate(model.estimators_[:5]):  # Use first 5 trees for simplicity
            tree_data = {
                "tree_id": i,
                "feature_importances": tree.feature_importances_.tolist(),
                "n_features": tree.n_features_in_,
            }
            trees_data.append(tree_data)
        
        return {
            "model_type": "random_forest",
            "n_estimators": len(trees_data),
            "feature_importances": model.feature_importances_.tolist(),
            "classes": model.classes_.tolist() if hasattr(model, 'classes_') else [],
            "trees": trees_data,
            "n_features": model.n_features_in_,
        }
    
    def convert_label_encoder(self, encoder_file: str) -> Dict[str, Any]:
        """Convert label encoder to Go format."""
        encoder = joblib.load(os.path.join(self.models_dir, encoder_file))
        
        # Create mapping from labels to integers
        label_to_int = {}
        int_to_label = {}
        
        for i, label in enumerate(encoder.classes_):
            label_to_int[str(label)] = i
            int_to_label[i] = str(label)
        
        return {
            "encoder_type": "label_encoder",
            "label_to_int": label_to_int,
            "int_to_label": int_to_label,
            "n_classes": len(encoder.classes_),
        }
    
    def load_training_report(self) -> Dict[str, Any]:
        """Load training report for metadata."""
        report_file = os.path.join(self.models_dir, "ai_enhanced_training_report.json")
        if os.path.exists(report_file):
            with open(report_file, 'r') as f:
                return json.load(f)
        return {}
    
    def convert_all_models(self) -> Dict[str, Any]:
        """Convert all models to Go format."""
        
        # Load training report
        training_report = self.load_training_report()
        
        go_models = {
            "metadata": {
                "training_timestamp": training_report.get("training_timestamp", ""),
                "data_summary": training_report.get("data_summary", {}),
                "feature_columns": training_report.get("feature_engineering", {}).get("feature_columns", []),
            },
            "models": {},
            "encoders": {},
        }
        
        # Convert models
        model_files = {
            "false_positive_detector": "false_positive_detector.joblib",
            "confidence_predictor": "confidence_predictor.joblib", 
            "severity_classifier": "severity_classifier.joblib",
        }
        
        for model_name, model_file in model_files.items():
            model_path = os.path.join(self.models_dir, model_file)
            if os.path.exists(model_path):
                try:
                    # Detect model type
                    model = joblib.load(model_path)
                    if hasattr(model, 'coef_'):  # Logistic Regression
                        go_models["models"][model_name] = self.convert_logistic_regression(model_file)
                    elif hasattr(model, 'estimators_'):  # Random Forest
                        go_models["models"][model_name] = self.convert_random_forest(model_file)
                    else:
                        print(f"⚠️  Unknown model type for {model_name}")
                    
                    print(f"✅ Converted {model_name}")
                except Exception as e:
                    print(f"❌ Failed to convert {model_name}: {e}")
        
        # Convert encoders
        encoder_files = [
            "algorithm_encoder.joblib",
            "severity_encoder.joblib", 
            "crypto_type_encoder.joblib",
            "language_encoder.joblib",
            "rule_id_encoder.joblib",
            "file_extension_encoder.joblib",
        ]
        
        for encoder_file in encoder_files:
            encoder_path = os.path.join(self.models_dir, encoder_file)
            if os.path.exists(encoder_path):
                try:
                    encoder_name = encoder_file.replace("_encoder.joblib", "")
                    go_models["encoders"][encoder_name] = self.convert_label_encoder(encoder_file)
                    print(f"✅ Converted {encoder_name} encoder")
                except Exception as e:
                    print(f"❌ Failed to convert {encoder_file}: {e}")
        
        return go_models
    
    def generate_go_code(self, go_models: Dict[str, Any]) -> str:
        """Generate Go code for the ML models."""
        
        go_code = '''package ml

import (
	"math"
	"strings"
)

// MLModels contains all converted ML models
type MLModels struct {
	FalsePositiveDetector *LogisticRegressionModel
	ConfidencePredictor   *RandomForestModel
	SeverityClassifier    *RandomForestModel
	Encoders             map[string]*LabelEncoder
}

// LogisticRegressionModel represents a logistic regression model
type LogisticRegressionModel struct {
	Coefficients []float64
	Intercept    float64
	Classes      []int
	NFeatures    int
}

// RandomForestModel represents a simplified random forest model
type RandomForestModel struct {
	FeatureImportances []float64
	Classes           []string
	NFeatures         int
	NEstimators       int
}

// LabelEncoder represents a label encoder
type LabelEncoder struct {
	LabelToInt map[string]int
	IntToLabel map[int]string
	NClasses   int
}

// Predict using logistic regression
func (lr *LogisticRegressionModel) Predict(features []float64) float64 {
	if len(features) != lr.NFeatures {
		return 0.0
	}
	
	// Calculate linear combination
	linearCombination := lr.Intercept
	for i, coef := range lr.Coefficients {
		if i < len(features) {
			linearCombination += coef * features[i]
		}
	}
	
	// Apply sigmoid function
	return 1.0 / (1.0 + math.Exp(-linearCombination))
}

// PredictClass using random forest (simplified)
func (rf *RandomForestModel) PredictClass(features []float64) string {
	if len(features) != rf.NFeatures || len(rf.Classes) == 0 {
		return "unknown"
	}
	
	// Simplified prediction based on feature importances
	score := 0.0
	for i, importance := range rf.FeatureImportances {
		if i < len(features) {
			score += importance * features[i]
		}
	}
	
	// Map score to class (simplified)
	if score > 0.5 {
		return rf.Classes[len(rf.Classes)-1] // Return highest class
	}
	return rf.Classes[0] // Return lowest class
}

// Encode converts a string label to integer
func (le *LabelEncoder) Encode(label string) int {
	if val, exists := le.LabelToInt[label]; exists {
		return val
	}
	return 0 // Default to 0 for unknown labels
}

// Decode converts an integer to string label
func (le *LabelEncoder) Decode(value int) string {
	if label, exists := le.IntToLabel[value]; exists {
		return label
	}
	return "unknown"
}

// NewMLModels creates a new MLModels instance with trained models
func NewMLModels() *MLModels {
	return &MLModels{
'''

        # Add false positive detector
        if "false_positive_detector" in go_models["models"]:
            fp_model = go_models["models"]["false_positive_detector"]
            coeffs = ', '.join([f"{c:.6f}" for c in fp_model["coefficients"]])
            go_code += f'''		FalsePositiveDetector: &LogisticRegressionModel{{
			Coefficients: []float64{{{coeffs}}},
			Intercept:    {fp_model["intercept"]:.6f},
			Classes:      []int{{{', '.join(map(str, fp_model["classes"]))}}},
			NFeatures:    {fp_model["n_features"]},
		}},
'''

        # Add confidence predictor
        if "confidence_predictor" in go_models["models"]:
            conf_model = go_models["models"]["confidence_predictor"]
            importances = ', '.join([f"{i:.6f}" for i in conf_model["feature_importances"]])
            classes = ', '.join([f'"{c}"' for c in conf_model["classes"]])
            go_code += f'''		ConfidencePredictor: &RandomForestModel{{
			FeatureImportances: []float64{{{importances}}},
			Classes:           []string{{{classes}}},
			NFeatures:         {conf_model["n_features"]},
			NEstimators:       {conf_model["n_estimators"]},
		}},
'''

        # Add severity classifier
        if "severity_classifier" in go_models["models"]:
            sev_model = go_models["models"]["severity_classifier"]
            importances = ', '.join([f"{i:.6f}" for i in sev_model["feature_importances"]])
            classes = ', '.join([f'"{c}"' for c in sev_model["classes"]])
            go_code += f'''		SeverityClassifier: &RandomForestModel{{
			FeatureImportances: []float64{{{importances}}},
			Classes:           []string{{{classes}}},
			NFeatures:         {sev_model["n_features"]},
			NEstimators:       {sev_model["n_estimators"]},
		}},
'''

        # Add encoders
        go_code += '''		Encoders: map[string]*LabelEncoder{
'''
        for encoder_name, encoder_data in go_models["encoders"].items():
            label_to_int = ', '.join([f'"{k}": {v}' for k, v in encoder_data["label_to_int"].items()])
            int_to_label = ', '.join([f'{k}: "{v}"' for k, v in encoder_data["int_to_label"].items()])
            go_code += f'''			"{encoder_name}": &LabelEncoder{{
				LabelToInt: map[string]int{{{label_to_int}}},
				IntToLabel: map[int]string{{{int_to_label}}},
				NClasses:   {encoder_data["n_classes"]},
			}},
'''

        go_code += '''		},
	}
}

// ExtractFeatures extracts features from a finding for ML prediction
func ExtractFeatures(finding map[string]interface{}, encoders map[string]*LabelEncoder) []float64 {
	features := make([]float64, 34) // Match the number of features from training
	
	// Helper function to get string value
	getString := func(key string) string {
		if val, ok := finding[key]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
		return "unknown"
	}
	
	// Helper function to get float value
	getFloat := func(key string) float64 {
		if val, ok := finding[key]; ok {
			if f, ok := val.(float64); ok {
				return f
			}
		}
		return 0.0
	}
	
	// Helper function to get bool as float
	getBool := func(condition bool) float64 {
		if condition {
			return 1.0
		}
		return 0.0
	}
	
	// Extract basic features (first 7 features are categorical, encoded)
	algorithm := getString("algorithm")
	severity := getString("severity") 
	cryptoType := getString("crypto_type")
	language := getString("language")
	ruleID := getString("rule_id")
	file := getString("file")
	
	// Encode categorical features
	features[0] = float64(encoders["algorithm"].Encode(algorithm))
	features[1] = float64(encoders["severity"].Encode(severity))
	features[2] = getFloat("confidence")
	features[3] = float64(encoders["crypto_type"].Encode(cryptoType))
	features[4] = float64(encoders["language"].Encode(language))
	features[5] = float64(encoders["rule_id"].Encode(ruleID))
	features[6] = getFloat("line")
	
	// File extension
	fileExt := "unknown"
	if file != "" && strings.Contains(file, ".") {
		parts := strings.Split(file, ".")
		fileExt = parts[len(parts)-1]
	}
	features[7] = float64(encoders["file_extension"].Encode(fileExt))
	
	// File path depth
	features[8] = float64(len(strings.Split(file, "/")))
	
	// Filename length
	features[9] = float64(len(file))
	
	// Boolean features (10-33)
	features[10] = getBool(strings.Contains(strings.ToLower(file), "test"))
	features[11] = getBool(strings.Contains(strings.ToLower(file), "crypto") || 
		strings.Contains(strings.ToLower(file), "ssl") || 
		strings.Contains(strings.ToLower(file), "tls") || 
		strings.Contains(strings.ToLower(file), "hash"))
	features[12] = getBool(strings.HasSuffix(file, ".c") || 
		strings.HasSuffix(file, ".cpp") || 
		strings.HasSuffix(file, ".h") || 
		strings.HasSuffix(file, ".hpp"))
	
	// Pattern analysis
	pattern := getString("pattern")
	features[13] = float64(len(pattern))
	features[14] = getBool(strings.Contains(pattern, "("))
	features[15] = getBool(strings.Contains(strings.ToLower(pattern), "import"))
	
	// Algorithm-specific features
	features[16] = getBool(cryptoType == "hash")
	features[17] = getBool(cryptoType == "symmetric")
	features[18] = getBool(cryptoType == "asymmetric")
	features[19] = getBool(algorithm == "md5" || algorithm == "sha1" || algorithm == "des" || algorithm == "rc4")
	features[20] = getBool(algorithm == "sha256" || algorithm == "sha512" || algorithm == "aes" || algorithm == "chacha20")
	
	// Severity features
	features[21] = getBool(severity == "critical")
	features[22] = getBool(severity == "high")
	features[23] = getBool(severity == "medium")
	features[24] = getBool(severity == "low")
	features[25] = getBool(severity == "info")
	
	// Language features
	features[26] = getBool(language == "c" || language == "cpp" || language == "c++")
	features[27] = getBool(language == "python" || language == "java" || language == "javascript" || language == "go")
	features[28] = getBool(language == "c" || language == "cpp" || language == "rust" || language == "go")
	
	// Additional features to match training
	features[29] = 0.0 // ai_is_valid (not available during prediction)
	features[30] = 0.0 // ai_confidence (not available during prediction)
	features[31] = 0.0 // ai_severity encoded (not available during prediction)
	features[32] = 0.0 // has_ai_evaluation (always false during prediction)
	features[33] = 0.0 // finding_id (not used for prediction)
	
	return features
}

// EnhanceFindingWithML enhances a finding with ML predictions
func EnhanceFindingWithML(finding map[string]interface{}, models *MLModels) map[string]interface{} {
	// Extract features
	features := ExtractFeatures(finding, models.Encoders)
	
	// Make predictions
	enhanced := make(map[string]interface{})
	for k, v := range finding {
		enhanced[k] = v
	}
	
	// False positive prediction
	if models.FalsePositiveDetector != nil {
		fpScore := models.FalsePositiveDetector.Predict(features)
		enhanced["ml_false_positive_score"] = fpScore
		enhanced["ml_is_likely_valid"] = fpScore > 0.5
	}
	
	// Confidence prediction
	if models.ConfidencePredictor != nil {
		confClass := models.ConfidencePredictor.PredictClass(features)
		enhanced["ml_confidence_class"] = confClass
	}
	
	// Severity prediction
	if models.SeverityClassifier != nil {
		sevClass := models.SeverityClassifier.PredictClass(features)
		enhanced["ml_predicted_severity"] = sevClass
	}
	
	return enhanced
}
'''

        return go_code
    
    def save_models_and_code(self, output_dir: str = "../internal/ml"):
        """Save converted models and generate Go code."""
        os.makedirs(output_dir, exist_ok=True)
        
        # Convert models
        print("🔄 Converting models to Go format...")
        go_models = self.convert_all_models()
        
        # Save JSON representation
        json_file = os.path.join(output_dir, "models.json")
        with open(json_file, 'w') as f:
            json.dump(go_models, f, indent=2)
        print(f"💾 Saved model data to {json_file}")
        
        # Generate Go code
        print("🔄 Generating Go code...")
        go_code = self.generate_go_code(go_models)
        
        # Save Go code
        go_file = os.path.join(output_dir, "embedded_models.go")
        with open(go_file, 'w') as f:
            f.write(go_code)
        print(f"💾 Saved Go code to {go_file}")
        
        print("\n✅ Model conversion complete!")
        print(f"📊 Converted {len(go_models['models'])} models and {len(go_models['encoders'])} encoders")
        print(f"📁 Files saved to: {output_dir}/")
        print("   - models.json (model data)")
        print("   - embedded_models.go (Go integration code)")
        
        return go_models

def main():
    """Main function to convert models."""
    converter = ModelToGoConverter()
    converter.save_models_and_code()

if __name__ == "__main__":
    main() 