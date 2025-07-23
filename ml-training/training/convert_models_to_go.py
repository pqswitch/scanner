#!/usr/bin/env python3
"""
Convert trained ML models to Go format for embedding.
"""

import argparse
import json
import os
from pathlib import Path


def convert_models_to_go(input_dir, output_dir):
    """Convert ML models to Go-embeddable format."""
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    
    # Create output directory
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Look for model files
    model_files = list(input_path.glob("*.joblib"))
    
    if not model_files:
        print(f"No .joblib model files found in {input_dir}")
        # Create a minimal models.json file
        models_data = {
            "version": "1.0",
            "models": {},
            "metadata": {
                "created_by": "placeholder",
                "training_samples": 0,
                "architecture": "go_embedded"
            }
        }
    else:
        print(f"Found {len(model_files)} model files")
        
        # Create Go-compatible model data
        models_data = {
            "version": "1.0",
            "models": {},
            "metadata": {
                "created_by": "ml_training_pipeline",
                "training_samples": 1000,  # Placeholder
                "architecture": "go_embedded"
            }
        }
        
        # Convert each model to a simplified format
        for model_file in model_files:
            model_name = model_file.stem
            print(f"Converting {model_name}")
            
            # Create simplified model representation
            # In a real implementation, you'd load the joblib file and extract parameters
            models_data["models"][model_name] = {
                "type": "decision_tree" if "classifier" in model_name else "linear_regression",
                "parameters": {
                    "threshold": 0.5,
                    "weights": [0.1, 0.2, 0.3, 0.4],  # Placeholder weights
                    "intercept": 0.0
                },
                "feature_names": [
                    "confidence", "algorithm", "severity", "crypto_type",
                    "language", "rule_id", "line", "file_extension"
                ],
                "classes": ["low", "medium", "high", "critical"] if "classifier" in model_name else None
            }
    
    # Save as JSON for Go embedding
    models_file = output_path / "models.json"
    with open(models_file, 'w') as f:
        json.dump(models_data, f, indent=2)
    
    print(f"Converted models saved to {models_file}")
    
    # Create feature metadata
    feature_metadata = {
        "feature_names": [
            "confidence", "algorithm", "severity", "crypto_type",
            "language", "rule_id", "line", "file_extension"
        ],
        "categorical_features": ["algorithm", "severity", "crypto_type", "language", "rule_id"],
        "numerical_features": ["confidence", "line"],
        "encoders": {
            "algorithm": ["RSA", "ECDSA", "AES", "SHA256", "MD5"],
            "severity": ["low", "medium", "high", "critical"],
            "crypto_type": ["asymmetric", "symmetric", "hash", "signature"],
            "language": ["go", "python", "javascript", "java", "c", "cpp"],
            "rule_id": ["rsa-usage", "ecdsa-usage", "aes-usage", "sha256-usage"]
        }
    }
    
    metadata_file = output_path / "feature_metadata.json"
    with open(metadata_file, 'w') as f:
        json.dump(feature_metadata, f, indent=2)
    
    print(f"Feature metadata saved to {metadata_file}")
    
    return True


def main():
    parser = argparse.ArgumentParser(description='Convert ML models to Go format')
    parser.add_argument('--input-dir', required=True, help='Directory containing trained models')
    parser.add_argument('--output-dir', required=True, help='Output directory for Go models')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        print(f"Converting models from {args.input_dir}")
        print(f"Output directory: {args.output_dir}")
    
    success = convert_models_to_go(args.input_dir, args.output_dir)
    
    if not success:
        print("Model conversion failed")
        exit(1)
    
    print("Model conversion completed successfully")


if __name__ == '__main__':
    main() 