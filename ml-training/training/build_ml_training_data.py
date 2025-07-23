#!/usr/bin/env python3
"""
Build ML training data from scan results.
"""

import argparse
import json
import os
from pathlib import Path


def build_training_data(results_dir, output_dir):
    """Build training data from scan results."""
    results_path = Path(results_dir)
    output_path = Path(output_dir)
    
    # Create output directory
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Find all JSON files in results directory
    json_files = list(results_path.glob("*.json"))
    
    if not json_files:
        print(f"No JSON files found in {results_dir}")
        return False
    
    training_data = []
    
    for json_file in json_files:
        print(f"Processing {json_file}")
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
                
            # Extract findings for training
            if 'findings' in data:
                training_data.extend(data['findings'])
            elif isinstance(data, list):
                training_data.extend(data)
                
        except Exception as e:
            print(f"Error processing {json_file}: {e}")
            continue
    
    # Save training data
    training_file = output_path / "training_data.json"
    with open(training_file, 'w') as f:
        json.dump(training_data, f, indent=2)
    
    print(f"Built training data with {len(training_data)} samples")
    print(f"Saved to {training_file}")
    
    return True


def main():
    parser = argparse.ArgumentParser(description='Build ML training data')
    parser.add_argument('--results-dir', required=True, help='Directory containing scan results')
    parser.add_argument('--output-dir', required=True, help='Output directory for training data')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        print(f"Building training data from {args.results_dir}")
        print(f"Output directory: {args.output_dir}")
    
    success = build_training_data(args.results_dir, args.output_dir)
    
    if not success:
        print("Failed to build training data")
        exit(1)
    
    print("Training data built successfully")


if __name__ == '__main__':
    main() 