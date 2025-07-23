#!/usr/bin/env python3
"""
combine_results.py - Combine all scan results into a single file for AI evaluation
Usage: python3 combine_results.py [results_dir] [output_file]
"""

import json
import glob
import os
import sys
from typing import List, Dict, Any

def combine_scan_results(results_dir: str = "results", output_file: str = "../combined_scan_results.json") -> None:
    """
    Combine all scan results from individual JSON files into a single file.
    
    Args:
        results_dir: Directory containing individual scan result files
        output_file: Output file path for combined results
    """
    
    # Get all scan result files
    pattern = os.path.join(results_dir, "*_scan_results.json")
    result_files = glob.glob(pattern)
    
    if not result_files:
        print(f"❌ No scan result files found in {results_dir}")
        print(f"   Looking for pattern: {pattern}")
        return
    
    print(f"📄 Found {len(result_files)} scan result files")
    
    # Statistics tracking
    all_findings = []
    successful_files = 0
    total_repos = 0
    repo_stats = []
    
    # Process each file
    for file_path in sorted(result_files):
        total_repos += 1
        repo_name = os.path.basename(file_path).replace('_scan_results.json', '')
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            findings = []
            
            # Extract findings based on file structure
            if isinstance(data, dict) and 'crypto_findings' in data:
                findings = data['crypto_findings'] or []
            elif isinstance(data, dict) and 'findings' in data:
                findings = data['findings'] or []
            elif isinstance(data, dict) and 'results' in data:
                findings = data['results'] or []
            elif isinstance(data, list):
                findings = data
            
            # Add findings to combined list
            if findings:
                all_findings.extend(findings)
                successful_files += 1
                
                # Track repository statistics
                repo_stats.append({
                    'repo': repo_name,
                    'findings': len(findings),
                    'file_size': os.path.getsize(file_path)
                })
                
                # Print progress for significant repositories
                if len(findings) >= 100:
                    print(f"  🔥 {repo_name}: {len(findings)} findings")
                elif len(findings) >= 10:
                    print(f"  📊 {repo_name}: {len(findings)} findings")
                elif len(findings) > 0:
                    print(f"  📄 {repo_name}: {len(findings)} findings")
            
        except json.JSONDecodeError as e:
            print(f"  ⚠️  JSON decode error in {repo_name}: {e}")
        except Exception as e:
            print(f"  ⚠️  Error reading {repo_name}: {e}")
    
    # Print comprehensive statistics
    print(f"\n📈 Combined Results Summary:")
    print(f"  - Total repositories processed: {total_repos}")
    print(f"  - Repositories with findings: {successful_files}")
    print(f"  - Total findings collected: {len(all_findings)}")
    
    if repo_stats:
        # Sort by findings count
        repo_stats.sort(key=lambda x: x['findings'], reverse=True)
        
        print(f"\n🏆 Top 10 Repositories by Findings:")
        for i, stat in enumerate(repo_stats[:10], 1):
            print(f"  {i:2d}. {stat['repo']}: {stat['findings']} findings")
        
        # Algorithm distribution analysis
        print(f"\n🔍 Quick Algorithm Analysis:")
        algorithm_counts = {}
        for finding in all_findings[:1000]:  # Sample first 1000 for quick analysis
            if isinstance(finding, dict) and 'algorithm' in finding:
                alg = finding['algorithm']
                if alg:
                    algorithm_counts[alg] = algorithm_counts.get(alg, 0) + 1
        
        if algorithm_counts:
            top_algorithms = sorted(algorithm_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            for alg, count in top_algorithms:
                print(f"  - {alg}: {count} findings")
    
    # Save combined results
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(all_findings, f, indent=2, ensure_ascii=False)
        
        file_size_mb = os.path.getsize(output_file) / (1024 * 1024)
        print(f"\n✅ Combined results saved to: {output_file}")
        print(f"   File size: {file_size_mb:.1f} MB")
        print(f"\n🚀 Ready for AI evaluation with:")
        print(f"   ./build/pqswitch ai-evaluate {os.path.basename(output_file)} --api-key YOUR_KEY")
        
        # Cost estimation
        if len(all_findings) > 0:
            print(f"\n💰 AI Evaluation Cost Estimates:")
            for max_findings in [100, 500, 1000, 5000]:
                if len(all_findings) >= max_findings:
                    cost = max_findings * 0.0001  # Rough estimate
                    print(f"   - {max_findings} findings: ~${cost:.3f}")
        
    except Exception as e:
        print(f"❌ Error saving combined results: {e}")

def main():
    """Main function to handle command line arguments."""
    
    # Parse command line arguments
    results_dir = "results"
    output_file = "../combined_scan_results.json"
    
    if len(sys.argv) > 1:
        results_dir = sys.argv[1]
    if len(sys.argv) > 2:
        output_file = sys.argv[2]
    
    print(f"🔗 Combining scan results from: {results_dir}")
    print(f"📝 Output file: {output_file}")
    
    # Check if results directory exists
    if not os.path.exists(results_dir):
        print(f"❌ Results directory not found: {results_dir}")
        print(f"   Make sure to run systematic_scan_parallel.sh first")
        sys.exit(1)
    
    # Combine results
    combine_scan_results(results_dir, output_file)

if __name__ == "__main__":
    main() 