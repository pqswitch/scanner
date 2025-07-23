#!/usr/bin/env python3
"""
analyze_results.py - Analyze PQSwitch scan results for ML training
Comprehensive analysis of crypto findings across multiple repositories
"""

import json
import sys
import os
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional
import statistics
from datetime import datetime

def load_scan_results(file_path: str) -> Optional[Dict[str, Any]]:
    """Load and validate scan results from JSON file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Validate required fields - but be more lenient
        if 'crypto_findings' not in data:
            print(f"⚠️  Warning: No crypto_findings in {file_path}, creating empty list")
            data['crypto_findings'] = []
        
        # Ensure crypto_findings is a list, not None
        if data['crypto_findings'] is None:
            data['crypto_findings'] = []
            
        return data
    except json.JSONDecodeError as e:
        print(f"❌ JSON decode error in {file_path}: {e}")
        return None
    except Exception as e:
        print(f"❌ Error loading {file_path}: {e}")
        return None

def extract_finding_features(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Extract features from a crypto finding for ML analysis."""
    features = {
        'algorithm': finding.get('algorithm', 'unknown'),
        'severity': finding.get('severity', 'unknown'),
        'confidence': finding.get('confidence', 0.0),
        'crypto_type': finding.get('crypto_type', 'unknown'),
        'language': finding.get('language', 'unknown'),
        'file_type': finding.get('file', '').split('.')[-1] if finding.get('file') else 'unknown',
        'rule_id': finding.get('rule_id', 'unknown'),
        'line_number': finding.get('line', 0),
        'context_type': 'unknown',  # Will be enhanced with context analysis
        'implementation_level': 'unknown',  # High-level API vs low-level implementation
        'library_context': False,  # Whether this is in a crypto library vs application
        'test_context': False,  # Whether this is in test code
    }
    
    # Enhanced context analysis
    file_path = finding.get('file', '').lower()
    if file_path:
        # Test context detection
        if any(test_indicator in file_path for test_indicator in ['test', 'spec', 'mock', 'fixture']):
            features['test_context'] = True
            features['context_type'] = 'test'
        
        # Library context detection
        elif any(lib_indicator in file_path for lib_indicator in ['crypto', 'ssl', 'tls', 'hash', 'cipher']):
            features['library_context'] = True
            features['context_type'] = 'library'
        
        # Implementation level detection
        if any(low_level in file_path for low_level in ['.c', '.cpp', '.h', '.hpp', '.s', '.asm']):
            features['implementation_level'] = 'low_level'
        else:
            features['implementation_level'] = 'high_level'
    
    return features

def analyze_repository_findings(repo_name: str, scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze findings from a single repository."""
    findings = scan_data.get('crypto_findings', [])
    
    # Handle None case - some scan results may have None instead of empty list
    if findings is None:
        findings = []
    
    analysis = {
        'repo_name': repo_name,
        'total_findings': len(findings),
        'severity_distribution': Counter(),
        'algorithm_distribution': Counter(),
        'confidence_distribution': {'high': 0, 'medium': 0, 'low': 0},
        'language_distribution': Counter(),
        'crypto_type_distribution': Counter(),
        'context_analysis': {
            'test_findings': 0,
            'library_findings': 0,
            'application_findings': 0,
            'low_level_findings': 0,
            'high_level_findings': 0,
        },
        'confidence_stats': {
            'mean': 0.0,
            'median': 0.0,
            'std_dev': 0.0,
            'min': 0.0,
            'max': 0.0,
        },
        'quality_metrics': {
            'high_confidence_findings': 0,  # >= 0.8
            'medium_confidence_findings': 0,  # 0.5 - 0.8
            'low_confidence_findings': 0,   # < 0.5
        },
        'findings_by_severity': defaultdict(list),
        'top_algorithms': [],
        'scan_metadata': scan_data.get('scan_info', {}),
    }
    
    if not findings:
        return analysis
    
    # Process each finding
    confidences = []
    for finding in findings:
        features = extract_finding_features(finding)
        
        # Update distributions
        analysis['severity_distribution'][features['severity']] += 1
        analysis['algorithm_distribution'][features['algorithm']] += 1
        analysis['language_distribution'][features['language']] += 1
        analysis['crypto_type_distribution'][features['crypto_type']] += 1
        
        # Confidence analysis
        confidence = features['confidence']
        confidences.append(confidence)
        
        if confidence >= 0.8:
            analysis['confidence_distribution']['high'] += 1
            analysis['quality_metrics']['high_confidence_findings'] += 1
        elif confidence >= 0.5:
            analysis['confidence_distribution']['medium'] += 1
            analysis['quality_metrics']['medium_confidence_findings'] += 1
        else:
            analysis['confidence_distribution']['low'] += 1
            analysis['quality_metrics']['low_confidence_findings'] += 1
        
        # Context analysis
        if features['test_context']:
            analysis['context_analysis']['test_findings'] += 1
        elif features['library_context']:
            analysis['context_analysis']['library_findings'] += 1
        else:
            analysis['context_analysis']['application_findings'] += 1
        
        if features['implementation_level'] == 'low_level':
            analysis['context_analysis']['low_level_findings'] += 1
        else:
            analysis['context_analysis']['high_level_findings'] += 1
        
        # Group findings by severity for detailed analysis
        analysis['findings_by_severity'][features['severity']].append(finding)
    
    # Calculate confidence statistics
    if confidences:
        analysis['confidence_stats'] = {
            'mean': statistics.mean(confidences),
            'median': statistics.median(confidences),
            'std_dev': statistics.stdev(confidences) if len(confidences) > 1 else 0.0,
            'min': min(confidences),
            'max': max(confidences),
        }
    
    # Top algorithms (sorted by frequency)
    analysis['top_algorithms'] = [
        {'algorithm': algo, 'count': count} 
        for algo, count in analysis['algorithm_distribution'].most_common(10)
    ]
    
    return analysis

def generate_comprehensive_analysis(all_analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate comprehensive analysis across all repositories."""
    
    # Aggregate statistics
    total_findings = sum(analysis['total_findings'] for analysis in all_analyses)
    total_repos = len(all_analyses)
    
    # Aggregate distributions
    combined_severity = Counter()
    combined_algorithm = Counter()
    combined_language = Counter()
    combined_crypto_type = Counter()
    combined_context = defaultdict(int)
    
    all_confidences = []
    quality_totals = defaultdict(int)
    
    for analysis in all_analyses:
        combined_severity.update(analysis['severity_distribution'])
        combined_algorithm.update(analysis['algorithm_distribution'])
        combined_language.update(analysis['language_distribution'])
        combined_crypto_type.update(analysis['crypto_type_distribution'])
        
        for context_type, count in analysis['context_analysis'].items():
            combined_context[context_type] += count
        
        # Collect all confidence values
        findings_by_sev = analysis.get('findings_by_severity', {})
        if findings_by_sev:
            for finding_list in findings_by_sev.values():
                if isinstance(finding_list, list):
                    for f in finding_list:
                        if isinstance(f, dict):
                            conf = f.get('confidence', 0.0)
                            if conf > 0:
                                all_confidences.append(conf)
        
        for metric, value in analysis['quality_metrics'].items():
            quality_totals[metric] += value
    
    # Calculate global confidence statistics
    global_confidence_stats = {}
    if all_confidences:
        global_confidence_stats = {
            'mean': statistics.mean(all_confidences),
            'median': statistics.median(all_confidences),
            'std_dev': statistics.stdev(all_confidences) if len(all_confidences) > 1 else 0.0,
            'min': min(all_confidences),
            'max': max(all_confidences),
        }
    
    # Repository rankings
    repo_rankings = {
        'by_total_findings': sorted(all_analyses, key=lambda x: x['total_findings'], reverse=True)[:10],
        'by_high_confidence': sorted(all_analyses, key=lambda x: x['quality_metrics']['high_confidence_findings'], reverse=True)[:10],
        'by_avg_confidence': sorted(all_analyses, key=lambda x: x['confidence_stats']['mean'], reverse=True)[:10],
    }
    
    # ML Training Suitability Analysis
    ml_suitability = {
        'total_training_samples': total_findings,
        'high_quality_samples': quality_totals['high_confidence_findings'],
        'diverse_algorithms': len(combined_algorithm),
        'diverse_languages': len(combined_language),
        'context_diversity': {
            'test_ratio': combined_context['test_findings'] / total_findings if total_findings > 0 else 0,
            'library_ratio': combined_context['library_findings'] / total_findings if total_findings > 0 else 0,
            'application_ratio': combined_context['application_findings'] / total_findings if total_findings > 0 else 0,
        },
        'confidence_distribution': {
            'high_confidence_ratio': quality_totals['high_confidence_findings'] / total_findings if total_findings > 0 else 0,
            'medium_confidence_ratio': quality_totals['medium_confidence_findings'] / total_findings if total_findings > 0 else 0,
            'low_confidence_ratio': quality_totals['low_confidence_findings'] / total_findings if total_findings > 0 else 0,
        },
        'recommendations': []
    }
    
    # Generate ML training recommendations
    if ml_suitability['total_training_samples'] < 1000:
        ml_suitability['recommendations'].append("Consider scanning more repositories to reach 1000+ training samples")
    
    if ml_suitability['high_quality_samples'] < 100:
        ml_suitability['recommendations'].append("Increase high-confidence samples for better model training")
    
    if ml_suitability['diverse_algorithms'] < 20:
        ml_suitability['recommendations'].append("Scan more diverse crypto libraries to increase algorithm coverage")
    
    if ml_suitability['context_diversity']['test_ratio'] > 0.5:
        ml_suitability['recommendations'].append("High ratio of test findings - consider filtering or balancing dataset")
    
    return {
        'analysis_timestamp': datetime.now().isoformat(),
        'summary': {
            'total_repositories': total_repos,
            'total_findings': total_findings,
            'avg_findings_per_repo': total_findings / total_repos if total_repos > 0 else 0,
        },
        'distributions': {
            'severity': dict(combined_severity),
            'algorithm': dict(combined_algorithm.most_common(20)),
            'language': dict(combined_language),
            'crypto_type': dict(combined_crypto_type),
            'context': dict(combined_context),
        },
        'confidence_analysis': global_confidence_stats,
        'quality_metrics': dict(quality_totals),
        'repository_rankings': repo_rankings,
        'ml_training_suitability': ml_suitability,
        'detailed_repository_analyses': all_analyses,
    }

def main():
    """Main analysis function."""
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_results.py <scan_result_files...> [output_file]")
        print("Example: python3 analyze_results.py results/*_scan_results.json ml_analysis.json")
        sys.exit(1)
    
    input_files = sys.argv[1:-1] if len(sys.argv) > 2 else sys.argv[1:]
    output_file = sys.argv[-1] if len(sys.argv) > 2 and not sys.argv[-1].endswith('.json') else None
    
    if not output_file:
        output_file = "ml_training_analysis.json"
        input_files = sys.argv[1:]
    
    print(f"📊 Analyzing {len(input_files)} scan result files...")
    print(f"📁 Output will be saved to: {output_file}")
    
    # Load and analyze all scan results
    all_analyses = []
    loaded_files = 0
    
    for file_path in input_files:
        if not os.path.exists(file_path):
            print(f"⚠️  File not found: {file_path}")
            continue
        
        scan_data = load_scan_results(file_path)
        if scan_data is None:
            continue
        
        repo_name = Path(file_path).stem.replace('_scan_results', '')
        analysis = analyze_repository_findings(repo_name, scan_data)
        all_analyses.append(analysis)
        loaded_files += 1
        
        if loaded_files % 10 == 0:
            print(f"📈 Processed {loaded_files} files...")
    
    if not all_analyses:
        print("❌ No valid scan results found")
        sys.exit(1)
    
    print(f"✅ Successfully analyzed {len(all_analyses)} repositories")
    
    # Generate comprehensive analysis
    print("🧠 Generating comprehensive ML training analysis...")
    comprehensive_analysis = generate_comprehensive_analysis(all_analyses)
    
    # Save results
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(comprehensive_analysis, f, indent=2, ensure_ascii=False)
        print(f"✅ Analysis saved to {output_file}")
    except Exception as e:
        print(f"❌ Error saving analysis: {e}")
        sys.exit(1)
    
    # Print summary
    summary = comprehensive_analysis['summary']
    ml_suit = comprehensive_analysis['ml_training_suitability']
    
    print("\n📊 ML Training Dataset Analysis Summary:")
    print(f"   📁 Repositories: {summary['total_repositories']}")
    print(f"   🔍 Total Findings: {summary['total_findings']}")
    print(f"   📈 Avg per Repo: {summary['avg_findings_per_repo']:.1f}")
    print(f"   🎯 High Confidence: {ml_suit['high_quality_samples']} ({ml_suit['confidence_distribution']['high_confidence_ratio']:.1%})")
    print(f"   🧬 Algorithm Diversity: {ml_suit['diverse_algorithms']} different algorithms")
    print(f"   💻 Language Diversity: {ml_suit['diverse_languages']} programming languages")
    
    print("\n🏆 Top Algorithms:")
    for algo, count in list(comprehensive_analysis['distributions']['algorithm'].items())[:5]:
        print(f"   {algo}: {count} findings")
    
    print("\n🎯 ML Training Recommendations:")
    for rec in ml_suit['recommendations']:
        print(f"   • {rec}")
    
    if not ml_suit['recommendations']:
        print("   ✅ Dataset is suitable for ML training!")

if __name__ == "__main__":
    main() 