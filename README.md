# PQSwitch Scanner

A comprehensive **post-quantum cryptography vulnerability scanner** designed to identify and assess cryptographic implementations that may be vulnerable to quantum computing attacks.

[![CI](https://github.com/pqswitch/scanner/workflows/CI/badge.svg)](https://github.com/pqswitch/scanner/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/pqswitch/scanner)](https://goreportcard.com/report/github.com/pqswitch/scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **🚨 The quantum threat is real.** Current RSA, ECC, and other crypto algorithms will be broken by quantum computers. This scanner helps you identify vulnerable code **before** it's too late.

## 🚀 Quick Start

### Installation Options

#### Option 1: Download Pre-built Binary

```bash
# Download latest release
curl -L https://github.com/pqswitch/scanner/releases/latest/download/pqswitch-linux-amd64 -o pqswitch
chmod +x pqswitch
sudo mv pqswitch /usr/local/bin/
```

#### Option 2: Install via Go

```bash
go install github.com/pqswitch/scanner/cmd/pqswitch@latest
```

#### Option 3: Docker (Recommended for CI/CD)

```bash
# Pull the latest image
docker pull pqswitch/scanner:latest

# Quick scan
docker run --rm -v $(pwd):/workspace pqswitch/scanner:latest scan /workspace
```

### Basic Usage

```bash
# Scan current directory
pqswitch scan .

# Scan with JSON output
pqswitch scan . --output json --output-file results.json

# Enhanced scan with ML confidence scoring
pqswitch enhanced-scan . --enable-ml --min-confidence 0.3

# Layered scan (most comprehensive)
pqswitch layered-scan . --enable-l2 --enable-ml --min-confidence 0.3

# SARIF output for GitHub Security tab
pqswitch scan . --output sarif --output-file security.sarif
```

## 🎯 Features

### ✨ **Core Capabilities**

- **🔍 Multi-language Support**: Go, C/C++, Java, Python, JavaScript, Rust, C#, Swift, Ruby
- **🎯 Comprehensive Detection**: RSA, ECC, AES, DES, MD5, SHA-1, and quantum-vulnerable algorithms
- **🧠 Context-Aware Analysis**: Distinguishes between legitimate protocol implementations and vulnerabilities
- **📊 Multiple Output Formats**: JSON, SARIF, human-readable text
- **🚀 CI/CD Ready**: GitHub Actions, Docker, exit codes for build pipelines

### 🔬 **Detection Layers (L0, L1, L2)**

#### **L0: Regex Pre-filtering** (⚡ Ultra Fast)
```bash
pqswitch scan . --layer l0
```
- ~1000x faster than AST analysis
- Pattern-based detection using regex
- Perfect for CI/CD pipelines and quick scans
- **Use case**: First-pass filtering, large codebases

#### **L1: AST-based Analysis** (🎯 Accurate)
```bash
pqswitch scan . --layer l1  # Default mode
```
- Language-specific Abstract Syntax Tree parsing
- Structured pattern matching
- Significantly reduces false positives
- **Use case**: Standard security scans, development workflow

#### **L2: Data Flow Analysis** (🔬 Comprehensive)
```bash
pqswitch layered-scan . --enable-l2
```
- Inter-procedural analysis tracking crypto data flow
- Most thorough but resource-intensive
- Detects complex crypto usage patterns
- **Use case**: Security audits, compliance reviews

### 🤖 **ML-Enhanced Detection**

```bash
pqswitch enhanced-scan . --enable-ml --min-confidence 0.3
```

- **Intelligent Confidence Scoring**: ML models assess finding reliability
- **Smart Prioritization**: Focus on high-confidence vulnerabilities first
- **Continuous Learning**: Models improve with more training data
- **AI-Powered Evaluation**: OpenAI integration for complex analysis

## 🐳 Docker Image

We provide a **comprehensive Docker image** optimized for all use cases:

### **PQSwitch Scanner** (~60MB) - Complete crypto security scanner
```bash
# Pull the latest image
docker pull pqswitch/scanner:latest

# Quick crypto scan
docker run --rm -v $(pwd):/workspace pqswitch/scanner:latest scan /workspace

# Enhanced scan with ML confidence scoring
docker run --rm -v $(pwd):/workspace pqswitch/scanner:latest enhanced-scan --enable-ml /workspace

# Comprehensive layered scan
docker run --rm -v $(pwd):/workspace pqswitch/scanner:latest layered-scan --enable-l2 --enable-ml /workspace
```

**What's included:**
- ✅ **Complete crypto detection**: All scan modes (L0, L1, L2, ML-enhanced)
- ✅ **Multi-language support**: Go, Java, Python, JavaScript, C/C++, Rust, and more
- ✅ **Cloud integration**: AWS CLI for S3 uploads and cloud workflows
- ✅ **Essential tools**: Git, Bash, cURL for repository analysis
- ✅ **Optimized size**: Only ~60MB with all necessary components
- ✅ **Multi-platform**: Linux AMD64 and ARM64 support

**Perfect for:**
- 🚀 **CI/CD pipelines**: Fast, reliable crypto vulnerability detection
- 🏢 **Enterprise workflows**: Complete scanning with cloud integration
- 🔍 **Security audits**: All detection layers and ML confidence scoring
- ⚡ **Local development**: Lightweight but comprehensive analysis

## 📖 Comprehensive Usage Guide

### 🎯 **Scan Modes for Different Use Cases**

#### Frontend Applications
```bash
# Quick React/Vue/Angular scan
pqswitch scan . --include "*.js,*.ts,*.jsx,*.tsx" --min-confidence 0.3

# Enhanced scan with ML
pqswitch enhanced-scan . --enable-ml --include "*.js,*.ts" --layer l1
```

#### Backend Services
```bash
# Comprehensive server application scan
pqswitch layered-scan . --enable-l2 --enable-ml --min-confidence 0.3

# Focus on crypto libraries
pqswitch scan . --include "*/crypto/*,*/security/*" --enable-ml
```

#### Mobile Applications
```bash
# Android (Java/Kotlin)
pqswitch scan . --include "*.java,*.kt" --min-confidence 0.3

# iOS (Swift/Objective-C)
pqswitch scan . --include "*.swift,*.m,*.mm" --min-confidence 0.3
```

#### Microservices & Containers
```bash
# Scan entire microservices repo
pqswitch layered-scan . --enable-l2 --parallel 8

# Container-optimized scan
docker run --rm -v $(pwd):/workspace pqswitch/scanner:latest \
  enhanced-scan --include-deps --min-confidence 0.4 /workspace
```

### ⚙️ **Configuration Options**

#### Configuration File (`.pqswitch.yaml`)

```yaml
# Scanning preferences
scanner:
  enable_ast: true          # Enable AST analysis (L1)
  enable_ml: true           # Enable ML confidence scoring
  enable_dataflow: false    # Enable data flow analysis (L2)
  min_confidence: 0.3       # ML confidence threshold
  parallel: 4               # Parallel processing
  
# Output settings
output:
  format: "json"            # json|sarif|text
  file: "pqswitch-results.json"
  verbose: true
  include_source: true

# Include/exclude patterns
patterns:
  include:
    - "**/*.go"
    - "**/*.java"
    - "**/*.py"
    - "**/*.js"
    - "**/*.ts"
  exclude:
    - "**/test/**"
    - "**/vendor/**"
    - "**/node_modules/**"
    - "**/*.test.go"

# ML model settings
ml:
  confidence_threshold: 0.3
  enable_prioritization: true
  model_version: "latest"

# Dependency scanning
dependencies:
  enable_npm_audit: true
  enable_go_vuln: true
  enable_pip_safety: true
  snyk_token: ""            # Set via environment variable
```

#### Environment Variables

```bash
# ML/AI Integration (Optional)
export OPENAI_API_KEY="sk-your-key-here"

# Dependency Scanning (Optional)
export SNYK_TOKEN="your-snyk-token"

# AWS for ML training data (Optional)
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-west-2"
```

### 🔧 **Advanced Command Options**

```bash
# All available scan commands with key options
pqswitch scan [PATH] [OPTIONS]
pqswitch enhanced-scan [PATH] [OPTIONS]
pqswitch layered-scan [PATH] [OPTIONS]

# Key OPTIONS:
--output string           Output format: json|sarif|text (default "text")
--output-file string      Output file path
--min-confidence float    ML confidence threshold (0.0-1.0)
--include strings         Include file patterns
--exclude strings         Exclude file patterns
--parallel int            Number of parallel workers (default 4)
--enable-ml               Enable ML confidence scoring
--enable-l2               Enable data flow analysis (resource intensive)
--layer string            Detection layer: l0|l1|l2 (default "l1")
--include-deps            Include dependency vulnerability scanning
--external-tools          Use external security tools (full image only)
--snyk-token string       Snyk API token for enhanced dependency scanning
--max-file-size int       Maximum file size to scan in bytes
```

## 🏗️ Architecture

### Detection Engine Flow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   L0: Regex     │───▶│   L1: AST       │───▶│   L2: DataFlow  │
│   Pre-filter    │    │   Analysis      │    │   Analysis      │
│   (~1000x fast) │    │   (Accurate)    │    │   (Complete)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ML Confidence Scorer                         │
│         ┌─────────────────────────────────────────┐            │
│         │           Intelligent                   │            │
│         │          Prioritization                 │            │
│         │     (High → Medium → Low confidence)    │            │
│         └─────────────────────────────────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

### Supported Cryptographic Patterns

| **Algorithm Type** | **Patterns Detected** | **Quantum Safe?** | **Recommendation** |
|-------------------|----------------------|-------------------|-------------------|
| **Asymmetric** | RSA, ECDSA, ECDH, DH | ❌ Vulnerable | Kyber, Dilithium |
| **Symmetric** | AES, ChaCha20 | ✅ Safe | Keep using |
| **Hashing** | MD5, SHA-1 | ❌ Weak | SHA-256, SHA-3 |
| **Key Exchange** | ECDH, DH | ❌ Vulnerable | Kyber KEM |
| **Signatures** | RSA-PSS, ECDSA | ❌ Vulnerable | Dilithium, Falcon |
| **Password Hash** | bcrypt, Argon2 | ✅ Safe | Keep using |

## 🔄 CI/CD Integration

### GitHub Actions

Create `.github/workflows/security.yml`:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  pq-crypto-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: PQ Crypto Scan
        uses: pqswitch/scanner/.github/actions/scan@v1
        with:
          upload-sarif: true
          min-confidence: 0.3
          
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: pqswitch-results.sarif
```

### Docker in CI/CD

```yaml
# GitLab CI, Jenkins, etc.
scan-crypto:
  image: pqswitch/scanner:latest
  script:
    - pqswitch enhanced-scan --include-deps --output sarif --output-file security.sarif .
  artifacts:
    reports:
      sast: security.sarif
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                script {
                    docker.image('pqswitch/scanner:latest').inside {
                        sh 'pqswitch layered-scan --enable-l2 --output json --output-file results.json .'
                    }
                }
                publishHTML([allowMissing: false,
                           alwaysLinkToLastBuild: true,
                           keepAll: true,
                           reportDir: '.',
                           reportFiles: 'results.json',
                           reportName: 'PQ Crypto Report'])
            }
        }
    }
}
```

## 🤖 ML/AI Integration

### AI-Enhanced Analysis

```bash
# AI evaluation of scan results
pqswitch ai-evaluate results.json --api-key "$OPENAI_API_KEY" --max-findings 10
```

The AI evaluator:
- Analyzes complex cryptographic patterns
- Provides context-aware recommendations
- Reduces false positives through intelligent analysis
- Generates migration suggestions

### Training Your Own Models

```bash
# Collect training data
cd ml-training
python systematic_scan_parallel.sh

# Train models
cd training
python train_ml_model.py --data-dir ../results --output-dir ../trained_models

# Convert to Go format
python convert_models_to_go.py --input-dir ../trained_models --output-dir ../../internal/ml/models
```

## 🛠️ Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/pqswitch/scanner.git
cd scanner

# Install dependencies
make deps

# Run tests
make test

# Build binary
make build

# Run crypto rules validation
make test-crypto-rules
```

### Adding Custom Detection Rules

Create custom rules in `internal/scanner/rules/crypto_rules.yaml`:

```yaml
- id: "custom-crypto-pattern"
  name: "Custom Crypto Detection"
  description: "Detects custom cryptographic pattern"
  pattern: "\\b(YourCryptoLibrary\\.encrypt)\\b"
  message: "Custom crypto library usage detected"
  severity: "medium"
  crypto_type: "symmetric"
  quantum_safe: false
  suggestion: "Consider quantum-safe alternatives"
  languages: ["go", "java"]
```

## 📊 Output Formats

### JSON Output
```json
{
  "findings": [
    {
      "id": "rsa-key-generation",
      "file": "crypto/keys.go",
      "line": 42,
      "column": 15,
      "message": "RSA key generation detected",
      "severity": "high",
      "confidence": 0.95,
      "crypto_type": "asymmetric",
      "quantum_safe": false,
      "suggestion": "Replace with Kyber KEM for quantum safety"
    }
  ],
  "summary": {
    "total_findings": 1,
    "high_severity": 1,
    "quantum_vulnerable": 1
  }
}
```

### SARIF Output (GitHub Security Tab)
Compatible with GitHub's security tab, showing findings directly in pull requests.

## 🔧 Troubleshooting

### Common Issues

**Q: "AST parsing failed" errors**
```bash
# Disable AST if you encounter tree-sitter crashes
pqswitch scan . --layer l0
# or in config file:
# scanner.enable_ast: false
```

**Q: High memory usage during L2 scans**
```bash
# Reduce parallel workers for large codebases
pqswitch layered-scan . --enable-l2 --parallel 2
```

**Q: Docker permission errors**
```bash
# Add user to docker group or use sudo
sudo docker run --rm -v $(pwd):/workspace pqswitch/scanner:latest scan /workspace
```

### Performance Optimization

| **Codebase Size** | **Recommended Mode** | **Typical Runtime** |
|------------------|---------------------|-------------------|
| < 1K files | `layered-scan --enable-l2` | < 30 seconds |
| 1K - 10K files | `enhanced-scan --enable-ml` | 1-5 minutes |
| 10K - 100K files | `scan --layer l1` | 5-15 minutes |
| > 100K files | `scan --layer l0` | 1-3 minutes |

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Quick Contribution Setup
```bash
git clone https://github.com/pqswitch/scanner.git
cd scanner
make deps
make test
```

### Areas We Need Help With
- 🔍 **Detection Rules**: New crypto patterns, language support
- 🏗️ **Core Features**: Performance optimizations, new scan modes
- 🤖 **ML/AI**: Model improvements, training data
- 📚 **Documentation**: Usage examples, integration guides

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 🏆 Acknowledgments

- **Quantum cryptography research community** for post-quantum standards
- **NIST Post-Quantum Cryptography** project for algorithm recommendations
- **Open source security tools ecosystem** for inspiration and collaboration
- **Contributors and early adopters** who help improve the scanner

## 🆘 Support & Community

- **📚 Documentation**: [docs/](docs/)
- **🐛 Issues**: [GitHub Issues](https://github.com/pqswitch/scanner/issues)
- **💬 Discussions**: [GitHub Discussions](https://github.com/pqswitch/scanner/discussions)
- **🔄 CI/CD Help**: [CI/CD Integration Guide](docs/cicd-integration.md)

---

**⚡ Built for the post-quantum era - Secure your cryptography today!**

> The quantum threat is not a distant future problem. Start identifying vulnerable crypto **now** to ensure your applications are ready for the quantum age.

**🔐 Don't wait for quantum computers to break your crypto. Use PQSwitch Scanner today!** 