# Contributing to PQSwitch Scanner

Thank you for your interest in contributing to PQSwitch Scanner! This guide will help you understand how to contribute effectively to our post-quantum cryptography scanner.

## 🚀 Quick Start

### Prerequisites

- **Go 1.24+** - Install from [golang.org](https://golang.org/dl/)
- **Git** - Version control
- **Docker** (optional) - For testing Docker-based workflows
- **Python 3.8+** (optional) - For ML training contributions

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YOUR_USERNAME/pqswitch-scanner.git
   cd pqswitch-scanner
   ```

2. **Install Dependencies**
   ```bash
   make deps
   ```

3. **Run Tests**
   ```bash
   make test
   ```

4. **Build the Scanner**
   ```bash
   make build
   ```

## 📋 How to Contribute

### 🐛 Reporting Bugs

**Before submitting a bug report:**
- Check existing [issues](https://github.com/pqswitch/scanner/issues)
- Test with the latest version
- Gather relevant information (Go version, OS, command used)

**Bug Report Template:**
```markdown
## Bug Description
Brief description of the issue

## Steps to Reproduce
1. Run command: `pqswitch scan ...`
2. Expected result
3. Actual result

## Environment
- OS: [e.g., macOS 14.0, Ubuntu 22.04]
- Go Version: [e.g., 1.24.3]
- Scanner Version: [e.g., v1.2.3]

## Additional Context
Any relevant logs, config files, or screenshots
```

### 💡 Suggesting Features

**Feature Request Template:**
```markdown
## Feature Description
Clear description of the proposed feature

## Use Case
Who would benefit and how?

## Implementation Ideas
Any thoughts on how this could be implemented

## Alternatives Considered
Other solutions you've considered
```

### 🔧 Code Contributions

#### Types of Contributions We Welcome

1. **🔍 Detection Rules**
   - New crypto patterns
   - Language-specific improvements
   - False positive reductions

2. **🏗️ Core Features**
   - Scanner optimizations
   - New scan modes
   - Output format improvements

3. **🤖 ML/AI Enhancements**
   - Model improvements
   - Training data contributions
   - Confidence scoring enhancements

4. **📚 Documentation**
   - Usage examples
   - Integration guides
   - Best practices

#### Development Workflow

1. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b bugfix/issue-number
   ```

2. **Make Your Changes**
   - Follow existing code style
   - Add tests for new functionality
   - Update documentation as needed

3. **Test Your Changes**
   ```bash
   # Run all tests
   make test
   
   # Run crypto rules validation
   make test-crypto-rules
   
   # Run linting
   make lint
   
   # Test specific functionality
   go test ./internal/scanner -v
   ```

4. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "feat: add new detection rule for XYZ crypto pattern"
   ```

5. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

## 🎯 Coding Standards

### Go Code Style

- **Follow Go conventions**: Use `gofmt`, `goimports`
- **Error handling**: Always handle errors appropriately
- **Comments**: Add meaningful comments for exported functions
- **Testing**: Write tests for new functionality

```go
// Good example
func DetectCryptoPattern(content string) (*types.Finding, error) {
    if content == "" {
        return nil, fmt.Errorf("content cannot be empty")
    }
    
    // Implementation...
    return finding, nil
}
```

### Detection Rules Guidelines

When adding new crypto detection rules to `internal/scanner/rules/crypto_rules.yaml`:

```yaml
- id: "unique-rule-id"
  name: "Human Readable Name"
  description: "Clear description of what this detects"
  pattern: "\\b(pattern|with|alternatives)\\b"
  message: "Clear message explaining the finding"
  severity: "high|medium|low|info"
  crypto_type: "asymmetric|symmetric|hash|signature|other"
  quantum_safe: false
  suggestion: "Recommended quantum-safe alternative"
  references:
    - "https://relevant-documentation.com"
  languages:
    - "go"
    - "python"
```

### Testing Requirements

#### Unit Tests
```go
func TestDetectRSA(t *testing.T) {
    tests := []struct {
        name     string
        content  string
        expected bool
    }{
        {
            name:     "RSA key generation",
            content:  "rsa.GenerateKey(rand.Reader, 2048)",
            expected: true,
        },
        {
            name:     "Non-crypto content",
            content:  "fmt.Println('hello')",
            expected: false,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := DetectRSA(tt.content)
            assert.Equal(t, tt.expected, result != nil)
        })
    }
}
```

#### Integration Tests
- Test complete scanning workflows
- Verify output formats (JSON, SARIF)
- Test with real-world code samples

## 🤖 ML/AI Contributions

### Training Data Contributions

If contributing to ML training:

1. **Data Quality**: Ensure high-quality, labeled examples
2. **Privacy**: No sensitive or proprietary code
3. **Format**: Follow existing data structure
4. **Documentation**: Explain data source and labeling methodology

### Model Improvements

```python
# Example contribution structure
ml-training/
├── training/
│   ├── your_improvement.py
│   └── README.md
├── data/
│   └── your_dataset.json
└── evaluation/
    └── your_evaluation.py
```

## 📚 Documentation

### Documentation Guidelines

- **Clear Examples**: Include working code examples
- **Step-by-step**: Break down complex processes
- **Keep Updated**: Update docs when changing functionality
- **Multiple Formats**: Support different user needs

### Writing Style

- Use present tense
- Be concise but complete
- Include code examples
- Add links to external resources

## 🔄 Pull Request Process

### PR Checklist

- [ ] Tests pass (`make test`)
- [ ] Linting passes (`make lint`)
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if applicable)
- [ ] Commit messages follow convention
- [ ] PR description is clear and complete

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Other: ___

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed

## Related Issues
Fixes #issue_number
```

### Review Process

1. **Automated Checks**: CI/CD must pass
2. **Code Review**: At least one maintainer review
3. **Testing**: Verify functionality works as expected
4. **Merge**: Squash and merge approach

## 🌍 Community Guidelines

### Code of Conduct

We are committed to providing a welcoming and inclusive environment:

- **Be Respectful**: Treat all contributors with respect
- **Be Collaborative**: Work together towards common goals
- **Be Patient**: Help newcomers learn and grow
- **Be Constructive**: Provide helpful feedback

### Communication Channels

- **GitHub Issues**: Bug reports, feature requests
- **GitHub Discussions**: General questions, ideas
- **Pull Requests**: Code contributions

## 🎖️ Recognition

Contributors are recognized in:
- `CONTRIBUTORS.md` file
- Release notes
- GitHub contributors page

## 🆘 Getting Help

**Stuck? Need Help?**

1. Check existing [documentation](docs/)
2. Search [GitHub Issues](https://github.com/pqswitch/scanner/issues)
3. Create a new issue with the "question" label
4. Join our [GitHub Discussions](https://github.com/pqswitch/scanner/discussions)

## 📄 License

By contributing, you agree that your contributions will be licensed under the same license as the project (MIT License).

---

**🚀 Ready to contribute? We can't wait to see what you build!**

Thank you for helping make cryptography quantum-safe! 🔐 