# Pull Request

## 📋 Description

<!-- Briefly describe what this PR changes and why -->

## 🔍 Type of Change

- [ ] 🐛 Bug fix (non-breaking change that fixes an issue)
- [ ] ✨ New feature (non-breaking change that adds functionality) 
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📚 Documentation update
- [ ] 🔧 Refactoring (no functional changes)
- [ ] 🎨 Style/formatting changes
- [ ] ⚡ Performance improvement
- [ ] 🧪 Test additions or improvements
- [ ] 🔒 Security enhancement
- [ ] 🔍 **Crypto rules changes** (detection rules, patterns, or classification logic)

## 🧪 Testing Checklist

### Core Tests
- [ ] Unit tests pass locally (`make test`)
- [ ] Linting passes (`make lint`)
- [ ] Build succeeds (`make build`)

### 🔍 Crypto Rules Validation (Required for crypto-related changes)

If this PR modifies crypto detection rules, patterns, or classification logic:

- [ ] **Crypto rules tests pass** (`make test-crypto-rules`)
- [ ] **Context-aware detection verified** - Rules correctly distinguish:
  - [ ] 🛡️ Protocol implementations (INFO severity)
  - [ ] 🚨 Application vulnerabilities (HIGH/CRITICAL severity)  
  - [ ] 🧪 Test context usage (INFO severity)
  - [ ] ⚙️ Build configuration (INFO severity)
- [ ] **No regression in detection accuracy**
- [ ] **False positive rate maintained or improved**

#### For New Crypto Rules:
- [ ] Rule added to appropriate severity category
- [ ] Test case created in `test/crypto_rules/`
- [ ] Context-aware rule added to `isContextAwareRule()` if needed
- [ ] Documentation updated for new detection capability

#### For Rule Modifications:
- [ ] Existing test cases still pass
- [ ] Behavior change documented and justified
- [ ] Impact on existing codebases considered

## 📊 Impact Assessment

### Detection Changes (if applicable)
- **Algorithms affected**: <!-- e.g., RSA, MD5, SHA-1 -->
- **Languages affected**: <!-- e.g., Go, Java, C -->
- **Expected impact**: <!-- e.g., 20% reduction in false positives -->
- **Breaking changes**: <!-- Any changes that affect existing rule behavior -->

### Performance Impact
- [ ] No significant performance regression
- [ ] Memory usage remains acceptable
- [ ] Scanning speed impact assessed

## 🔍 Examples

### Before (if changing behavior):
```
<!-- Example of previous detection behavior -->
```

### After:
```
<!-- Example of new detection behavior -->
```

## 📋 Manual Testing Performed

<!-- Describe specific testing scenarios you ran -->

- [ ] Tested on real-world codebase
- [ ] Verified with known false positive cases
- [ ] Validated with known true positive cases
- [ ] Cross-platform testing (if applicable)

## 🚀 CI/CD Pipeline Verification

The following quality gates must pass before merge:

- [ ] **Unit Tests** (`test` job)
- [ ] **Code Quality** (`lint` job)
- [ ] **Security Scan** (`security` job)  
- [ ] **Crypto Rules Validation** (`crypto-rules-test` job)
- [ ] **Build** succeeds for all platforms
- [ ] **Integration Tests** pass

## 🔗 Related Issues

<!-- Link to related issues -->
Fixes #
Relates to #

## 🆕 Dependencies

<!-- List any new dependencies added -->
- [ ] No new dependencies
- [ ] New dependencies documented and justified

## 📚 Documentation Updates

- [ ] Code comments updated
- [ ] README updated (if needed)
- [ ] API documentation updated (if needed)
- [ ] CI/CD documentation updated (if needed)

## ⚠️ Migration Notes

<!-- If this is a breaking change, describe migration steps -->

## 🏷️ Labels

<!-- Add appropriate labels -->
- crypto-rules
- enhancement / bug / documentation
- breaking-change (if applicable)

---

## 🔍 For Reviewers

### Crypto Rules Review Checklist

If this PR affects crypto detection:

- [ ] **Accuracy verified** - New rules/changes don't introduce false positives
- [ ] **Context awareness maintained** - Legitimate protocol usage isn't flagged as vulnerabilities
- [ ] **Test coverage adequate** - Changes are covered by crypto rules tests
- [ ] **Performance impact acceptable** - No significant slowdown in scanning
- [ ] **Documentation complete** - New detection capabilities are documented

### Security Review (if applicable)

- [ ] No security vulnerabilities introduced
- [ ] Input validation adequate
- [ ] Error handling appropriate
- [ ] Sensitive data handled properly

---

## ✅ Reviewer Approval

<!-- Reviewers: Please verify crypto rules validation passes before approving -->

**Required**: Crypto rules validation must pass for all crypto-related changes.

Check CI/CD pipeline results: 
- 🔍 Crypto Rules Validation job status
- 📊 Quality Gate Summary results
- 🏆 Overall pipeline success 