# 🔍 Crypto Rules Test Suite

This test suite validates that our crypto scanning rules correctly distinguish between different contexts and assign appropriate severity levels.

## 🎯 Test Categories

### 1. **Protocol Implementation** (`protocol_implementation/`)
**Expected Severity: INFO**

Tests legitimate crypto implementations required by networking protocols:

- **`dnssec_legitimate.c`** - DNSSEC SHA-1 support (RFC 4034/5155 compliance)
- **`dns_over_tls_client.c`** - DNS-over-TLS client implementation (RFC 7858)

**Why INFO?** These are legitimate protocol implementations required for standards compliance, not security vulnerabilities.

### 2. **Application Vulnerabilities** (`application_vulnerabilities/`)
**Expected Severity: HIGH/CRITICAL**

Tests actual crypto vulnerabilities in application code:

- **`password_hashing_vulnerabilities.c`** - MD5/SHA-1 for passwords (CRITICAL)
- **`key_generation_vulnerabilities.go`** - RSA/ECDSA key generation (HIGH)

**Why HIGH/CRITICAL?** These are real security issues that need immediate attention.

### 3. **Test Context** (`test_context/`)
**Expected Severity: INFO**

Tests crypto usage in test files and testing frameworks:

- **`crypto_test_suite.py`** - MD5/SHA-1 in unit tests

**Why INFO?** Testing legacy crypto compatibility is legitimate and should not alarm security teams.

### 4. **Configuration** (`configuration/`)
**Expected Severity: INFO**

Tests build-time configuration files:

- **`Kconfig.crypto`** - Embedded system crypto configuration

**Why INFO?** Build configuration options are planning/compatibility items, not runtime vulnerabilities.

## 🏃‍♂️ Running Tests

### Quick Test
```bash
make test-crypto-rules
```

### Manual Test
```bash
# Build scanner first
make build

# Run test suite
cd test/crypto_rules/runner
go run test_runner.go
```

### Test Individual Files
```bash
./build/pqswitch scan test/crypto_rules/protocol_implementation/dnssec_legitimate.c --output json
```

## 📊 Expected Results

| Test File | Category | Expected Severity | Expected Rules |
|-----------|----------|------------------|----------------|
| `dnssec_legitimate.c` | Protocol | **INFO** | `dnssec-protocol-sha1` |
| `dns_over_tls_client.c` | Protocol | **INFO** | `dns-tls-client-usage` |
| `password_hashing_vulnerabilities.c` | Vulnerability | **CRITICAL** | `weak-hash-md5` |
| `key_generation_vulnerabilities.go` | Vulnerability | **HIGH** | `go-rsa-keygen` |
| `crypto_test_suite.py` | Test | **INFO** | `weak-hash-md5-test-context` |
| `Kconfig.crypto` | Config | **INFO** | `tls-config-kconfig` |

## 🧪 Test Validation

The test runner validates:

1. **Severity Levels** - Ensures protocol implementation gets INFO vs application vulnerabilities get HIGH/CRITICAL
2. **Rule Triggering** - Verifies expected rules are triggered
3. **Message Content** - Checks that appropriate context-aware messages are generated
4. **False Positive Reduction** - Confirms legitimate protocol code isn't flagged as vulnerable

## 🔧 Adding New Tests

1. **Create test file** in appropriate category directory
2. **Add expected results** to `runner/test_runner.go` in `loadTestCases()`
3. **Run tests** to validate

Example test case:
```go
{
    File:             "test/crypto_rules/new_category/test_file.c",
    ExpectedSeverity: "info",
    ExpectedRuleIDs:  []string{"rule-id-1", "rule-id-2"},
    ExpectedMessage:  "expected message content",
    Description:      "What this test validates",
    Category:         "new_category",
}
```

## 🎯 Success Criteria

- **Protocol implementations** → INFO severity (not HIGH)
- **Application vulnerabilities** → HIGH/CRITICAL severity  
- **Test files** → INFO severity (not HIGH)
- **Configuration files** → INFO severity (not MEDIUM)
- **Context-aware messages** → Specific to usage context
- **False positive rate** → <10% for legitimate code

## 📈 Coverage Goals

- ✅ **DNSSEC protocol support** (RFC compliance)
- ✅ **DNS-over-TLS implementation** (service protocols)  
- ✅ **Application crypto vulnerabilities** (real security issues)
- ✅ **Test framework usage** (development context)
- ✅ **Build configuration** (planning context)
- 🚧 **TLS library implementations** (protocol libraries)
- 🚧 **Crypto driver code** (kernel/hardware context)
- 🚧 **Migration guidance** (hybrid approaches)

This test suite ensures our scanner provides **actionable intelligence** rather than **alert fatigue**. 