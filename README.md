# NullSec V-Vault

**Secure Credential Vault** written in V

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/bad-antics/nullsec-vvault/releases)
[![Language](https://img.shields.io/badge/language-V-5d87bf.svg)](https://vlang.io/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> Part of the **NullSec** offensive security toolkit  
> Twitter: [x.com/AnonAntics](https://x.com/AnonAntics)  
> Portal: [bad-antics.github.io](https://bad-antics.github.io)

## Overview

V-Vault is a secure credential management and auditing tool that analyzes stored credentials for security weaknesses, enforces password policies, and tracks rotation compliance. Built with V's clean syntax and compile-time safety guarantees.

## V Language Features Showcased

- **Compile-time Safety**: Memory safety without GC
- **Enums with Methods**: Type-safe risk levels
- **Structs**: Clean data structures
- **Optional Types**: Safe null handling
- **Array Methods**: `filter`, `any`, `map`
- **String Interpolation**: Clean formatting
- **Match Expressions**: Exhaustive pattern matching

## Security Audits

| Check | Risk | CWE | Description |
|-------|------|-----|-------------|
| Weak Password | CRITICAL | CWE-521 | Common patterns detected |
| Password Age | HIGH/MEDIUM | CWE-262 | Not rotated in 90+ days |
| Non-HTTPS | HIGH | CWE-319 | Credentials over HTTP |
| Default Username | MEDIUM | CWE-1391 | admin/root accounts |
| Short Password | HIGH | CWE-521 | Less than 8 characters |
| Missing Complexity | MEDIUM | CWE-521 | Lacks character diversity |

## Password Strength Analysis

| Criterion | Score Impact |
|-----------|--------------|
| Length ≥ 12 chars | +2 |
| Length 8-11 chars | +1 |
| Uppercase letters | +1 |
| Lowercase letters | +1 |
| Numbers | +1 |
| Special characters | +2 |
| Common patterns | -2 |
| Keyboard sequences | -1 |

## Installation

```bash
# Clone
git clone https://github.com/bad-antics/nullsec-vvault.git
cd nullsec-vvault

# Build (requires V compiler)
v vvault.v

# Run
./vvault
```

## Usage

```bash
# Run security audit
./vvault --audit

# Check password strength
./vvault --strength

# Export encrypted vault
./vvault --export backup.vault

# Show help
./vvault --help
```

### Options

```
USAGE:
    vvault [OPTIONS]

OPTIONS:
    -h, --help       Show help
    -a, --audit      Audit vault security
    -s, --strength   Check password strength
    -e, --export     Export vault (encrypted)
```

## Sample Output

```
╔══════════════════════════════════════════════════════════════════╗
║            NullSec V-Vault - Secure Credential Vault             ║
╚══════════════════════════════════════════════════════════════════╝

[Demo Mode]

Auditing credential vault for security issues...

  [CRITICAL] Weak password detected
    Credential:     Production Database
    ID:             cred-001
    Recommendation: Use at least 12 characters, Add special characters
    CWE:            CWE-521

  [CRITICAL] Weak password detected
    Credential:     GitHub Enterprise
    ID:             cred-003
    Recommendation: Use at least 12 characters, Avoid common words
    CWE:            CWE-521

  [HIGH] Password not rotated in 400 days
    Credential:     Production Database
    ID:             cred-001
    Recommendation: Rotate password every 90 days
    CWE:            CWE-262

  [HIGH] Credential used with non-HTTPS URL
    Credential:     Production Database
    ID:             cred-001
    Recommendation: Use HTTPS for all credential submissions
    CWE:            CWE-319

═══════════════════════════════════════════

  Summary:
    Credentials Audited: 5
    Issues Found:        9
    Critical:            3
    High:                4
    Medium:              2
```

## Code Highlights

### Enum with Methods
```v
enum RiskLevel {
    critical
    high
    medium
    low
    info
}

fn (r RiskLevel) str() string {
    return match r {
        .critical { 'CRITICAL' }
        .high { 'HIGH' }
        .medium { 'MEDIUM' }
        .low { 'LOW' }
        .info { 'INFO' }
    }
}
```

### Struct Definitions
```v
struct Credential {
    id          string
    name        string
    username    string
    password    string
    url         string
    category    string
    created_at  i64
    modified_at i64
    tags        []string
}
```

### Array Methods
```v
has_upper := password.bytes().any(fn (c u8) bool {
    return c >= `A` && c <= `Z`
})

critical := findings.filter(fn (f AuditFinding) bool {
    return f.risk == .critical
}).len
```

### Match Expressions
```v
risk := if score <= 1 {
    RiskLevel.critical
} else if score <= 3 {
    RiskLevel.high
} else if score <= 5 {
    RiskLevel.medium
} else {
    RiskLevel.low
}
```

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                     V-Vault Architecture                       │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│    │ Credential  │───▶│  Password   │───▶│  Strength   │      │
│    │   Store     │    │  Analyzer   │    │   Result    │      │
│    └─────────────┘    └─────────────┘    └──────┬──────┘      │
│                                                  │             │
│    ┌─────────────┐    ┌─────────────┐           │             │
│    │  Rotation   │───▶│   Policy    │───────────┤             │
│    │  Tracker    │    │   Engine    │           │             │
│    └─────────────┘    └─────────────┘           │             │
│                                                  │             │
│    ┌─────────────┐    ┌─────────────┐           │             │
│    │    URL      │───▶│  Security   │───────────┤             │
│    │  Validator  │    │   Check     │           │             │
│    └─────────────┘    └─────────────┘           │             │
│                                                  ▼             │
│                                        ┌─────────────────┐    │
│                                        │  Audit Report   │    │
│                                        └─────────────────┘    │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

## Why V?

| Requirement | V Advantage |
|-------------|-------------|
| Memory Safety | Compile-time guarantees |
| Performance | C-level speed |
| Clean Syntax | Easy to read/write |
| Fast Compilation | Sub-second builds |
| No GC | Predictable performance |
| Simplicity | Minimal language |

## License

MIT License - See [LICENSE](LICENSE) for details.

## Related Tools

- [nullsec-reporaider](https://github.com/bad-antics/nullsec-reporaider) - Secret scanner (Clojure)
- [nullsec-perlscrub](https://github.com/bad-antics/nullsec-perlscrub) - Log sanitizer (Perl)
- [nullsec-cryptoaudit](https://github.com/bad-antics/nullsec-cryptoaudit) - Crypto analyzer (Scala)
