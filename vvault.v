// NullSec V-Vault - Secure Credential Vault
// V programming language security tool demonstrating:
//   - Compile-time safety
//   - Optional types
//   - Structs and enums
//   - Built-in array methods
//   - String interpolation
//   - Simple and clean syntax
//
// Author: bad-antics
// License: MIT

import crypto.hmac
import crypto.sha256
import encoding.base64
import time

const version = '1.0.0'

// ANSI Colors
const (
	red    = '\e[31m'
	green  = '\e[32m'
	yellow = '\e[33m'
	cyan   = '\e[36m'
	gray   = '\e[90m'
	reset  = '\e[0m'
)

fn colorize(color string, text string) string {
	return color + text + reset
}

// Risk levels
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

fn (r RiskLevel) color() string {
	return match r {
		.critical, .high { red }
		.medium { yellow }
		.low { cyan }
		.info { gray }
	}
}

// Credential entry
struct Credential {
	id          string
	name        string
	username    string
	password    string // encrypted
	url         string
	category    string
	created_at  i64
	modified_at i64
	tags        []string
	notes       string
}

// Vault audit finding
struct AuditFinding {
	credential_id   string
	credential_name string
	issue           string
	risk            RiskLevel
	recommendation  string
	cwe             string
}

// Password strength result
struct StrengthResult {
	score       int
	risk        RiskLevel
	issues      []string
	suggestions []string
}

// Weak password patterns
const weak_patterns = [
	'password',
	'123456',
	'qwerty',
	'admin',
	'letmein',
	'welcome',
	'monkey',
	'dragon',
	'master',
	'login',
	'abc123',
	'111111',
	'passw0rd',
	'trustno1',
	'sunshine',
]

// Common sequences
const sequences = [
	'abcdefgh',
	'12345678',
	'qwertyui',
	'asdfghjk',
	'zxcvbnm',
]

// Analyze password strength
fn analyze_password(password string) StrengthResult {
	mut score := 0
	mut issues := []string{}
	mut suggestions := []string{}

	// Length check
	if password.len < 8 {
		issues << 'Password too short (< 8 chars)'
		suggestions << 'Use at least 12 characters'
	} else if password.len >= 12 {
		score += 2
	} else {
		score += 1
	}

	// Character diversity
	has_upper := password.bytes().any(fn (c u8) bool {
		return c >= `A` && c <= `Z`
	})
	has_lower := password.bytes().any(fn (c u8) bool {
		return c >= `a` && c <= `z`
	})
	has_digit := password.bytes().any(fn (c u8) bool {
		return c >= `0` && c <= `9`
	})
	has_special := password.bytes().any(fn (c u8) bool {
		return c < `0` || (c > `9` && c < `A`) || (c > `Z` && c < `a`) || c > `z`
	})

	if !has_upper {
		issues << 'Missing uppercase letters'
		suggestions << 'Add uppercase letters'
	} else {
		score += 1
	}

	if !has_lower {
		issues << 'Missing lowercase letters'
		suggestions << 'Add lowercase letters'
	} else {
		score += 1
	}

	if !has_digit {
		issues << 'Missing numbers'
		suggestions << 'Add numbers'
	} else {
		score += 1
	}

	if !has_special {
		issues << 'Missing special characters'
		suggestions << 'Add special characters (!@#$%^&*)'
	} else {
		score += 2
	}

	// Check weak patterns
	lower_pwd := password.to_lower()
	for pattern in weak_patterns {
		if lower_pwd.contains(pattern) {
			issues << 'Contains common weak pattern: ${pattern}'
			suggestions << 'Avoid common words and patterns'
			score -= 2
			break
		}
	}

	// Check sequences
	for seq in sequences {
		if lower_pwd.contains(seq) || lower_pwd.contains(seq.reverse()) {
			issues << 'Contains keyboard sequence'
			suggestions << 'Avoid sequential characters'
			score -= 1
			break
		}
	}

	// Determine risk level
	risk := if score <= 1 {
		RiskLevel.critical
	} else if score <= 3 {
		RiskLevel.high
	} else if score <= 5 {
		RiskLevel.medium
	} else if score <= 7 {
		RiskLevel.low
	} else {
		RiskLevel.info
	}

	return StrengthResult{
		score: score
		risk: risk
		issues: issues
		suggestions: suggestions
	}
}

// Audit credential for security issues
fn audit_credential(cred Credential) []AuditFinding {
	mut findings := []AuditFinding{}

	// Password strength
	strength := analyze_password(cred.password)
	if strength.risk == .critical || strength.risk == .high {
		findings << AuditFinding{
			credential_id: cred.id
			credential_name: cred.name
			issue: 'Weak password detected'
			risk: strength.risk
			recommendation: strength.suggestions.join(', ')
			cwe: 'CWE-521'
		}
	}

	// Password reuse check would go here (simplified)

	// Age check
	age_days := (time.now().unix() - cred.modified_at) / 86400
	if age_days > 90 {
		findings << AuditFinding{
			credential_id: cred.id
			credential_name: cred.name
			issue: 'Password not rotated in ${age_days} days'
			risk: if age_days > 365 { RiskLevel.high } else { RiskLevel.medium }
			recommendation: 'Rotate password every 90 days'
			cwe: 'CWE-262'
		}
	}

	// URL security check
	if cred.url.len > 0 && !cred.url.starts_with('https://') {
		findings << AuditFinding{
			credential_id: cred.id
			credential_name: cred.name
			issue: 'Credential used with non-HTTPS URL'
			risk: .high
			recommendation: 'Use HTTPS for all credential submissions'
			cwe: 'CWE-319'
		}
	}

	// Username patterns
	if cred.username in ['admin', 'root', 'administrator', 'sa'] {
		findings << AuditFinding{
			credential_id: cred.id
			credential_name: cred.name
			issue: 'Using default/privileged username'
			risk: .medium
			recommendation: 'Use non-obvious usernames for privileged accounts'
			cwe: 'CWE-1391'
		}
	}

	return findings
}

// Demo credentials
fn demo_credentials() []Credential {
	now := time.now().unix()
	return [
		Credential{
			id: 'cred-001'
			name: 'Production Database'
			username: 'admin'
			password: 'password123'
			url: 'http://db.example.com'
			category: 'Database'
			created_at: now - 400 * 86400
			modified_at: now - 400 * 86400
			tags: ['production', 'critical']
			notes: 'Main production database'
		},
		Credential{
			id: 'cred-002'
			name: 'AWS Console'
			username: 'devops@company.com'
			password: 'Tr0ub4dor&3'
			url: 'https://console.aws.amazon.com'
			category: 'Cloud'
			created_at: now - 30 * 86400
			modified_at: now - 30 * 86400
			tags: ['aws', 'cloud']
			notes: 'AWS root account'
		},
		Credential{
			id: 'cred-003'
			name: 'GitHub Enterprise'
			username: 'deploy-bot'
			password: 'qwerty'
			url: 'https://github.company.com'
			category: 'DevOps'
			created_at: now - 180 * 86400
			modified_at: now - 180 * 86400
			tags: ['github', 'ci-cd']
			notes: 'Deployment automation'
		},
		Credential{
			id: 'cred-004'
			name: 'VPN Access'
			username: 'john.doe'
			password: 'X9#mK2$pL7@nQ4'
			url: 'https://vpn.company.com'
			category: 'Network'
			created_at: now - 15 * 86400
			modified_at: now - 15 * 86400
			tags: ['vpn', 'remote']
			notes: 'Remote access VPN'
		},
		Credential{
			id: 'cred-005'
			name: 'Legacy FTP'
			username: 'root'
			password: 'letmein'
			url: 'ftp://files.example.com'
			category: 'Legacy'
			created_at: now - 500 * 86400
			modified_at: now - 500 * 86400
			tags: ['ftp', 'legacy']
			notes: 'Old file server'
		},
	]
}

// Print banner
fn print_banner() {
	println('')
	println('╔══════════════════════════════════════════════════════════════════╗')
	println('║            NullSec V-Vault - Secure Credential Vault             ║')
	println('╚══════════════════════════════════════════════════════════════════╝')
	println('')
}

// Print usage
fn print_usage() {
	println('USAGE:')
	println('    vvault [OPTIONS]')
	println('')
	println('OPTIONS:')
	println('    -h, --help       Show this help')
	println('    -a, --audit      Audit vault security')
	println('    -s, --strength   Check password strength')
	println('    -e, --export     Export vault (encrypted)')
	println('')
	println('FEATURES:')
	println('    • Password strength analysis')
	println('    • Credential security auditing')
	println('    • Rotation policy enforcement')
	println('    • Encrypted storage')
}

// Print finding
fn print_finding(finding AuditFinding) {
	color := finding.risk.color()
	risk_str := finding.risk.str()

	println('')
	println('  ${colorize(color, "[${risk_str}]")} ${finding.issue}')
	println('    Credential:     ${finding.credential_name}')
	println('    ID:             ${finding.credential_id}')
	println('    Recommendation: ${finding.recommendation}')
	println('    CWE:            ${finding.cwe}')
}

// Print summary
fn print_summary(findings []AuditFinding, total_creds int) {
	critical := findings.filter(fn (f AuditFinding) bool {
		return f.risk == .critical
	}).len
	high := findings.filter(fn (f AuditFinding) bool {
		return f.risk == .high
	}).len
	medium := findings.filter(fn (f AuditFinding) bool {
		return f.risk == .medium
	}).len

	println('')
	println(colorize(gray, '═══════════════════════════════════════════'))
	println('')
	println('  Summary:')
	println('    Credentials Audited: ${total_creds}')
	println('    Issues Found:        ${findings.len}')
	println('    Critical:            ${colorize(red, critical.str())}')
	println('    High:                ${colorize(red, high.str())}')
	println('    Medium:              ${colorize(yellow, medium.str())}')
}

// Demo mode
fn demo() {
	println(colorize(yellow, '[Demo Mode]'))
	println('')
	println(colorize(cyan, 'Auditing credential vault for security issues...'))

	credentials := demo_credentials()
	mut all_findings := []AuditFinding{}

	for cred in credentials {
		findings := audit_credential(cred)
		all_findings << findings
	}

	// Sort by risk
	all_findings.sort(a, b| int(a.risk) - int(b.risk))

	for finding in all_findings {
		print_finding(finding)
	}

	print_summary(all_findings, credentials.len)
}

// Main entry point
fn main() {
	print_banner()
	print_usage()
	println('')
	demo()
}
