# VulnShop - Intentionally Vulnerable Test Codebase

**WARNING: This codebase contains intentional security vulnerabilities for testing purposes only!**

## Overview

VulnShop is a comprehensive test application designed to demonstrate various types of security vulnerabilities across multiple programming languages and frameworks. This codebase is specifically created for testing security analysis tools.

## Structure

```
test_vulnerable_codebase/
├── backend/
│   └── app.py              # Flask backend (35+ vulnerabilities)
├── frontend/
│   └── main.js             # JavaScript frontend (23+ vulnerabilities)
├── config/
│   └── database.php        # PHP configuration (37+ vulnerabilities)
├── utils/
│   └── security.java       # Java utilities (30+ vulnerabilities)
└── README.md               # This file
```

## Languages & Frameworks Detected

- **Python**: Flask web framework
- **JavaScript**: Vanilla JS with XSS, DOM manipulation
- **PHP**: Database configuration and web utilities
- **Java**: Security utilities and servlet handling

## Vulnerability Categories

### [CRITICAL] Vulnerabilities (Priority 1)
1. **SQL Injection** - Multiple instances across all languages
2. **Command Injection** - System command execution with user input
3. **Remote Code Execution** - Via deserialization, eval(), file upload
4. **Hardcoded Credentials** - Database passwords, API keys, JWT secrets

### [HIGH] Priority Vulnerabilities (Priority 2)
5. **Cross-Site Scripting (XSS)** - Reflected and DOM-based
6. **Path Traversal** - File system access vulnerabilities
7. **Insecure Deserialization** - Object injection attacks
8. **XML External Entity (XXE)** - XML parsing vulnerabilities

### [MEDIUM] Priority Vulnerabilities (Priority 3)
9. **Insecure Direct Object Reference (IDOR)** - Authorization bypass
10. **Server-Side Request Forgery (SSRF)** - Internal network access
11. **LDAP Injection** - Directory service attacks
12. **Weak Cryptography** - MD5 hashing, weak encryption

### [INFO] Information Disclosure (Priority 4)
13. **Sensitive Data Exposure** - Logs, error messages, debug info
14. **Information Leakage** - Stack traces, database errors
15. **Debug Mode in Production** - Development settings exposed

## Expected Analysis Results

When running the security analyzer on this codebase, you should expect:

- **Total Files**: 4 source files
- **Languages Detected**: Python, JavaScript, PHP, Java
- **Frameworks Detected**: Flask
- **High-Risk Entry Points**: 15-20 endpoints
- **Total Vulnerabilities**: 125+ individual security issues
- **Critical Issues**: 25+ requiring immediate attention

## Test Scenarios

This codebase is designed to test:

1. **Multi-language Detection**: Ensure analyzer works across Python, JS, PHP, Java
2. **Framework Recognition**: Proper Flask framework detection
3. **Vulnerability Classification**: Correct risk scoring and prioritization
4. **Stack Overflow Citations**: Evidence-based fix recommendations
5. **Report Generation**: Comprehensive HTML reports with all findings

## Sample Vulnerabilities for Testing

### SQL Injection (app.py:45)
```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
```

### XSS Vulnerability (main.js:28)
```javascript
document.getElementById('welcome').innerHTML = `Welcome back, ${username}!`;
```

### Command Injection (database.php:87)
```php
$command = "mysqldump -u " . DB_USER . " -p" . DB_PASS . " " . DB_NAME . " > $backupPath";
shell_exec($command);
```

### Deserialization (security.java:67)
```java
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
return ois.readObject(); // Dangerous!
```

## Security Report Expectations

The generated security report should include:

1. **Executive Summary** with risk breakdown
2. **Detailed Vulnerability Listings** with:
   - File paths and line numbers
   - Risk classifications
   - Stack Overflow citations
   - Proof-of-concept exploits
   - Remediation recommendations
3. **Framework-specific Guidance**
4. **Compliance Mapping** (OWASP Top 10, CWE)
5. **Actionable Remediation Steps**

## Usage

```bash
# Run complete security analysis
python -m src.main ai-analyze test_vulnerable_codebase/ --output vulnshop_report.json

# Generate HTML report
python -m src.main generate-report test_vulnerable_codebase/ --format html --output vulnshop_security_report.html
```

## Expected Timeline

- **Phase 1 (Entry Points)**: ~2-3 seconds
- **Phase 2 (RAG Analysis)**: ~10-15 seconds  
- **Phase 3 (AI Validation)**: ~30-60 seconds
- **Phase 4 (Report Generation)**: ~5-10 seconds

**Total Analysis Time**: ~1-2 minutes for complete report

---

**[TARGET] This codebase represents a comprehensive security testing scenario with 125+ vulnerabilities across 4 languages, designed to validate the complete security analysis pipeline from detection to professional reporting.**