# HTTP/1.1 Must Die - Production Security Scanner

A comprehensive, production-ready implementation of James Kettle's groundbreaking research "HTTP/1.1 Must Die: The Desync Endgame" with advanced subdomain scanning capabilities and complete proof-of-concept generation.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: Educational](https://img.shields.io/badge/license-Educational-green.svg)](LICENSE)
[![Security Scanner](https://img.shields.io/badge/type-Security%20Scanner-red.svg)](https://github.com/your-repo)

## 🔥 Overview

This repository contains a **production-ready security scanner** that implements all major HTTP/1.1 desync attack techniques discovered by James Kettle, enhanced with:

- **🎯 Bulk Subdomain Scanning** - Concurrent scanning of multiple targets
- **⚡ Critical-Only Mode** - Focus on CRITICAL vulnerabilities (CVSS 9.0+)
- **📋 Complete PoC Generation** - Ready-to-use HTTP payloads for every vulnerability
- **📊 Professional Reporting** - JSON, HTML, and console output formats
- **🛡️ Production Security** - Authorization checks and safety controls

## ⚠️ ETHICAL USE DISCLAIMER

**This code is for educational and authorized security testing purposes only.**

- Only use these tools on systems you own or have explicit written permission to test
- Never use these techniques against systems without proper authorization
- This research is intended to help security professionals understand and defend against these attacks
- Unauthorized use of these techniques may be illegal and could result in criminal charges

## 🚀 Key Features

### **Advanced Vulnerability Detection**
- **Parser Discrepancy Detection** - V-H and H-V header parsing differences
- **CL.0 Desync Attacks** - Content-Length.0 based request smuggling
- **0.CL Desync with Early Response Gadgets** - Windows reserved names exploitation
- **Expect-based Attacks** - Memory disclosure and response queue poisoning
- **HTTP/2 Security Comparison** - Protocol migration benefits analysis

### **Production-Ready Capabilities**
- **🌐 Bulk Subdomain Scanning** - Scan 100+ subdomains concurrently
- **🔥 Critical Vulnerability Focus** - CVSS 9.0+ findings only
- **📄 Complete Proof-of-Concepts** - HTTP payloads ready for testing
- **⚡ High-Performance Scanning** - Configurable concurrent workers
- **🛡️ Enterprise Security** - Authorization and compliance controls

### **Professional Reporting**
- **JSON Reports** - Machine-readable vulnerability data
- **HTML Reports** - Executive-ready security assessments
- **Console Output** - Real-time scanning feedback
- **CVSS Scoring** - Industry-standard vulnerability ratings
- **Remediation Guidance** - Actionable security recommendations

## 💰 Research Impact

From James Kettle's research:

- **$350,000+ in bug bounties** earned using these techniques
- **24+ million websites** were vulnerable to a single Cloudflare infrastructure bug
- **HTTP/1.1 has a fatal flaw** - poor request boundary separation
- **HTTP/2 upstream connections** virtually eliminate desync vulnerabilities
- **More desync attacks are always coming** due to protocol complexity

## 📋 Quick Start

### **1. Installation**
```bash
git clone https://github.com/your-repo/http1-must-die
cd http1-must-die
python3 setup.py
```

### **2. Single Target Scanning**
```bash
# Basic vulnerability scan
python3 run_all_demos.py --target https://example.com

# Critical vulnerabilities only (recommended)
python3 run_all_demos.py --target https://example.com --critical-only

# Generate JSON report
python3 run_all_demos.py --target https://example.com --output json --file report.json

# Generate HTML report
python3 run_all_demos.py --target https://example.com --output html --file report.html
```

### **3. Bulk Subdomain Scanning**
```bash
# Create subdomain list
echo -e "api.example.com\nwww.example.com\nadmin.example.com" > subdomains.txt

# Bulk scan for critical vulnerabilities
python3 run_all_demos.py --subdomain-list subdomains.txt --critical-only

# High-performance bulk scan
python3 run_all_demos.py --subdomain-list subdomains.txt --critical-only --max-concurrent 10

# Generate comprehensive report
python3 run_all_demos.py --subdomain-list subdomains.txt --critical-only --output json --file bulk_report.json
```

### **4. Lab Environment (Optional)**
```bash
# Start vulnerable test servers
cd lab && docker-compose up -d

# Test against lab environment
python3 run_all_demos.py --target http://localhost:8080
```

## 🎯 Usage Examples

### **Bug Bounty Reconnaissance**
```bash
# Quick critical vulnerability assessment
python3 run_all_demos.py --subdomain-list targets.txt --critical-only --max-concurrent 8
```

### **Infrastructure Security Audit**
```bash
# Comprehensive subdomain audit with reporting
python3 run_all_demos.py --subdomain-list company_subdomains.txt --critical-only --output json --file audit_report.json
```

### **Penetration Testing**
```bash
# Full assessment with detailed PoCs
python3 run_all_demos.py --target https://target.com --output html --file pentest_report.html
```

### **Continuous Security Monitoring**
```bash
# Daily automated scan
python3 run_all_demos.py --subdomain-list production_domains.txt --critical-only --output json --file daily_scan_$(date +%Y%m%d).json
```

## 🔥 Critical Vulnerabilities Detected

The scanner focuses on **CRITICAL** vulnerabilities (CVSS 9.0+) that matter most:

### **1. CL.0 Request Smuggling (CVSS 10.0)**
- **Impact:** Complete request smuggling capability
- **Exploitation:** Cache poisoning, session hijacking, security bypass
- **PoC Generated:** Ready-to-use HTTP payloads

### **2. 0.CL Desync with Early Response Gadgets (CVSS 10.0)**
- **Impact:** Advanced request smuggling chains
- **Exploitation:** Windows reserved name exploitation, double desync attacks
- **PoC Generated:** Deadlock breaking and exploitation chains

### **3. Expect-Based Memory Disclosure (CVSS 9.6)**
- **Impact:** Server memory content leakage
- **Exploitation:** Information disclosure, response queue poisoning
- **PoC Generated:** Memory extraction techniques

## 📊 Sample Output

### **Console Report**
```
====================================================================================================
HTTP/1.1 MUST DIE - BULK SUBDOMAIN SECURITY ASSESSMENT REPORT
====================================================================================================
Subdomain List: subdomains.txt
Subdomains Scanned: 10
Subdomains Vulnerable: 3
🔥 CRITICAL-ONLY MODE: Scanning for critical vulnerabilities only

🌐 SUBDOMAIN SCAN SUMMARY
🔥 VULNERABLE SUBDOMAINS:
  • api.example.com - 2 critical vulnerabilities
  • admin.example.com - 1 critical vulnerabilities

🎯 DETAILED PROOF OF CONCEPTS
[CRITICAL] #1 - CL.0 Request Smuggling Vulnerability
Target: api.example.com
CVSS Score: 10.0

HTTP Request Payload:
GET /style.css HTTP/1.1
Host: api.example.com
 Content-Length: 23
Connection: keep-alive

GET /404 HTTP/1.1
X: y

Impact: Complete request smuggling capability...
Remediation: Migrate to HTTP/2 upstream connections...
```

### **JSON Report Structure**
```json
{
  "scan_metadata": {
    "subdomain_list": "subdomains.txt",
    "subdomains_scanned": 10,
    "subdomains_vulnerable": 3,
    "critical_only_mode": true,
    "total_vulnerabilities": 5,
    "critical_vulnerabilities": 5
  },
  "proof_of_concepts": [
    {
      "id": 1,
      "vulnerability_type": "REQUEST_SMUGGLING",
      "severity": "CRITICAL",
      "title": "CL.0 Request Smuggling Vulnerability",
      "target": "api.example.com",
      "http_request": "GET /style.css HTTP/1.1\r\nHost: api.example.com...",
      "cvss_score": 10.0,
      "impact": "Complete request smuggling capability...",
      "remediation": "Migrate to HTTP/2 upstream connections..."
    }
  ]
}
```

## ⚡ Performance & Scalability

### **Concurrent Scanning**
- **Default:** 5 concurrent workers
- **Recommended:** 5-10 for most networks
- **High-performance:** Up to 20 for fast networks
- **Conservative:** 2-3 for slow/unstable targets

### **Critical-Only Benefits**
- **Speed:** 3-5x faster than full scans
- **Accuracy:** Focuses on exploitable vulnerabilities
- **Scale:** Suitable for 100+ subdomains
- **Resources:** Lower CPU and network usage

### **Timeout Configuration**
- **Default:** 30 seconds per subdomain
- **Fast networks:** 15 seconds
- **Slow networks:** 45-60 seconds
- **Unstable targets:** 60+ seconds

## 📄 Subdomain List Format

Create a text file with one subdomain per line:

```
# Comments start with #
# Protocol is optional - defaults to https (http for localhost)

localhost:8080
127.0.0.1:8080
api.example.com
www.example.com
https://secure.example.com
admin.example.com
staging.example.com
```

## 🛡️ Security & Authorization

### **Built-in Safety Features**
- **Authorization prompts** for non-localhost targets
- **Legal compliance warnings** for external domains
- **Rate limiting** to prevent service disruption
- **Timeout controls** to avoid hanging scans
- **Comprehensive error handling** and recovery

### **Authorization Requirements**
- **Explicit permission** required for all targets
- **Written authorization** recommended for external domains
- **Legal compliance** with local regulations
- **Responsible disclosure** for any findings

## 🎯 Real-World Use Cases

### **1. Bug Bounty Reconnaissance**
- Quick critical vulnerability assessment across multiple subdomains
- Focus on high-impact findings with complete PoCs
- Efficient scanning with minimal resource usage

### **2. Infrastructure Security Audits**
- Comprehensive subdomain coverage for enterprise environments
- Executive-ready reports with CVSS scoring
- Actionable remediation guidance

### **3. Penetration Testing**
- Complete proof-of-concepts with ready-to-use HTTP payloads
- Detailed vulnerability analysis and impact assessment
- Professional reporting for client deliverables

### **4. Continuous Security Monitoring**
- Automated daily/weekly scans for production environments
- Integration with CI/CD pipelines and security workflows
- Machine-readable JSON output for SIEM integration

## 📚 Research Context

### **The Fatal Flaw**
HTTP/1.1 has weak request boundaries - requests are concatenated with no delimiters and multiple ways to specify length, creating ambiguity about where requests start/end.

### **Attack Categories**
1. **V-H Discrepancies** - Front-end sees header, back-end doesn't
2. **H-V Discrepancies** - Front-end doesn't see header, back-end does
3. **0.CL Attacks** - Zero Content-Length with early response gadgets
4. **Expect Attacks** - Exploiting Expect: 100-continue complexity

### **Why HTTP/2 is Safer**
- Binary protocol with zero length ambiguity
- Built-in message framing eliminates parser discrepancies
- Significantly reduces exploitable bug probability

## 🔧 Command Line Options

```bash
# Target specification (mutually exclusive)
--target URL                    # Single target URL
--subdomain-list FILE          # File containing subdomains

# Scanning options
--critical-only                # Scan for CRITICAL vulnerabilities only
--timeout SECONDS              # Request timeout (default: 30)
--max-concurrent N             # Max concurrent subdomain scans (default: 5)
--subdomain-timeout SECONDS    # Timeout per subdomain (default: 15)

# Output options
--output FORMAT                # Output format: console, json, html
--file PATH                    # Output file path
--verbose                      # Verbose logging

# Test selection
--skip-parser                  # Skip parser discrepancy detection
--skip-cl0                     # Skip CL.0 desync attacks
--skip-0cl                     # Skip 0.CL desync attacks
--skip-expect                  # Skip Expect-based attacks
--skip-http2                   # Skip HTTP/2 comparison

# Safety options
--force                        # Skip authorization prompts
--rate-limit SECONDS           # Delay between test categories
```

## 📁 Project Structure

```
├── README.md                    # This comprehensive guide
├── SUBDOMAIN_SCANNING_GUIDE.md  # Detailed subdomain scanning documentation
├── run_all_demos.py            # Main production scanner
├── setup.py                    # Installation and dependencies
├── sample_subdomains.txt       # Example subdomain list
├── detect_discrepancies.py     # Parser discrepancy detector
├── basic_cl0_demo.py           # CL.0 desync demonstrations
├── early_response_gadgets.py   # 0.CL desync with gadgets
├── expect_desync_demo.py       # Expect-based attack demos
├── security_comparison.py      # HTTP/2 vs HTTP/1.1 analysis
└── lab/                        # Controlled lab environment
    └── docker-compose.yml      # Vulnerable test servers
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Follow responsible disclosure practices
2. Include proper documentation and test cases
3. Maintain the educational and ethical focus
4. Add comprehensive proof-of-concept generation

## 📖 References

- [Original Research Paper](https://portswigger.net/research/http1-must-die) - James Kettle's groundbreaking research
- [HTTP Request Smuggler v3.0](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646) - Burp Suite extension
- [Web Security Academy Labs](https://portswigger.net/web-security/request-smuggling) - Interactive learning
- [RFC 7230](https://tools.ietf.org/html/rfc7230) - HTTP/1.1 Message Syntax and Routing
- [RFC 7540](https://tools.ietf.org/html/rfc7540) - HTTP/2 Protocol Specification

## 📄 License

This project is for educational purposes. Please use responsibly and ethically.

---

## 🔥 **Remember: HTTP/1.1 Must Die!**

This scanner demonstrates why **HTTP/1.1 must die** and provides the evidence needed to justify **HTTP/2 migration** across entire infrastructures. With techniques that earned **$350,000+ in bug bounties** and affected **24+ million websites**, this research proves that HTTP/1.1's fundamental flaws make it unsuitable for modern security requirements.

**Use these techniques ethically and legally. With great power comes great responsibility.** 🛡️
