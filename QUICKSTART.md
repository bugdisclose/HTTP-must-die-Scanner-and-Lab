# Quick Start Guide

Get up and running with the HTTP/1.1 desync research implementation in minutes.

## Prerequisites

- Python 3.8+
- Docker (optional, for lab environment)
- Basic understanding of HTTP protocols

## Installation

1. **Clone or download this repository**
2. **Run the setup script**:
   ```bash
   python3 setup.py
   ```

## Option 1: Use the Lab Environment (Recommended)

### Start the Lab
```bash
cd lab
docker-compose up -d
```

This creates vulnerable HTTP/1.1 servers for safe testing.

### Run All Demonstrations
```bash
python3 run_all_demos.py --target http://localhost:8080
```

### Run Individual Tools
```bash
# Parser discrepancy detection
python3 tools/parser-detector/detect_discrepancies.py --target http://localhost:8080

# CL.0 desync attacks
python3 examples/cl0-attacks/basic_cl0_demo.py --target http://localhost:8080

# 0.CL desync with early response gadgets
python3 examples/0cl-attacks/early_response_gadgets.py --target http://localhost:8080

# Expect-based attacks
python3 examples/expect-attacks/expect_desync_demo.py --target http://localhost:8080

# HTTP/2 vs HTTP/1.1 comparison
python3 examples/http2-migration/security_comparison.py --target http://localhost:8080
```

## Option 2: Test Your Own Server

⚠️ **WARNING**: Only test systems you own or have explicit permission to test!

```bash
python3 run_all_demos.py --target http://your-test-server.com
```

## Understanding the Results

### Parser Discrepancy Detection
- **V-H discrepancies**: Frontend sees header, backend doesn't
- **H-V discrepancies**: Frontend doesn't see header, backend does
- **High confidence findings**: Most likely to be exploitable

### Attack Demonstrations
- **CL.0 attacks**: Content-Length.0 based smuggling
- **0.CL attacks**: Zero Content-Length with early response gadgets
- **Expect attacks**: Exploiting Expect: 100-continue complexity

### Security Recommendations
- Migrate to HTTP/2 upstream connections
- Enable strict header validation
- Deploy WAF with desync protection
- Regular security testing

## Common Issues

### "No vulnerabilities found"
- This is good! Your server may be properly configured
- Try testing against the lab environment to see the tools working
- Some attacks only work against specific server configurations

### "Connection refused"
- Make sure the target server is running
- Check the URL format (include http:// or https://)
- Verify firewall settings

### "Permission denied"
- Make sure you have permission to test the target
- Only test systems you own or have explicit authorization for

## Next Steps

1. **Read the research summary**: `docs/RESEARCH_SUMMARY.md`
2. **Study the original paper**: [HTTP/1.1 Must Die](https://portswigger.net/research/http1-must-die)
3. **Explore the code**: Each tool is well-documented with educational comments
4. **Practice responsibly**: Always follow ethical guidelines

## Getting Help

- Check the documentation in the `docs/` directory
- Review the code comments for technical details
- Ensure you understand the ethical and legal implications

## Safety Reminders

- ⚠️ **Educational purposes only**
- ⚠️ **Only test authorized systems**
- ⚠️ **Unauthorized testing may be illegal**
- ⚠️ **Follow responsible disclosure practices**

---

**Happy learning, and remember: HTTP/1.1 must die!** 🔥
