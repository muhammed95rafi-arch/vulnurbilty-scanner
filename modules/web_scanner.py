import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style
import urllib3

# Disable insecure request warnings for simplicity during scans
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebScanner:
    def __init__(self, start_url):
        self.start_url = start_url
        if not self.start_url.startswith(('http://', 'https://')):
            self.start_url = 'http://' + self.start_url
        self.session = requests.Session()
        # Set a generic user-agent to avoid simple blocks
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SimpleVulnScanner/1.0'
        })
        
    def check_security_headers(self, url=None):
        if url is None: url = self.start_url
        print(f"\n{Fore.CYAN}[*] Checking Security Headers for {url}{Style.RESET_ALL}")
        try:
            response = self.session.get(url, verify=False, timeout=5)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS Header. Susceptible to downgrade attacks.',
                'Content-Security-Policy': 'Missing CSP. Susceptible to XSS.',
                'X-Frame-Options': 'Missing X-Frame-Options. Susceptible to Clickjacking.',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options. Susceptible to MIME-sniffing.'
            }
            
            for header, warning in security_headers.items():
                if header not in headers:
                    print(f"{Fore.YELLOW}[!] {warning}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] {header} is present.{Style.RESET_ALL}")
                    
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Error connecting to {url}: {e}{Style.RESET_ALL}")

    def test_xss_in_url(self, url=None):
        if url is None: url = self.start_url
        print(f"\n{Fore.CYAN}[*] Testing basic URL parameter XSS on {url}{Style.RESET_ALL}")
        
        parsed = urlparse(url)
        payload = "<script>alert('xss')</script>"
        test_url = url
        
        # Super simple fuzzing by appending an arbitrary parameter or updating query string
        if parsed.query:
            test_url = f"{url}&test={payload}"
        else:
            test_url = f"{url}?test={payload}"
            
        try:
            response = self.session.get(test_url, verify=False, timeout=5)
            if payload in response.text:
                 print(f"{Fore.RED}[!] XSS Vulnerability Potentially Found! Payload reflected in response.{Style.RESET_ALL}")
                 print(f"    Payload URL: {test_url}")
            else:
                 print(f"{Fore.GREEN}[+] No obvious reflection found in URL parameters.{Style.RESET_ALL}")
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Error testing XSS on {url}: {e}{Style.RESET_ALL}")

    def test_sqli_in_url(self, url=None):
        if url is None: url = self.start_url
        print(f"\n{Fore.CYAN}[*] Testing basic URL parameter SQLi on {url}{Style.RESET_ALL}")
        
        parsed = urlparse(url)
        payload = "'"
        test_url = url
        
        if parsed.query:
            test_url = f"{url}&id={payload}"
        else:
            test_url = f"{url}?id={payload}"
            
        sql_errors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "sqlexception"
        ]
        
        try:
            response = self.session.get(test_url, verify=False, timeout=5)
            content_lower = response.text.lower()
            
            vulnerable = False
            for error in sql_errors:
                if error in content_lower:
                    vulnerable = True
                    break
                    
            if vulnerable:
                 print(f"{Fore.RED}[!] SQLi Vulnerability Potentially Found! Error message reflected in response.{Style.RESET_ALL}")
                 print(f"    Payload URL: {test_url}")
            else:
                 print(f"{Fore.GREEN}[+] No obvious SQL errors found from basic payload.{Style.RESET_ALL}")
                 
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Error testing SQLi on {url}: {e}{Style.RESET_ALL}")

    def run_all(self):
        self.check_security_headers()
        self.test_xss_in_url()
        self.test_sqli_in_url()


if __name__ == "__main__":
    scanner = WebScanner("http://example.com")
    scanner.run_all()
