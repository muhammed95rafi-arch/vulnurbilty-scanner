import argparse
from colorama import init, Fore, Style

from modules.port_scanner import run_port_scan
from modules.web_scanner import WebScanner

def print_banner():
    banner = f"""
{Fore.MAGENTA}
  ____  _                 _   __     __    _        _____                               
 / ___|(_)_ __ ___  _ __ | |  \ \   / /   | |____  / ___ |                              
 \___ \| | '_ ` _ \| '_ \| |   \ \ / /   | | '_  \ \___ \                               
  ___) | | | | | | | |_) | |___ \ V /_   | | | | |  ___) |                              
 |____/|_|_| |_| |_| .__/|_____| \_/(_)  |_|_| |_| |____/                               
                   |_|                                                                  
{Style.RESET_ALL}
Simple Python Vulnerability Scanner
"""
    print(banner)

def main():
    init(autoreset=True)
    
    parser = argparse.ArgumentParser(description="A simple Python Vulnerability Scanner.")
    parser.add_argument("target", help="Target URL or IP address (e.g., example.com or http://example.com)")
    parser.add_argument("-p", "--ports", help="Ports to scan (comma-separated, e.g., 22,80,443) or 'common'.", default="common")
    parser.add_argument("--skip-ports", action="store_true", help="Skip port scanning step")
    parser.add_argument("--skip-web", action="store_true", help="Skip web vulnerabilities scanning step")
    
    args = parser.parse_args()
    
    print_banner()
    
    target = args.target

    if not args.skip_ports:
        ports_to_scan = []
        if args.ports.lower() == "common":
            ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        else:
            try:
                ports_to_scan = [int(p.strip()) for p in args.ports.split(",")]
            except ValueError:
                print(f"{Fore.RED}[!] Invalid port format. Please provide comma-separated integers.{Style.RESET_ALL}")
                return
                
        # For port scanning, we just want the domain/ip, without http://
        host_to_scan = target
        if "://" in host_to_scan:
            host_to_scan = host_to_scan.split("://")[1].split("/")[0]
            
        run_port_scan(host_to_scan, ports_to_scan)
        
    if not args.skip_web:
        web_scanner = WebScanner(target)
        web_scanner.run_all()

    print(f"\n{Fore.GREEN}[*] Scan Completed.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
