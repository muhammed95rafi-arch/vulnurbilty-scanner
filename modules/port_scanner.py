import socket
import concurrent.futures
from colorama import Fore, Style

def scan_port(ip, port, timeout=1.0):
    """Attempt to connect to a specific port on the target IP."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                print(f"{Fore.GREEN}[+] Port {port} is OPEN{Style.RESET_ALL}")
                try:
                    # Attempt a basic banner grab
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode('utf-8', errors='ignore').split('\n')[0].strip()
                    if banner:
                        print(f"    Banner: {banner}")
                except:
                    pass
                return port
            return None
    except Exception:
        return None

def run_port_scan(target, ports, max_threads=100):
    """Run a multi-threaded port scan."""
    print(f"\n{Fore.CYAN}[*] Starting Port Scan on {target}{Style.RESET_ALL}")
    
    try:
        target_ip = socket.gethostbyname(target)
        print(f"[*] Target IP: {target_ip}")
    except socket.gaierror:
        print(f"{Fore.RED}[-] Target {target} could not be resolved.{Style.RESET_ALL}")
        return []

    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, target_ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port = future.result()
            if port:
                open_ports.append(port)
                
    if not open_ports:
         print(f"[-] No open ports found in the specified range.")
    else:
         print(f"{Fore.GREEN}[+] Finished checking ports. {len(open_ports)} open.{Style.RESET_ALL}")
         
    return open_ports

if __name__ == "__main__":
    run_port_scan("scanme.nmap.org", [21, 22, 80, 443, 8080])
