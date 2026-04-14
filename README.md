# Simple Python Vulnerability Scanner

A basic vulnerability scanner written in Python. This tool performs port scanning, HTTP security headers analysis, and simple tests for XSS and SQLi via URL parameter injection.

> **Disclaimer**: This tool is for educational purposes only. Only scan targets you own or have explicit permission to test. Web scanning can be disruptive and trigger security alarms.

## Features

- **Port Scanning**: Multi-threaded TCP port scanner.
- **Security Headers Check**: Checks for missing critical security headers like `Strict-Transport-Security`, `Content-Security-Policy`, and others.
- **XSS & SQLi Fuzzing**: Appends basic payloads to the URL to detect naive reflection or SQL syntax errors on the target page.

## Installation

1. Ensure you have Python 3 installed.
2. Clone the repository:
   ```bash
   git clone https://github.com/muhammed95rafi-arch/vulnurbilty-scanner.git
   cd vulnurbilty-scanner
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the scanner by providing a target URL or IP:

```bash
python main.py http://example.com
```

### Options

- `target`: The URL or IP to scan.
- `-p, --ports`: Specify a comma-separated list of ports (e.g., `80,443,8080`) or use `common` (default).
- `--skip-ports`: Skip the port scanning phase.
- `--skip-web`: Skip testing for web vulnerabilities.

### Examples

Scan both ports and web vulnerabilities (default behavior):
```bash
python main.py http://testphp.vulnweb.com
```

Only check specified ports:
```bash
python main.py scanme.nmap.org -p 22,80,443 --skip-web
```
