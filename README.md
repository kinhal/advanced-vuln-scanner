# Interactive Ethical Hacking Web Scanner

A simple, standalone Python tool for scanning websites for common vulnerabilities and sensitive paths. Designed for ethical hackers and security testers to quickly identify potential security issues.

---

## Features

- Scans a predefined list of common sensitive paths (e.g., `/admin`, `/phpinfo.php`, `.git/`, etc.)
- Detects potential vulnerabilities such as:
  - Local File Inclusion (LFI)
  - Basic SQL Injection (SQLi)
  - Common error messages indicating misconfigurations or leaks
- Multi-threaded for faster scanning
- Outputs results directly to the terminal (no external files required)
- Easy to use with interactive prompt — just run and enter the target URL

---

## Requirements

- Python 3.6+
- `requests` library
- `urllib3` library

Install dependencies:

```bash
pip install -r requirements.txt
