import requests
import threading
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from queue import Queue
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class InteractiveWebScanner:
    COMMON_PATHS = [
        "/", "admin/", "administrator/", "login/", "phpinfo.php", ".git/", "backup.zip",
        "wp-login.php", "config.php", "server-status", "robots.txt", "admin.php", "test.php",
        "vendor/", "env", "debug", "upload/", "uploads/", "dashboard/", "admin/login.php"
    ]

    def __init__(self, base_url, threads=20, timeout=7, user_agent=None):
        self.base_url = base_url if base_url.startswith(("http://", "https://")) else "http://" + base_url
        self.timeout = timeout
        self.user_agent = user_agent or "EthicalScanner/1.0"
        self.threads = threads
        self.queue = Queue()
        self.lock = threading.Lock()
        self.paths = self.COMMON_PATHS
        self.vuln_signatures = self.load_vuln_signatures()

    def load_vuln_signatures(self):
        return {
            "phpinfo": [r"phpinfo\(\)", r"php version", r"system", r"configure command"],
            "database_error": [r"sql syntax", r"mysql_fetch", r"ora-\d+", r"syntax error"],
            "server_error": [r"apache tomcat", r"server error", r"exception", r"stacktrace"],
            "git_repo": [r"\.git", r"repository", r"index of /"],
            "wordpress": [r"wp-content", r"wp-includes", r"wordpress"],
        }

    def test_lfi(self, url):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        if not query:
            return False, None
        for param in query:
            query[param] = ["../../../../../../etc/passwd"]
            new_query = urlencode(query, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            try:
                resp = requests.get(new_url, headers={"User-Agent": self.user_agent}, timeout=self.timeout, verify=False)
                if "root:x:" in resp.text:
                    return True, new_url
            except:
                return False, None
        return False, None

    def test_sql_injection(self, url):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        if not query:
            return False, None
        for param in query:
            original = query[param][0]
            query[param] = [original + "'"]
            new_query = urlencode(query, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            try:
                resp = requests.get(new_url, headers={"User-Agent": self.user_agent}, timeout=self.timeout, verify=False)
                errors = ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark"]
                for err in errors:
                    if err in resp.text.lower():
                        return True, new_url
            except:
                return False, None
        return False, None

    def worker(self):
        headers = {"User-Agent": self.user_agent}
        while not self.queue.empty():
            path = self.queue.get()
            url = urljoin(self.base_url, path)
            try:
                resp = requests.get(url, headers=headers, timeout=self.timeout, allow_redirects=True, verify=False)
                content = resp.text.lower()
                found_vulns = []
                for name, patterns in self.vuln_signatures.items():
                    for pattern in patterns:
                        if re.search(pattern.lower(), content):
                            found_vulns.append(name)
                            break

                # Test LFI
                lfi, lfi_url = self.test_lfi(url)
                if lfi:
                    found_vulns.append(f"LFI detected at {lfi_url}")

                # Test SQLi
                sqli, sqli_url = self.test_sql_injection(url)
                if sqli:
                    found_vulns.append(f"SQL Injection detected at {sqli_url}")

                with self.lock:
                    print(f"[{resp.status_code}] {url}")
                    if found_vulns:
                        print(f"  >> Possible vulnerabilities: {', '.join(found_vulns)}")
            except Exception as e:
                with self.lock:
                    print(f"[ERROR] {url} - {e}")
            self.queue.task_done()

    def run(self):
        for path in self.paths:
            self.queue.put(path)
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        self.queue.join()
        for t in threads:
            t.join()

def main():
    print("=== Interactive Ethical Hacking Web Scanner ===")
    target = input("Enter target website (e.g. http://example.com): ").strip()
    if not target:
        print("No target entered, exiting.")
        return
    scanner = InteractiveWebScanner(target)
    scanner.run()
    input("Scan complete.")

if __name__ == "__main__":
    main()
