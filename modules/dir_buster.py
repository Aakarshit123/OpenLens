# modules/dir_buster.py
"""
Directory Buster Module
Brute-forces common directories and files on the target web server.

Soft-404 detection:
  Before scanning, probes two random junk paths to establish a baseline.
  Any response whose (status_code, content_length_bucket) matches the
  baseline is treated as a 404 and excluded — even if the server returns 200.
"""

import requests
import concurrent.futures
import uuid
import urllib3
from config import Config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WORDLIST = [
    # Admin & Control panels
    "admin", "administrator", "admin/login", "admin/dashboard", "wp-admin",
    "cpanel", "phpmyadmin", "pma", "adminer", "webmin", "plesk",
    "manager", "management", "control", "panel", "backend",
    # Auth & user
    "login", "signin", "signup", "register", "logout", "auth",
    "account", "accounts", "user", "users", "profile", "dashboard",
    "portal", "member", "members",
    # Dev & config
    "api", "api/v1", "api/v2", "api/v3", "rest", "graphql",
    "swagger", "swagger-ui", "swagger-ui.html", "api-docs", "openapi.json",
    "config", "configuration", ".env", "settings", ".git",
    ".git/config", ".git/HEAD", "Dockerfile", "docker-compose.yml",
    ".htaccess", ".htpasswd", "web.config", "robots.txt", "sitemap.xml",
    "security.txt", ".well-known/security.txt",
    # Backup & sensitive files
    "backup", "backups", "bak", "old", "archive", "dump",
    "db.sql", "database.sql", "backup.sql", "backup.zip",
    "wp-config.php", "config.php", "database.php",
    # Devops & monitoring
    "jenkins", "gitlab", "github", "ci", "cd", "deploy",
    "monitoring", "grafana", "kibana", "prometheus", "zabbix",
    "status", "health", "healthcheck", "metrics", "actuator",
    "actuator/health", "actuator/env", "actuator/mappings",
    # Content & CMS
    "blog", "news", "wp-content", "wp-includes", "wp-json",
    "xmlrpc.php", "feed", "rss", "atom", "sitemap_index.xml",
    "uploads", "files", "media", "assets", "static",
    "images", "img", "css", "js", "scripts",
    # Info disclosure
    "info.php", "phpinfo.php", "test.php", "debug", "trace",
    "error", "errors", "logs", "log", "server-status",
    "server-info", "readme", "README.md", "CHANGELOG", "VERSION",
    # Common apps
    "shop", "store", "cart", "checkout", "payment",
    "mail", "webmail", "email", "smtp", "ftp",
    "forum", "community", "support", "help", "docs", "documentation",
    "wiki", "kb", "confluence", "jira", "redmine",
    # Cloud & infra
    "s3", "storage", "bucket", "cdn", "proxy",
    "internal", "private", "secret", "hidden", "secure",
]

INTERESTING_STATUSES = {200, 301, 302, 403, 401, 405}

# Content-length tolerance: responses within ±5% of the baseline length
# are considered soft-404s.
SOFT404_TOLERANCE = 0.05


def _size_bucket(length: int) -> int:
    """Round content length to nearest 50 bytes to allow minor variation."""
    return round(length / 50) * 50


class DirBuster:
    def __init__(self, target: str, threads: int = 30):
        self.target = target
        self.domain = target.replace("www.", "")
        self.threads = threads
        self.config = Config()
        self.headers = {
            "User-Agent": self.config.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        self.base_url = f"https://{self.domain}"
        # Soft-404 baseline: set of (status_code, size_bucket) tuples
        self._soft404_signatures: set = set()

    def _fetch(self, path: str) -> requests.Response | None:
        """Fetch a path, falling back to HTTP on SSL errors."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        try:
            return requests.get(url, headers=self.headers, timeout=8,
                                allow_redirects=False, verify=False), url
        except requests.exceptions.SSLError:
            http_url = url.replace("https://", "http://")
            try:
                return requests.get(http_url, headers=self.headers, timeout=6,
                                    allow_redirects=False), http_url
            except Exception:
                return None, url
        except Exception:
            return None, url

    def _establish_baseline(self):
        """
        Probe two guaranteed-nonexistent random paths to learn what a 404
        looks like on this server (handles soft-404 / catch-all pages).
        """
        for _ in range(2):
            junk = f"__osint_probe_{uuid.uuid4().hex[:12]}__"
            resp, _ = self._fetch(junk)
            if resp is not None:
                sig = (resp.status_code, _size_bucket(len(resp.content)))
                self._soft404_signatures.add(sig)

    def _is_soft404(self, status: int, content_length: int) -> bool:
        """Return True if this response matches the soft-404 baseline."""
        bucket = _size_bucket(content_length)
        for (base_status, base_bucket) in self._soft404_signatures:
            if status == base_status:
                # Allow ±SOFT404_TOLERANCE relative difference in size
                if base_bucket == 0:
                    if bucket == 0:
                        return True
                else:
                    diff = abs(bucket - base_bucket) / base_bucket
                    if diff <= SOFT404_TOLERANCE:
                        return True
        return False

    def probe(self, path: str) -> dict | None:
        """Probe a single path and return result if genuinely interesting."""
        resp, url = self._fetch(path)
        if resp is None:
            return None

        status = resp.status_code
        content_length = len(resp.content)

        # Hard-filter: only consider interesting status codes
        if status not in INTERESTING_STATUSES:
            return None

        # Soft-404 filter: skip responses that look like the 404 baseline
        if self._is_soft404(status, content_length):
            return None

        return {
            "path": f"/{path.lstrip('/')}",
            "url": url,
            "status": status,
            "status_label": _status_label(status),
            "content_length": content_length,
            "redirect": resp.headers.get("Location", ""),
            "content_type": resp.headers.get("Content-Type", "").split(";")[0],
        }

    def run(self) -> list:
        """Establish baseline, then scan concurrently."""
        self._establish_baseline()

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.probe, path): path for path in WORDLIST}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)

        results.sort(key=lambda x: (x["status"], x["path"]))
        return results


def _status_label(code: int) -> str:
    labels = {
        200: "OK", 301: "Redirect", 302: "Found",
        401: "Unauthorized", 403: "Forbidden", 405: "Not Allowed"
    }
    return labels.get(code, str(code))
