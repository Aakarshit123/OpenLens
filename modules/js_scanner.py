# modules/js_scanner.py
"""
JS Scanner Module
1. Crawls the target website to discover all linked JS files.
2. Downloads each JS file.
3. Uses regex (grep-style) to extract API endpoints, fetch/axios calls,
   hardcoded URLs, secrets, and other interesting patterns.
"""

import re
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from config import Config


# ── Patterns to search for inside JS files ──────────────────────────────────
API_PATTERNS = [
    # fetch() calls
    (r'fetch\s*\(\s*[`"\']([^`"\']+)[`"\']', "fetch()"),
    # axios calls
    (r'axios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(\s*[`"\']([^`"\']+)[`"\']\s*', "axios"),
    # XMLHttpRequest
    (r'\.open\s*\(\s*[`"\'][A-Z]+[`"\'],\s*[`"\']([^`"\']+)[`"\']\s*', "XHR"),
    # Generic URL strings (paths starting with / or https?)
    (r'[`"\'](\/?api\/[^\s`"\'<>{}\\]+)[`"\']', "API path"),
    (r'[`"\'](\/?v\d+\/[^\s`"\'<>{}\\]+)[`"\']', "versioned path"),
    (r'[`"\'](\/?rest\/[^\s`"\'<>{}\\]+)[`"\']', "REST path"),
    (r'[`"\'](\/?graphql[^\s`"\'<>{}\\]*)[`"\']', "GraphQL"),
    # Full URLs
    (r'[`"\'](\bhttps?://[^\s`"\'<>{}\\]{8,})[`"\']', "full URL"),
    # Secrets & keys
    (r'(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|bearer)[`"\s:=]+([A-Za-z0-9_\-\.]{16,})', "potential secret"),
    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*[`"\']([^`"\']{4,})[`"\']', "hardcoded password"),
]


class JSScanner:
    def __init__(self, target: str):
        self.target = target
        self.domain = target.replace("www.", "")
        self.config = Config()
        self.headers = {
            "User-Agent": self.config.USER_AGENT,
            "Accept": "*/*",
        }
        self.base_url = f"https://{self.domain}"

    def discover_js_files(self) -> list:
        """Crawl the homepage and one level deep to collect JS file URLs."""
        js_urls = set()
        visited = set()
        to_visit = [self.base_url, f"https://www.{self.domain}"]

        for start_url in to_visit:
            if start_url in visited:
                continue
            visited.add(start_url)
            try:
                resp = requests.get(start_url, headers=self.headers, timeout=10, verify=False)
                soup = BeautifulSoup(resp.text, "html.parser")

                for tag in soup.find_all("script", src=True):
                    src = tag["src"]
                    full = urljoin(start_url, src)
                    # Only collect JS from the same domain or CDN paths
                    if self.domain in full or full.endswith(".js"):
                        js_urls.add(full)

                # Discover second-level pages linked from homepage
                for a in soup.find_all("a", href=True)[:20]:
                    href = urljoin(start_url, a["href"])
                    parsed = urlparse(href)
                    if parsed.netloc and self.domain not in parsed.netloc:
                        continue
                    if href not in visited and href.startswith("http"):
                        try:
                            r2 = requests.get(href, headers=self.headers, timeout=6, verify=False)
                            soup2 = BeautifulSoup(r2.text, "html.parser")
                            for tag in soup2.find_all("script", src=True):
                                full2 = urljoin(href, tag["src"])
                                if self.domain in full2 or full2.endswith(".js"):
                                    js_urls.add(full2)
                            visited.add(href)
                        except Exception:
                            pass

            except Exception:
                pass

        return list(js_urls)

    def download_js(self, url: str) -> str | None:
        """Download a JS file and return its content."""
        try:
            resp = requests.get(url, headers=self.headers, timeout=10, verify=False)
            if resp.status_code == 200 and "javascript" in resp.headers.get("Content-Type", "text/javascript"):
                return resp.text
            elif resp.status_code == 200:
                return resp.text  # Some CDNs return text/plain
        except Exception:
            pass
        return None

    def extract_endpoints(self, js_content: str, source_url: str) -> list:
        """Run all regex patterns against JS content."""
        findings = []
        seen = set()

        for pattern, label in API_PATTERNS:
            try:
                matches = re.findall(pattern, js_content)
                for match in matches:
                    match = match.strip()
                    if len(match) < 4 or match in seen:
                        continue
                    # Filter out common false positives
                    if any(fp in match.lower() for fp in [
                        ".png", ".jpg", ".gif", ".svg", ".css", ".woff",
                        "example.com", "schema.org", "w3.org", "//# sourceMappingURL"
                    ]):
                        continue
                    seen.add(match)
                    findings.append({
                        "type": label,
                        "value": match,
                        "source_js": source_url,
                        "is_secret": "secret" in label.lower() or "password" in label.lower(),
                    })
            except Exception:
                pass

        return findings

    def run(self) -> dict:
        """Main entry point. Returns dict with js_files and api_endpoints."""
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        js_files_info = []
        all_endpoints = []

        js_urls = self.discover_js_files()

        for url in js_urls:
            content = self.download_js(url)
            size = len(content) if content else 0
            endpoints = []

            if content:
                endpoints = self.extract_endpoints(content, url)
                all_endpoints.extend(endpoints)

            js_files_info.append({
                "url": url,
                "size_bytes": size,
                "endpoints_found": len(endpoints),
                "downloaded": content is not None,
            })

        return {
            "js_files": js_files_info,
            "api_endpoints": all_endpoints,
        }
