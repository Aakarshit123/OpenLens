# modules/subdomain.py
"""
Subdomain Enumeration Module
Uses passive DNS sources: crt.sh, HackerTarget, and a wordlist brute-force.
"""

import requests
import socket
import concurrent.futures
import json
from pathlib import Path


WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
    "admin", "vpn", "remote", "dev", "staging", "api", "app",
    "portal", "cloud", "test", "blog", "shop", "store", "cdn",
    "media", "static", "assets", "help", "support", "login",
    "auth", "secure", "dashboard", "beta", "internal", "git",
    "gitlab", "jenkins", "ci", "jira", "confluence", "wiki",
    "docs", "monitor", "status", "mobile", "m", "ws", "wss",
    "db", "database", "mysql", "redis", "elasticsearch", "backup",
    "old", "new", "prod", "production", "uat", "qa", "demo",
]


class SubdomainEnumerator:
    def __init__(self, target: str):
        self.target = target
        self.found = set()

    def query_crt_sh(self) -> set:
        """Query crt.sh certificate transparency logs."""
        results = set()
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub.endswith(self.target) and sub != self.target:
                            results.add(sub.lower())
        except Exception:
            pass
        return results

    def query_hackertarget(self) -> set:
        """Query HackerTarget passive DNS."""
        results = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200 and "error" not in resp.text.lower():
                for line in resp.text.strip().split("\n"):
                    parts = line.split(",")
                    if parts:
                        sub = parts[0].strip()
                        if sub.endswith(self.target) and sub != self.target:
                            results.add(sub.lower())
        except Exception:
            pass
        return results

    def resolve_subdomain(self, subdomain: str):
        """Try to resolve a subdomain to an IP."""
        try:
            ip = socket.gethostbyname(subdomain)
            return {"subdomain": subdomain, "ip": ip, "source": "bruteforce"}
        except Exception:
            return None

    def brute_force(self) -> list:
        """Brute-force subdomains using wordlist."""
        candidates = [f"{word}.{self.target}" for word in WORDLIST]
        resolved = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(self.resolve_subdomain, c): c for c in candidates}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    resolved.append(result)
        return resolved

    def run(self) -> list:
        # Passive enumeration
        passive = self.query_crt_sh() | self.query_hackertarget()

        results = []
        for sub in passive:
            try:
                ip = socket.gethostbyname(sub)
                results.append({"subdomain": sub, "ip": ip, "source": "passive"})
                self.found.add(sub)
            except Exception:
                results.append({"subdomain": sub, "ip": "unresolved", "source": "passive"})

        # Active brute force
        bf_results = self.brute_force()
        for r in bf_results:
            if r["subdomain"] not in self.found:
                results.append(r)
                self.found.add(r["subdomain"])

        return results
