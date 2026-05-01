# modules/google_dorks.py
"""
Google Dorks Module
Generates targeted Google dork queries and attempts to verify which ones
return actual results by checking Google's response (result count heuristic).
Only dorks that appear to have results are marked as "has_results".
"""

import urllib.parse
import requests
import time
import re
from config import Config


class GoogleDorker:
    def __init__(self, target: str):
        self.target = target
        self.domain = target.replace("www.", "")
        self.config = Config()
        self.headers = {
            "User-Agent": self.config.USER_AGENT,
            "Accept-Language": "en-US,en;q=0.9",
        }

    def generate_dorks(self) -> list:
        """Generate a comprehensive list of dork queries for the target."""
        d = self.domain
        dorks = [
            # Sensitive files
            {"category": "Sensitive Files", "query": f'site:{d} ext:pdf OR ext:doc OR ext:xls OR ext:xlsx OR ext:csv',
             "description": "Exposed documents (PDFs, spreadsheets, Word docs)"},
            {"category": "Sensitive Files", "query": f'site:{d} ext:sql OR ext:bak OR ext:log OR ext:conf',
             "description": "Database dumps, backups, logs, config files"},
            {"category": "Sensitive Files", "query": f'site:{d} ext:env OR ext:ini OR ext:yaml OR ext:yml',
             "description": "Environment and configuration files"},

            # Login & Admin panels
            {"category": "Login Pages", "query": f'site:{d} inurl:login OR inurl:admin OR inurl:signin',
             "description": "Login and admin panel pages"},
            {"category": "Login Pages", "query": f'site:{d} inurl:wp-admin OR inurl:wp-login.php',
             "description": "WordPress admin pages"},
            {"category": "Login Pages", "query": f'site:{d} inurl:phpmyadmin OR inurl:pma',
             "description": "phpMyAdmin instances"},

            # Exposed directories
            {"category": "Directory Listing", "query": f'site:{d} intitle:"Index of /"',
             "description": "Open directory listings"},
            {"category": "Directory Listing", "query": f'site:{d} intitle:"Index of" "parent directory"',
             "description": "Parent directory exposure"},

            # Error pages & debug info
            {"category": "Error & Debug", "query": f'site:{d} "Warning: mysql_" OR "Fatal error" OR "PHP Parse error"',
             "description": "PHP/MySQL error messages leaking info"},
            {"category": "Error & Debug", "query": f'site:{d} intext:"sql syntax" OR intext:"mysql error"',
             "description": "SQL error messages"},
            {"category": "Error & Debug", "query": f'site:{d} "stack trace" OR "debug mode" OR "traceback"',
             "description": "Debug information exposure"},

            # Credentials & keys
            {"category": "Credentials", "query": f'site:{d} intext:"password" filetype:txt OR filetype:log',
             "description": "Password files"},
            {"category": "Credentials", "query": f'site:github.com "{d}" password OR secret OR api_key OR token',
             "description": "GitHub secrets related to target"},
            {"category": "Credentials", "query": f'site:pastebin.com "{d}"',
             "description": "Pastebin mentions of target"},

            # API & Dev
            {"category": "API & Dev", "query": f'site:{d} inurl:api OR inurl:swagger OR inurl:graphql',
             "description": "API endpoints and documentation"},
            {"category": "API & Dev", "query": f'site:{d} inurl:v1 OR inurl:v2 OR inurl:rest',
             "description": "REST API paths"},

            # Cameras & IoT
            {"category": "IoT / Cameras", "query": f'site:{d} inurl:"view/index.shtml" OR inurl:"webcam"',
             "description": "Exposed webcams"},

            # Subdomains via Google
            {"category": "Subdomains", "query": f'site:*.{d} -www',
             "description": "Non-www subdomains indexed by Google"},
        ]
        return dorks

    def check_dork_has_results(self, query: str) -> bool:
        """
        Check if a Google dork query has results by fetching the search page
        and looking for result-count indicators. Returns True if results found.
        Note: Google may block scraping — we use heuristics on the response.
        """
        try:
            encoded = urllib.parse.quote(query)
            url = f"https://www.google.com/search?q={encoded}&num=10"
            resp = requests.get(url, headers=self.headers, timeout=10)

            text = resp.text

            # Heuristics for "no results" page
            no_result_signals = [
                "did not match any documents",
                "No results found",
                "no results",
                "Your search - ",
                "did not match any",
            ]
            for signal in no_result_signals:
                if signal.lower() in text.lower():
                    return False

            # If Google shows result stats, results exist
            if re.search(r'About [\d,]+ results', text):
                return True

            # Blocked by CAPTCHA / rate limit — assume unknown, mark as potential
            if "unusual traffic" in text.lower() or "captcha" in text.lower():
                return None  # unknown

            # If we got a proper HTML page with search results structure
            if 'id="search"' in text or 'data-sokoban-container' in text:
                return True

            return None  # uncertain
        except Exception:
            return None

    def get_search_urls(self, dorks: list) -> list:
        """Build clickable Google search URLs for each dork."""
        results = []
        for dork in dorks:
            encoded = urllib.parse.quote(dork["query"])
            url = f"https://www.google.com/search?q={encoded}"
            results.append({
                "category": dork["category"],
                "query": dork["query"],
                "description": dork["description"],
                "url": url,
                "has_results": None,  # will be populated in run()
            })
        return results

    def run(self) -> list:
        dorks = self.generate_dorks()
        results = self.get_search_urls(dorks)

        # Attempt result-checking with rate limiting
        for i, item in enumerate(results):
            has = self.check_dork_has_results(item["query"])
            item["has_results"] = has
            if i < len(results) - 1:
                time.sleep(2.5)  # avoid Google rate limiting

        return results
