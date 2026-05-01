# modules/email_harvest.py
"""
Email Harvesting Module
Scrapes emails from search engines and uses Hunter.io API if key is available.
"""

import re
import requests
from config import Config

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


class EmailHarvester:
    def __init__(self, target: str):
        self.target = target
        self.domain = target.replace("www.", "")
        self.emails = set()
        self.config = Config()
        # Fix: build headers after instantiation (was referencing Config.USER_AGENT at class scope)
        self.headers = {"User-Agent": self.config.USER_AGENT}

    def scrape_bing(self) -> set:
        emails = set()
        query = f"@{self.domain}"
        try:
            url = f"https://www.bing.com/search?q={query}&count=50"
            resp = requests.get(url, headers=self.headers, timeout=10)
            found = EMAIL_REGEX.findall(resp.text)
            for e in found:
                if self.domain in e:
                    emails.add(e.lower())
        except Exception:
            pass
        return emails

    def scrape_target_website(self) -> set:
        emails = set()
        pages = [
            f"https://{self.domain}",
            f"https://{self.domain}/contact",
            f"https://{self.domain}/about",
            f"https://{self.domain}/team",
        ]
        for page in pages:
            try:
                resp = requests.get(page, headers=self.headers, timeout=8)
                found = EMAIL_REGEX.findall(resp.text)
                for e in found:
                    if self.domain in e:
                        emails.add(e.lower())
            except Exception:
                pass
        return emails

    def hunter_io(self) -> list:
        results = []
        if not self.config.HUNTER_API_KEY:
            return results
        try:
            url = "https://api.hunter.io/v2/domain-search"
            params = {"domain": self.domain, "api_key": self.config.HUNTER_API_KEY, "limit": 100}
            resp = requests.get(url, params=params, timeout=10)
            data = resp.json()
            for email_data in data.get("data", {}).get("emails", []):
                results.append({
                    "email": email_data.get("value"),
                    "first_name": email_data.get("first_name", ""),
                    "last_name": email_data.get("last_name", ""),
                    "position": email_data.get("position", ""),
                    "source": "hunter.io"
                })
                self.emails.add(email_data.get("value", ""))
        except Exception:
            pass
        return results

    def run(self) -> list:
        results = []
        scraped = self.scrape_bing() | self.scrape_target_website()
        for email in scraped:
            if email not in self.emails:
                self.emails.add(email)
                results.append({"email": email, "source": "scraping"})
        results.extend(self.hunter_io())
        return results
