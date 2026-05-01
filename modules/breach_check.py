# modules/breach_check.py
"""
Breach Check Module
Uses HaveIBeenPwned API to check if harvested emails appear in known data breaches.
"""

import requests
import time


class BreachChecker:
    def __init__(self, emails: list, api_key: str):
        self.emails = [e["email"] if isinstance(e, dict) else e for e in emails]
        self.api_key = api_key
        self.headers = {
            "hibp-api-key": self.api_key,
            "User-Agent": "OSINT-Framework-Research-Tool"
        }

    def check_email(self, email: str) -> dict:
        """Check a single email against HIBP API."""
        result = {"email": email, "breached": False, "breaches": []}
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            params = {"truncateResponse": "false"}
            resp = requests.get(url, headers=self.headers, params=params, timeout=10)

            if resp.status_code == 200:
                breaches = resp.json()
                result["breached"] = True
                result["breaches"] = [
                    {
                        "name": b.get("Name"),
                        "domain": b.get("Domain"),
                        "breach_date": b.get("BreachDate"),
                        "pwn_count": b.get("PwnCount"),
                        "data_classes": b.get("DataClasses", []),
                        "is_verified": b.get("IsVerified"),
                        "is_sensitive": b.get("IsSensitive"),
                    }
                    for b in breaches
                ]
            elif resp.status_code == 404:
                result["breached"] = False
            elif resp.status_code == 429:
                result["error"] = "Rate limited by HIBP API"
        except Exception as e:
            result["error"] = str(e)

        return result

    def run(self) -> list:
        results = []
        for email in self.emails:
            result = self.check_email(email)
            results.append(result)
            time.sleep(1.6)  # HIBP rate limit: 1 req/1.5s
        return results
