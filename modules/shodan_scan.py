# modules/shodan_scan.py
"""
Shodan Scanner Module
Uses Shodan API to find open ports, services, and vulnerabilities for the target IP.
"""

import socket
import shodan


class ShodanScanner:
    def __init__(self, target: str, api_key: str):
        self.target = target
        self.api = shodan.Shodan(api_key)

    def resolve_ip(self) -> str:
        try:
            return socket.gethostbyname(self.target)
        except Exception:
            return None

    def run(self) -> list:
        results = []
        ip = self.resolve_ip()
        if not ip:
            return results

        try:
            host = self.api.host(ip)
            for item in host.get("data", []):
                entry = {
                    "ip": ip,
                    "port": item.get("port"),
                    "protocol": item.get("transport", "tcp"),
                    "service": item.get("_shodan", {}).get("module", "unknown"),
                    "banner": item.get("data", "")[:200],
                    "product": item.get("product", ""),
                    "version": item.get("version", ""),
                    "cpe": item.get("cpe", []),
                    "vulns": list(item.get("vulns", {}).keys()),
                    "org": host.get("org", ""),
                    "isp": host.get("isp", ""),
                    "country": host.get("country_name", ""),
                    "os": host.get("os", ""),
                    "hostnames": host.get("hostnames", []),
                    "tags": host.get("tags", []),
                }
                results.append(entry)
        except shodan.APIError as e:
            results.append({"error": str(e), "ip": ip})
        except Exception as e:
            results.append({"error": str(e), "ip": ip})

        return results
