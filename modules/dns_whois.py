# modules/dns_whois.py
"""
DNS & WHOIS Scanner Module
Gathers DNS records (A, MX, TXT, NS, CNAME) and WHOIS registration info.

Returns a structured dict with separate keys so DNS record count is accurate:
  {
    "records": [...],   # actual DNS records only
    "whois":   {...},   # WHOIS data
    "ip_info": {...},   # IP / reverse-DNS
  }
"""

import socket
import whois
import dns.resolver
import dns.reversename
from datetime import datetime


class DNSWhoisScanner:
    def __init__(self, target: str):
        self.target = target

    def get_dns_records(self) -> list:
        records = []
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(self.target, rtype, lifetime=5)
                for rdata in answers:
                    records.append({
                        "type": rtype,
                        "value": str(rdata),
                        "ttl": answers.ttl
                    })
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
            except Exception:
                pass

        return records

    def get_whois_info(self) -> dict:
        try:
            w = whois.whois(self.target)
            return {
                "registrar": str(w.registrar) if w.registrar else "N/A",
                "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
                "expiration_date": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date),
                "updated_date": str(w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date),
                "name_servers": w.name_servers if w.name_servers else [],
                "status": w.status if w.status else "N/A",
                "emails": w.emails if w.emails else [],
                "org": str(w.org) if w.org else "N/A",
                "country": str(w.country) if w.country else "N/A",
            }
        except Exception as e:
            return {"error": str(e)}

    def get_ip_info(self) -> dict:
        try:
            ip = socket.gethostbyname(self.target)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = "N/A"
            return {"ip": ip, "reverse_dns": hostname}
        except Exception:
            return {"ip": "N/A", "reverse_dns": "N/A"}

    def run(self) -> dict:
        """
        Returns a dict with three separate keys so callers can count
        DNS records independently from WHOIS / IP data.
        """
        return {
            "records": self.get_dns_records(),
            "whois":   self.get_whois_info(),
            "ip_info": self.get_ip_info(),
        }
