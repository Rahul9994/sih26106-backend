"""
geolocation.py
Resolves a public IP address to geolocation + ISP data using the free
ip-api.com JSON endpoint (no key required, generous rate limits — fine
for a hackathon demo). Falls back to a clearly-marked "unresolved"
record on any network error so the rest of the pipeline never breaks.
"""
import requests

IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query,timezone"

TIMEOUT_SECONDS = 5


def locate_ip(ip: str) -> dict:
    if not ip:
        return _unresolved(ip, "no IP address available")
    try:
        resp = requests.get(IP_API_URL.format(ip=ip), timeout=TIMEOUT_SECONDS)
        data = resp.json()
    except Exception as exc:
        return _unresolved(ip, f"lookup failed: {exc}")

    if data.get("status") != "success":
        return _unresolved(ip, data.get("message", "lookup failed"))

    return {
        "ip": ip,
        "resolved": True,
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "latitude": data.get("lat"),
        "longitude": data.get("lon"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "asn": data.get("as"),
        "timezone": data.get("timezone"),
    }


def _unresolved(ip, reason):
    return {
        "ip": ip,
        "resolved": False,
        "reason": reason,
        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "isp": None,
        "org": None,
        "asn": None,
        "timezone": None,
    }


def locate_all(ips: list) -> list:
    return [locate_ip(ip) for ip in ips[:5]]  # cap lookups for demo speed
