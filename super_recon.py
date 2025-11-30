#!/usr/bin/env python3
"""
Super Reconnaissance Tool (free/open-source components only)

USE ONLY ON TARGETS YOU OWN OR ARE AUTHORIZED TO TEST.

Features:
- Target normalization (domain/IP/URL)
- Passive recon:
  - DNS records (A, AAAA, CNAME, MX, NS, TXT)
  - WHOIS summary
  - HTTP(S) headers
  - Basic tech fingerprinting
  - Subdomains via crt.sh
- Active recon:
  - Simple TCP connect scan on configurable ports
  - Basic banner grabbing
- Web recon:
  - robots.txt collection
  - Small crawler within same domain
  - Link and form discovery
- Reporting:
  - Human-readable console output
  - JSON output
  - Optional Markdown report file
"""

import argparse
import json
import socket
import ssl
import sys
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup
import dns.resolver
import dns.exception
import whois
import tldextract
import textwrap
import time


# =========================
# Data models
# =========================

@dataclass
class TargetInfo:
    raw: str
    scheme: str
    hostname: str
    ip: Optional[str]
    port: Optional[int]


@dataclass
class DNSRecords:
    A: List[str] = field(default_factory=list)
    AAAA: List[str] = field(default_factory=list)
    CNAME: List[str] = field(default_factory=list)
    MX: List[str] = field(default_factory=list)
    NS: List[str] = field(default_factory=list)
    TXT: List[str] = field(default_factory=list)


@dataclass
class PassiveResult:
    dns: DNSRecords
    whois_summary: Dict[str, Any]
    http_headers: Dict[str, str]
    technologies: List[str]
    subdomains: List[str]


@dataclass
class ActiveResult:
    open_ports: List[int]
    banners: Dict[int, str]


@dataclass
class WebPageInfo:
    url: str
    title: Optional[str]
    status_code: Optional[int]


@dataclass
class WebResult:
    robots_txt: str
    crawled_pages: List[WebPageInfo]
    links: List[str]
    forms: List[str]


@dataclass
class ReconResult:
    target: TargetInfo
    passive: Optional[PassiveResult]
    active: Optional[ActiveResult]
    web: Optional[WebResult]


# =========================
# Target normalization
# =========================

def normalize_target(raw: str, default_scheme: str = "https") -> TargetInfo:
    if "://" not in raw:
        raw_with_scheme = f"{default_scheme}://{raw}"
    else:
        raw_with_scheme = raw

    parsed = urlparse(raw_with_scheme)
    hostname = parsed.hostname or raw
    port = parsed.port

    # Resolve IP
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = None

    return TargetInfo(
        raw=raw,
        scheme=parsed.scheme or default_scheme,
        hostname=hostname,
        ip=ip,
        port=port,
    )


# =========================
# Passive recon helpers
# =========================

def dns_query(hostname: str, rtype: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(hostname, rtype)
        values = []
        for r in answers:
            val = str(r.to_text()).strip()
            values.append(val)
        return sorted(set(values))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.Timeout, dns.exception.DNSException):
        return []


def collect_dns_records(hostname: str) -> DNSRecords:
    records = DNSRecords()
    records.A = dns_query(hostname, "A")
    records.AAAA = dns_query(hostname, "AAAA")
    records.CNAME = dns_query(hostname, "CNAME")
    records.MX = dns_query(hostname, "MX")
    records.NS = dns_query(hostname, "NS")
    records.TXT = dns_query(hostname, "TXT")
    return records


def fetch_whois(hostname: str) -> Dict[str, Any]:
    try:
        w = whois.whois(hostname)
        # whois object is not always JSON-serializable; pick key fields
        summary = {
            "domain_name": str(w.domain_name) if hasattr(w, "domain_name") else None,
            "registrar": getattr(w, "registrar", None),
            "creation_date": str(getattr(w, "creation_date", None)),
            "expiration_date": str(getattr(w, "expiration_date", None)),
            "updated_date": str(getattr(w, "updated_date", None)),
            "name_servers": list(w.name_servers) if getattr(w, "name_servers", None) else [],
        }
        return summary
    except Exception:
        return {}


def fetch_http_headers(target: TargetInfo, timeout: int = 8) -> Dict[str, str]:
    url = f"{target.scheme}://{target.hostname}"
    if target.port:
        url = f"{target.scheme}://{target.hostname}:{target.port}"

    headers: Dict[str, str] = {}
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=True)
        for k, v in resp.headers.items():
            headers[k] = v
    except Exception:
        pass
    return headers


def fingerprint_technologies(headers: Dict[str, str], body_sample: str = "") -> List[str]:
    techs: Set[str] = set()
    server = headers.get("Server", "").lower()
    powered_by = headers.get("X-Powered-By", "").lower()

    if "nginx" in server:
        techs.add("nginx")
    if "apache" in server:
        techs.add("apache httpd")
    if "iis" in server:
        techs.add("microsoft iis")
    if "cloudflare" in server:
        techs.add("cloudflare")
    if "php" in powered_by or "php" in body_sample.lower():
        techs.add("php")
    if "asp.net" in powered_by or "asp.net" in body_sample.lower():
        techs.add("asp.net")
    if "django" in body_sample.lower():
        techs.add("django")
    if "wordpress" in body_sample.lower():
        techs.add("wordpress")
    if "laravel" in body_sample.lower():
        techs.add("laravel")
    if "wp-content" in body_sample.lower():
        techs.add("wordpress")
    return sorted(techs)


def fetch_subdomains_crtsh(domain: str, timeout: int = 8) -> List[str]:
    """
    Query crt.sh for subdomains (certificate transparency logs).
    Free, no API key, but be gentle (no rapid-fire loops).
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            return []
        data = resp.json()
        subs: Set[str] = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for line in name_value.split("\n"):
                line = line.strip().lower()
                if line.endswith("." + domain.lower()) or line == domain.lower():
                    subs.add(line)
        return sorted(subs)
    except Exception:
        return []


def extract_registered_domain(hostname: str) -> Optional[str]:
    ext = tldextract.extract(hostname)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"


def run_passive(target: TargetInfo) -> PassiveResult:
    dns_records = collect_dns_records(target.hostname)
    whois_summary = fetch_whois(target.hostname)
    headers = fetch_http_headers(target)

    # Get small body sample for tech fingerprint
    body_sample = ""
    try:
        url = f"{target.scheme}://{target.hostname}"
        if target.port:
            url = f"{target.scheme}://{target.hostname}:{target.port}"
        resp = requests.get(url, timeout=8, allow_redirects=True, verify=True)
        body_sample = resp.text[:5000]
    except Exception:
        pass

    techs = fingerprint_technologies(headers, body_sample=body_sample)

    registered_domain = extract_registered_domain(target.hostname)
    subdomains: List[str] = []
    if registered_domain:
        subdomains = fetch_subdomains_crtsh(registered_domain)

    return PassiveResult(
        dns=dns_records,
        whois_summary=whois_summary,
        http_headers=headers,
        technologies=techs,
        subdomains=subdomains,
    )


# =========================
# Active recon (simple TCP scan)
# =========================

def parse_ports(port_spec: str) -> List[int]:
    ports: List[int] = []
    for part in port_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start_s, end_s = part.split("-", 1)
                start, end = int(start_s), int(end_s)
                for p in range(start, end + 1):
                    if 1 <= p <= 65535:
                        ports.append(p)
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.append(p)
            except ValueError:
                continue
    ports = sorted(set(ports))
    return ports


def scan_tcp_ports(ip: str, ports: List[int], timeout: float = 0.5) -> Dict[int, bool]:
    results: Dict[int, bool] = {}
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            results[port] = True
        except Exception:
            results[port] = False
        finally:
            s.close()
    return results


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> Optional[str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    banner = None
    try:
        s.connect((ip, port))
        try:
            data = s.recv(1024)
            if data:
                banner = data.decode(errors="ignore").strip()
        except Exception:
            banner = None
    except Exception:
        banner = None
    finally:
        s.close()
    return banner


def run_active(target: TargetInfo, port_spec: str) -> ActiveResult:
    if not target.ip:
        return ActiveResult(open_ports=[], banners={})

    ports = parse_ports(port_spec)
    # Basic safety: limit default to smaller sets; user can override
    if len(ports) > 2000:
        ports = ports[:2000]

    scan_results = scan_tcp_ports(target.ip, ports)
    open_ports = [p for p, is_open in scan_results.items() if is_open]

    banners: Dict[int, str] = {}
    for port in open_ports:
        b = grab_banner(target.ip, port)
        if b:
            banners[port] = b

    return ActiveResult(open_ports=open_ports, banners=banners)


# =========================
# Web recon
# =========================

def fetch_robots_txt(target: TargetInfo, timeout: int = 8) -> str:
    url = f"{target.scheme}://{target.hostname}/robots.txt"
    if target.port:
        url = f"{target.scheme}://{target.hostname}:{target.port}/robots.txt"
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200 and "text" in resp.headers.get("Content-Type", ""):
            return resp.text
        return ""
    except Exception:
        return ""


def same_domain(base_hostname: str, url: str) -> bool:
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return True  # relative URL
        return parsed.hostname == base_hostname
    except Exception:
        return False


def crawl_site(target: TargetInfo, max_pages: int = 20, timeout: int = 8) -> WebResult:
    visited: Set[str] = set()
    to_visit: List[str] = []

    base_url = f"{target.scheme}://{target.hostname}"
    if target.port:
        base_url = f"{target.scheme}://{target.hostname}:{target.port}"

    to_visit.append(base_url)
    pages: List[WebPageInfo] = []
    links: Set[str] = set()
    forms: Set[str] = set()

    session = requests.Session()

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
        except Exception:
            pages.append(WebPageInfo(url=url, title=None, status_code=None))
            continue

        # Record page info
        title = None
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            title_tag = soup.find("title")
            if title_tag and title_tag.string:
                title = title_tag.string.strip()
        except Exception:
            title = None

        pages.append(WebPageInfo(url=url, title=title, status_code=resp.status_code))

        # Extract links and forms
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                full_url = urljoin(resp.url, href)
                links.add(full_url)
                if same_domain(target.hostname, full_url) and full_url not in visited and len(visited) + len(to_visit) < max_pages:
                    to_visit.append(full_url)

            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                form_desc = f"{method} {urljoin(resp.url, action)}"
                forms.add(form_desc)
        except Exception:
            # Ignore parsing errors
            pass

        # Be polite, small delay
        time.sleep(0.2)

    robots_txt = fetch_robots_txt(target)
    return WebResult(
        robots_txt=robots_txt,
        crawled_pages=pages,
        links=sorted(links),
        forms=sorted(forms),
    )


def run_web(target: TargetInfo, max_pages: int) -> WebResult:
    return crawl_site(target, max_pages=max_pages)


# =========================
# Reporting
# =========================

def result_to_dict(result: ReconResult) -> Dict[str, Any]:
    return {
        "target": asdict(result.target),
        "passive": asdict(result.passive) if result.passive else None,
        "active": asdict(result.active) if result.active else None,
        "web": asdict(result.web) if result.web else None,
    }


def print_section(title: str) -> None:
    print()
    print("=" * (len(title) + 4))
    print(f"| {title} |")
    print("=" * (len(title) + 4))


def print_human_readable(result: ReconResult) -> None:
    print_section(f"Recon Report for {result.target.raw}")
    print(f"Hostname : {result.target.hostname}")
    print(f"IP       : {result.target.ip or 'unresolved'}")
    print(f"Scheme   : {result.target.scheme}")
    print(f"Port     : {result.target.port or 'default'}")

    if result.passive:
        print_section("Passive Recon")
        dns = result.passive.dns
        print("DNS Records:")
        for rtype in ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]:
            vals = getattr(dns, rtype)
            if vals:
                print(f"  {rtype}:")
                for v in vals:
                    print(f"    - {v}")

        if result.passive.whois_summary:
            print("\nWHOIS (summary):")
            for k, v in result.passive.whois_summary.items():
                if v:
                    print(f"  {k}: {v}")

        if result.passive.http_headers:
            print("\nHTTP Headers (root):")
            for k, v in result.passive.http_headers.items():
                print(f"  {k}: {v}")

        if result.passive.technologies:
            print("\nDetected Technologies:")
            for t in result.passive.technologies:
                print(f"  - {t}")

        if result.passive.subdomains:
            print("\nSubdomains (crt.sh, may contain duplicates or noise):")
            for s in result.passive.subdomains[:50]:
                print(f"  - {s}")
            if len(result.passive.subdomains) > 50:
                print(f"  ... (+{len(result.passive.subdomains) - 50} more)")

    if result.active:
        print_section("Active Recon (TCP Ports)")
        if result.active.open_ports:
            print("Open ports:")
            for p in sorted(result.active.open_ports):
                banner = result.active.banners.get(p)
                if banner:
                    short_banner = (banner[:75] + "...") if len(banner) > 75 else banner
                    print(f"  - {p}/tcp  banner={short_banner!r}")
                else:
                    print(f"  - {p}/tcp")
        else:
            print("No open ports found in scanned range.")

    if result.web:
        print_section("Web Recon")
        if result.web.robots_txt:
            print("robots.txt (first 20 lines):")
            lines = result.web.robots_txt.splitlines()
            for line in lines[:20]:
                print(f"  {line}")
            if len(lines) > 20:
                print(f"  ... (+{len(lines) - 20} more lines)")

        if result.web.crawled_pages:
            print("\nCrawled pages:")
            for page in result.web.crawled_pages:
                status = page.status_code if page.status_code is not None else "?"
                title = page.title or ""
                print(f"  - [{status}] {page.url}  {('- ' + title) if title else ''}")

        if result.web.links:
            print("\nDiscovered links (unique, limited):")
            for link in result.web.links[:50]:
                print(f"  - {link}")
            if len(result.web.links) > 50:
                print(f"  ... (+{len(result.web.links) - 50} more)")

        if result.web.forms:
            print("\nDiscovered forms:")
            for f in result.web.forms:
                print(f"  - {f}")


def write_markdown_report(result: ReconResult, path: str) -> None:
    data = result_to_dict(result)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# Reconnaissance Report for {data['target']['raw']}\n\n")
            f.write("## Target\n")
            f.write(f"- Hostname: {data['target']['hostname']}\n")
            f.write(f"- IP: {data['target']['ip']}\n")
            f.write(f"- Scheme: {data['target']['scheme']}\n")
            f.write(f"- Port: {data['target']['port']}\n\n")

            if data["passive"]:
                f.write("## Passive Recon\n")
                dns = data["passive"]["dns"]
                f.write("### DNS Records\n")
                for rtype, vals in dns.items():
                    if vals:
                        f.write(f"- **{rtype}**:\n")
                        for v in vals:
                            f.write(f"  - {v}\n")
                if data["passive"]["whois_summary"]:
                    f.write("\n### WHOIS Summary\n")
                    for k, v in data["passive"]["whois_summary"].items():
                        if v:
                            f.write(f"- {k}: {v}\n")
                if data["passive"]["http_headers"]:
                    f.write("\n### HTTP Headers\n")
                    for k, v in data["passive"]["http_headers"].items():
                        f.write(f"- {k}: {v}\n")
                if data["passive"]["technologies"]:
                    f.write("\n### Detected Technologies\n")
                    for t in data["passive"]["technologies"]:
                        f.write(f"- {t}\n")
                if data["passive"]["subdomains"]:
                    f.write("\n### Subdomains (crt.sh)\n")
                    for s in data["passive"]["subdomains"]:
                        f.write(f"- {s}\n")

            if data["active"]:
                f.write("\n## Active Recon (TCP Ports)\n")
                if data["active"]["open_ports"]:
                    for p in data["active"]["open_ports"]:
                        banner = data["active"]["banners"].get(str(p)) or data["active"]["banners"].get(p)
                        if banner:
                            f.write(f"- {p}/tcp: `{banner}`\n")
                        else:
                            f.write(f"- {p}/tcp\n")
                else:
                    f.write("- No open ports in scanned range.\n")

            if data["web"]:
                f.write("\n## Web Recon\n")
                if data["web"]["robots_txt"]:
                    f.write("### robots.txt\n")
                    f.write("```text\n")
                    f.write(data["web"]["robots_txt"][:5000])
                    f.write("\n```\n")
                if data["web"]["crawled_pages"]:
                    f.write("\n### Crawled Pages\n")
                    for page in data["web"]["crawled_pages"]:
                        f.write(f"- [{page['status_code']}] {page['url']} - {page.get('title')}\n")
                if data["web"]["links"]:
                    f.write("\n### Discovered Links\n")
                    for link in data["web"]["links"]:
                        f.write(f"- {link}\n")
                if data["web"]["forms"]:
                    f.write("\n### Discovered Forms\n")
                    for form in data["web"]["forms"]:
                        f.write(f"- {form}\n")
    except Exception as e:
        print(f"[!] Failed to write Markdown report to {path}: {e}", file=sys.stderr)


# =========================
# CLI
# =========================

def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Super Recon Tool (for authorized security testing only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              super_recon.py example.com
              super_recon.py https://example.com --ports 80,443,8080
              super_recon.py target.com --no-active --max-pages 30
              super_recon.py 192.0.2.1 --ports 1-1024 --json
              super_recon.py example.com --markdown report.md
            """
        ),
    )
    parser.add_argument("target", help="Target domain, IP, or URL")

    parser.add_argument(
        "--no-passive",
        action="store_true",
        help="Disable passive recon (DNS/WHOIS/headers/tech/subdomains).",
    )
    parser.add_argument(
        "--no-active",
        action="store_true",
        help="Disable active recon (port scan + banners).",
    )
    parser.add_argument(
        "--no-web",
        action="store_true",
        help="Disable web recon (crawler, robots.txt, links/forms).",
    )
    parser.add_argument(
        "--ports",
        default="80,443,8080,8443,22,25,53,110,143,3306,5432",
        help="Ports or ranges, e.g. '80,443,8080' or '1-1024'.",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=20,
        help="Max pages to crawl in web recon.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON only (no pretty report).",
    )
    parser.add_argument(
        "--markdown",
        help="Write a Markdown report to the given file path.",
    )
    return parser.parse_args(argv)


def main(argv: List[str]) -> None:
    args = parse_args(argv)
    target = normalize_target(args.target)

    passive: Optional[PassiveResult] = None
    active: Optional[ActiveResult] = None
    web: Optional[WebResult] = None

    if not args.no_passive:
        passive = run_passive(target)
    if not args.no_active:
        active = run_active(target, args.ports)
    if not args.no_web:
        web = run_web(target, max_pages=args.max_pages)

    result = ReconResult(target=target, passive=passive, active=active, web=web)

    if args.json:
        print(json.dumps(result_to_dict(result), indent=2))
    else:
        print_human_readable(result)

    if args.markdown:
        write_markdown_report(result, args.markdown)


if __name__ == "__main__":
    main(sys.argv[1:])