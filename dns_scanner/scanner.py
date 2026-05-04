"""Server/domain configuration, multi-server scanning, block detection, and performance tests."""
import statistics
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional

from .client import QueryResult, query_udp, query_dot

# ---------------------------------------------------------------------------
# DNS server list
# ---------------------------------------------------------------------------

# Value tuple: (ip_or_hostname, filter_category)
DNS_SERVERS: dict[str, tuple[str, str]] = {
    # No filtering
    "Google":                   ("8.8.8.8",          "none"),
    "Google (secondary)":       ("8.8.4.4",          "none"),
    "Cloudflare":               ("1.1.1.1",          "none"),
    "Cloudflare (secondary)":   ("1.0.0.1",          "none"),
    "Quad9 (no filter)":        ("9.9.9.10",         "none"),
    "Verisign":                 ("64.6.64.6",        "none"),
    "Control D":                ("76.76.2.0",        "none"),
    "DNS.Watch":                ("84.200.69.80",     "none"),
    "Yandex DNS":               ("77.88.8.8",        "none"),
    "Level3":                   ("209.244.0.3",      "none"),
    # Security filtering (malware/phishing)
    "Quad9":                    ("9.9.9.9",          "security"),
    "OpenDNS":                  ("208.67.222.222",   "security"),
    "CleanBrowsing Security":   ("185.228.168.9",    "security"),
    "AdGuard DNS":              ("94.140.14.14",     "security"),
    "Comodo Secure":            ("8.26.56.26",       "security"),
    "Norton ConnectSafe":       ("199.85.126.10",    "security"),
    # Family filtering (adult + security)
    "Cloudflare Family":        ("1.1.1.3",          "family"),
    "OpenDNS FamilyShield":     ("208.67.222.123",  "family"),
    "CleanBrowsing Family":     ("185.228.168.168", "family"),
    "AdGuard Family":           ("94.140.14.15",     "family"),
}

DOT_SERVERS: dict[str, tuple[str, str]] = {
    "Google DoT":     ("dns.google",      "none"),
    "Cloudflare DoT": ("one.one.one.one", "none"),
    "Quad9 DoT":      ("dns.quad9.net",   "security"),
}

# ---------------------------------------------------------------------------
# Test domains
# ---------------------------------------------------------------------------

TEST_DOMAINS: list[tuple[str, str]] = [
    ("www.example.com",     "control — no server should block this"),
    ("www.pucrs.br",        "regional control"),
    ("internetbadguys.com", "OpenDNS test domain — blocked by security filters"),
    ("reddit.com",          "social network — potentially blocked by family filters"),
    ("tinder.com",          "dating app — potentially blocked by family filters"),
    ("polymarket.com",      "blocked in Brazil by court order (Anatel)"),
    ("www.google.com",      "additional control"),
    ("thepiratebay.org",    "potentially blocked"),
    ("bet365.com",          "gambling — blocked in Brazil"),
]

# ---------------------------------------------------------------------------
# Block detection
# ---------------------------------------------------------------------------

NULL_IPS = {"0.0.0.0", "127.0.0.1", "::"}

BLOCK_REASONS = {
    "NXDOMAIN":     "Domain does not exist (possible block)",
    "REFUSED":      "Query refused by server",
    "SERVFAIL":     "Server failure",
    "TIMEOUT":      "No response (timeout)",
    "NULL_IP":      "Null address returned (0.0.0.0 / 127.0.0.1)",
    "DIVERGENT_IP": "IP differs from consensus (possible redirect)",
    "NO_RECORDS":   "No A records in response",
}


def detect_blocks(results: list[QueryResult]) -> dict[str, tuple[str, list[str]]]:
    """Analyse results and return a mapping of server_name -> (block_type, ips).

    Consensus IPs are derived from unfiltered servers that returned NOERROR.
    A server is flagged only when its response clearly deviates from that consensus.
    """
    # Build consensus from unfiltered servers that returned NOERROR with IPs
    unfiltered_ips: list[str] = []
    for r in results:
        if r.filter_type == "none" and r.rcode == 0 and r.ips:
            unfiltered_ips.extend(r.ips)

    consensus: set[str] = set()
    if unfiltered_ips:
        counts = Counter(unfiltered_ips)
        max_count = max(counts.values())
        consensus = {ip for ip, c in counts.items() if c >= max(1, max_count // 2)}

    # Check whether the majority of servers resolve the domain successfully
    noerror_with_ips = sum(1 for r in results if r.rcode == 0 and r.ips)
    majority_resolves = noerror_with_ips >= len(results) // 2

    # TIMEOUT is only suspicious when most servers actually responded
    majority_responded = sum(1 for r in results if r.response is not None) >= len(results) // 2

    blocks: dict[str, tuple[str, list[str]]] = {}
    for r in results:
        name = r.server_name or r.server_ip

        if r.error == "TIMEOUT":
            # Flag only if most other servers responded fine — otherwise it's
            # a domain/infrastructure issue, not selective blocking.
            if majority_responded:
                blocks[name] = ("TIMEOUT", [])
            continue
        if r.response is None:
            if majority_responded:
                blocks[name] = (r.error or "NO_RECORDS", [])
            continue

        rcode = r.rcode
        ips = r.ips

        if rcode == 3:  # NXDOMAIN — flag only when most servers resolve fine
            if majority_resolves:
                blocks[name] = ("NXDOMAIN", [])
        elif rcode == 5:  # REFUSED
            blocks[name] = ("REFUSED", [])
        elif rcode == 2:  # SERVFAIL
            blocks[name] = ("SERVFAIL", [])
        elif rcode == 0:
            ip_set = set(ips)
            null_found = ip_set & NULL_IPS
            if null_found:
                blocks[name] = ("NULL_IP", list(ip_set))
            elif consensus and ip_set and not ip_set.intersection(consensus):
                blocks[name] = ("DIVERGENT_IP", list(ip_set))
            elif not ips:
                blocks[name] = ("NO_RECORDS", [])

    return blocks


# ---------------------------------------------------------------------------
# Multi-server scan
# ---------------------------------------------------------------------------

def scan_domain(
    domain: str,
    servers: Optional[dict[str, tuple[str, str]]] = None,
    timeout: float = 3.0,
    max_workers: int = 20,
) -> list[QueryResult]:
    """Query the domain against all configured servers in parallel."""
    if servers is None:
        servers = DNS_SERVERS

    results: list[QueryResult] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(query_udp, domain, ip, name, ft, 53, timeout): name
            for name, (ip, ft) in servers.items()
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r.server_name)
    return results


# ---------------------------------------------------------------------------
# Performance evaluation
# ---------------------------------------------------------------------------

@dataclass
class PerfStats:
    server_name: str
    server_ip: str
    filter_type: str
    domain: str
    protocol: str
    n_queries: int
    n_success: int
    avg_ms: float
    min_ms: float
    max_ms: float
    loss_rate: float

    @property
    def loss_pct(self) -> str:
        return f"{self.loss_rate * 100:.0f}%"


def perf_test(
    domain: str,
    server_name: str,
    server_ip: str,
    filter_type: str = "",
    n: int = 10,
    protocol: str = "udp",
    timeout: float = 3.0,
) -> PerfStats:
    """Run n queries and compute min/avg/max latency and packet loss."""
    times: list[float] = []
    errors = 0

    for _ in range(n):
        if protocol == "udp":
            result = query_udp(domain, server_ip, server_name, filter_type, timeout=timeout)
        else:
            result = query_dot(domain, server_ip, server_name, filter_type, timeout=10.0)

        if result.success and result.rcode == 0:
            times.append(result.elapsed_ms)
        else:
            errors += 1

    if times:
        avg = statistics.mean(times)
        mn = min(times)
        mx = max(times)
    else:
        avg = mn = mx = 0.0

    return PerfStats(
        server_name=server_name,
        server_ip=server_ip,
        filter_type=filter_type,
        domain=domain,
        protocol=protocol,
        n_queries=n,
        n_success=len(times),
        avg_ms=avg,
        min_ms=mn,
        max_ms=mx,
        loss_rate=errors / n,
    )


def perf_test_all(
    domain: str,
    servers: Optional[dict[str, tuple[str, str]]] = None,
    n: int = 10,
    max_workers: int = 10,
) -> list[PerfStats]:
    """Run performance tests against all servers in parallel, sorted by avg latency."""
    if servers is None:
        servers = DNS_SERVERS

    stats_list: list[PerfStats] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(perf_test, domain, name, ip, ft, n): name
            for name, (ip, ft) in servers.items()
        }
        for future in as_completed(futures):
            stats_list.append(future.result())

    stats_list.sort(key=lambda s: (s.avg_ms if s.n_success > 0 else float("inf")))
    return stats_list
