"""Configurações de servidores/domínios, varredura multi-servidor e detecção de bloqueio."""
import statistics
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional

from .client import QueryResult, query_udp, query_dot

# ---------------------------------------------------------------------------
# Servidores DNS configurados
# ---------------------------------------------------------------------------

# Tupla: (ip_ou_hostname, categoria_filtro)
DNS_SERVERS: dict[str, tuple[str, str]] = {
    # Sem filtragem
    "Google":                   ("8.8.8.8",          "nenhum"),
    "Google (secundário)":      ("8.8.4.4",          "nenhum"),
    "Cloudflare":               ("1.1.1.1",          "nenhum"),
    "Cloudflare (secundário)":  ("1.0.0.1",          "nenhum"),
    "Quad9 (sem filtro)":       ("9.9.9.10",         "nenhum"),
    "Verisign":                 ("64.6.64.6",        "nenhum"),
    "Control D":                ("76.76.2.0",        "nenhum"),
    "DNS.Watch":                ("84.200.69.80",     "nenhum"),
    "Yandex DNS":               ("77.88.8.8",        "nenhum"),
    "Level3":                   ("209.244.0.3",      "nenhum"),
    # Filtragem de segurança (malware/phishing)
    "Quad9":                    ("9.9.9.9",          "segurança"),
    "OpenDNS":                  ("208.67.222.222",   "segurança"),
    "CleanBrowsing Security":   ("185.228.168.9",    "segurança"),
    "AdGuard DNS":              ("94.140.14.14",     "segurança"),
    "Comodo Secure":            ("8.26.56.26",       "segurança"),
    "Norton ConnectSafe":       ("199.85.126.10",    "segurança"),
    # Filtragem familiar (adulto + segurança)
    "Cloudflare Family":        ("1.1.1.3",          "família"),
    "OpenDNS FamilyShield":     ("208.67.222.123",  "família"),
    "CleanBrowsing Family":     ("185.228.168.168", "família"),
    "AdGuard Family":           ("94.140.14.15",     "família"),
}

DOT_SERVERS: dict[str, tuple[str, str]] = {
    "Google DoT":     ("dns.google",      "nenhum"),
    "Cloudflare DoT": ("one.one.one.one", "nenhum"),
    "Quad9 DoT":      ("dns.quad9.net",   "segurança"),
}

# ---------------------------------------------------------------------------
# Domínios de teste
# ---------------------------------------------------------------------------

TEST_DOMAINS: list[tuple[str, str]] = [
    ("www.example.com",     "controle — nenhum deveria bloquear"),
    ("www.pucrs.br",        "controle regional"),
    ("internetbadguys.com", "teste OpenDNS — bloqueado por segurança"),
    ("reddit.com",          "rede social — potenc. bloqueado familiar"),
    ("tinder.com",          "aplicativo — potenc. bloqueado familiar"),
    ("polymarket.com",      "bloqueado no BR (ordem judicial Anatel)"),
    ("www.google.com",      "controle adicional"),
    ("thepiratebay.org",    "potencialmente bloqueado"),
    ("bet365.com",          "apostas — bloqueado no BR"),
]

# ---------------------------------------------------------------------------
# Detecção de bloqueio
# ---------------------------------------------------------------------------

NULL_IPS = {"0.0.0.0", "127.0.0.1", "::"}

BLOCK_REASONS = {
    "NXDOMAIN":      "Domínio inexistente (possível bloqueio)",
    "REFUSED":       "Consulta recusada",
    "SERVFAIL":      "Falha no servidor",
    "TIMEOUT":       "Sem resposta (timeout)",
    "NULL_IP":       "Endereço nulo (0.0.0.0 / 127.0.0.1)",
    "IP_DIVERGENTE": "IP diferente do consenso (possível redirecionamento)",
    "SEM_RESPOSTA":  "Sem registros A na resposta",
}


def detect_blocks(results: list[QueryResult]) -> dict[str, tuple[str, list[str]]]:
    """Analisa os resultados e retorna dict server_name → (tipo_bloqueio, ips)."""
    # Estabelece consenso a partir de servidores sem filtro que responderam NOERROR com IPs
    no_filter_ips: list[str] = []
    for r in results:
        if r.filter_type == "nenhum" and r.rcode == 0 and r.ips:
            no_filter_ips.extend(r.ips)

    consensus: set[str] = set()
    if no_filter_ips:
        counts = Counter(no_filter_ips)
        max_count = max(counts.values())
        # IPs que aparecem com frequência majoritária entre servidores sem filtro
        consensus = {ip for ip, c in counts.items() if c >= max(1, max_count // 2)}

    # Determina se a maioria dos servidores resolve normalmente
    noerror_with_ips = sum(1 for r in results if r.rcode == 0 and r.ips)
    majority_resolves = noerror_with_ips >= len(results) // 2

    blocks: dict[str, tuple[str, list[str]]] = {}
    for r in results:
        name = r.server_name or r.server_ip

        if r.error == "TIMEOUT":
            blocks[name] = ("TIMEOUT", [])
            continue
        if r.response is None:
            blocks[name] = (r.error or "SEM_RESPOSTA", [])
            continue

        rcode = r.rcode
        ips = r.ips

        if rcode == 3:  # NXDOMAIN
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
                blocks[name] = ("IP_DIVERGENTE", list(ip_set))
            elif not ips:
                blocks[name] = ("SEM_RESPOSTA", [])

    return blocks


# ---------------------------------------------------------------------------
# Varredura multi-servidor
# ---------------------------------------------------------------------------

def scan_domain(
    domain: str,
    servers: Optional[dict[str, tuple[str, str]]] = None,
    timeout: float = 3.0,
    max_workers: int = 20,
) -> list[QueryResult]:
    """Consulta o domínio em todos os servidores em paralelo."""
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
# Avaliação de desempenho
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
    """Executa n consultas e calcula estatísticas de desempenho."""
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
    """Executa teste de desempenho em todos os servidores em paralelo."""
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
