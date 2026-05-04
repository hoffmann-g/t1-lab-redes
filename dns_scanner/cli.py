"""Command-line interface for the DNS Scanner."""
import argparse
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from .client import QueryResult, query_dot, query_udp
from .scanner import (
    DNS_SERVERS,
    DOT_SERVERS,
    TEST_DOMAINS,
    PerfStats,
    BLOCK_REASONS,
    detect_blocks,
    perf_test,
    perf_test_all,
    scan_domain,
)

console = Console()

# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

RCODE_STYLES = {
    "NOERROR":  "green",
    "NXDOMAIN": "bold red",
    "REFUSED":  "yellow",
    "SERVFAIL": "dark_orange",
    "TIMEOUT":  "dim",
    "FORMERR":  "red",
}

FILTER_LABELS = {
    "none":     "[dim]none[/dim]",
    "security": "[cyan]security[/cyan]",
    "family":   "[magenta]family[/magenta]",
}

BLOCK_STYLES = {
    "NXDOMAIN":     "bold red",
    "REFUSED":      "yellow",
    "SERVFAIL":     "dark_orange",
    "TIMEOUT":      "dim",
    "NULL_IP":      "red",
    "DIVERGENT_IP": "yellow",
    "NO_RECORDS":   "dim",
}


def _rcode_text(rcode_name: str) -> Text:
    return Text(rcode_name, style=RCODE_STYLES.get(rcode_name, "white"))


def _fmt_ips(ips: list[str]) -> str:
    return ", ".join(ips) if ips else "—"


def _fmt_ms(value: float, valid: bool = True) -> str:
    return f"{value:.1f}" if valid else "—"


# ---------------------------------------------------------------------------
# CSV export helpers
# ---------------------------------------------------------------------------

def _export_scan_csv(results: list[QueryResult], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["server_name", "server_ip", "filter", "domain",
                    "rcode", "rcode_name", "ips", "time_ms", "error"])
        for r in results:
            w.writerow([
                r.server_name, r.server_ip, r.filter_type, r.domain,
                r.rcode, r.rcode_name, ";".join(r.ips),
                f"{r.elapsed_ms:.2f}", r.error or "",
            ])


def _export_perf_csv(stats_list: list[PerfStats], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["server_name", "server_ip", "filter", "domain", "protocol",
                    "n_queries", "n_success", "avg_ms", "min_ms", "max_ms", "loss_rate"])
        for s in stats_list:
            w.writerow([
                s.server_name, s.server_ip, s.filter_type, s.domain, s.protocol,
                s.n_queries, s.n_success,
                f"{s.avg_ms:.2f}", f"{s.min_ms:.2f}", f"{s.max_ms:.2f}",
                f"{s.loss_rate:.3f}",
            ])


def _export_full_csv(all_results: dict[str, list[QueryResult]], path: str) -> None:
    rows = []
    for domain, results in all_results.items():
        for r in results:
            rows.append({
                "domain": domain,
                "server_name": r.server_name,
                "server_ip": r.server_ip,
                "filter": r.filter_type,
                "rcode": r.rcode,
                "rcode_name": r.rcode_name,
                "ips": ";".join(r.ips),
                "time_ms": f"{r.elapsed_ms:.2f}",
                "error": r.error or "",
            })
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


# ---------------------------------------------------------------------------
# Command: scan
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> None:
    """Query a single domain across all configured DNS servers."""
    domain = args.domain
    console.rule(f"[bold]DNS Query: [cyan]{domain}[/cyan]")

    results = scan_domain(domain, timeout=args.timeout)

    table = Table(box=box.ROUNDED, title=f"Results — {domain}")
    table.add_column("Server",       style="cyan",  min_width=24)
    table.add_column("Server IP",    style="dim",   min_width=14)
    table.add_column("Filter",       min_width=10)
    table.add_column("RCODE",        min_width=10)
    table.add_column("Returned IPs")
    table.add_column("ms", justify="right", min_width=7)

    for r in results:
        table.add_row(
            r.server_name,
            r.server_ip,
            FILTER_LABELS.get(r.filter_type, r.filter_type),
            _rcode_text(r.rcode_name),
            _fmt_ips(r.ips),
            _fmt_ms(r.elapsed_ms),
        )

    console.print(table)

    blocks = detect_blocks(results)
    if blocks:
        console.print("\n[bold yellow]Block Detection:[/bold yellow]")
        bt = Table(box=box.SIMPLE, show_header=False)
        bt.add_column("Server",      style="cyan")
        bt.add_column("Type")
        bt.add_column("IPs",         style="dim")
        bt.add_column("Description", style="dim")
        for srv, (btype, bips) in sorted(blocks.items()):
            bt.add_row(
                srv,
                Text(btype, style=BLOCK_STYLES.get(btype, "white")),
                _fmt_ips(bips),
                BLOCK_REASONS.get(btype, ""),
            )
        console.print(bt)
    else:
        console.print("\n[green]No blocking detected.[/green]")

    if args.csv:
        _export_scan_csv(results, args.csv)
        console.print(f"\n[green]Exported:[/green] {args.csv}")


# ---------------------------------------------------------------------------
# Command: perf
# ---------------------------------------------------------------------------

def cmd_perf(args: argparse.Namespace) -> None:
    """Run a latency benchmark across all servers and display a ranking."""
    domain = args.domain
    n = args.n
    console.rule(f"[bold]Performance (UDP) — [cyan]{domain}[/cyan] ({n} queries/server)")

    with console.status("[bold]Running performance tests..."):
        stats_list = perf_test_all(domain, n=n)

    table = Table(box=box.ROUNDED, title=f"Performance Ranking — {domain}")
    table.add_column("#",        justify="right", style="dim")
    table.add_column("Server",   style="cyan", min_width=24)
    table.add_column("Filter",   min_width=10)
    table.add_column("Avg (ms)", justify="right")
    table.add_column("Min (ms)", justify="right")
    table.add_column("Max (ms)", justify="right")
    table.add_column("Loss",     justify="right")

    for i, s in enumerate(stats_list, 1):
        ok = s.n_success > 0
        loss_style = "red" if s.loss_rate > 0.2 else ("yellow" if s.loss_rate > 0 else "green")
        table.add_row(
            str(i),
            s.server_name,
            FILTER_LABELS.get(s.filter_type, s.filter_type),
            _fmt_ms(s.avg_ms, ok),
            _fmt_ms(s.min_ms, ok),
            _fmt_ms(s.max_ms, ok),
            Text(s.loss_pct, style=loss_style),
        )

    console.print(table)

    if args.csv:
        _export_perf_csv(stats_list, args.csv)
        console.print(f"\n[green]Exported:[/green] {args.csv}")


# ---------------------------------------------------------------------------
# Command: dot-perf
# ---------------------------------------------------------------------------

def cmd_dot_perf(args: argparse.Namespace) -> None:
    """Compare latency between plain UDP and DNS over TLS for the same providers."""
    domain = args.domain
    n = args.n
    console.rule(f"[bold]UDP vs DoT — [cyan]{domain}[/cyan] ({n} queries)")

    # Side-by-side pairs: (display_name, udp_ip, dot_hostname, filter_type)
    pairs = [
        ("Google",    "8.8.8.8",   "dns.google",      "none"),
        ("Cloudflare","1.1.1.1",   "one.one.one.one",  "none"),
        ("Quad9",     "9.9.9.9",   "dns.quad9.net",    "security"),
    ]

    all_stats: list[PerfStats] = []
    with console.status("[bold]Running UDP and DoT queries..."):
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = []
            for name, udp_ip, dot_host, ft in pairs:
                futures.append(executor.submit(perf_test, domain, name,          udp_ip,   ft, n, "udp"))
                futures.append(executor.submit(perf_test, domain, f"{name} DoT", dot_host, ft, n, "dot"))
            for future in as_completed(futures):
                all_stats.append(future.result())

    table = Table(box=box.ROUNDED, title=f"UDP vs DoT — {domain}")
    table.add_column("Server",   style="cyan", min_width=20)
    table.add_column("Protocol", min_width=8)
    table.add_column("Filter",   min_width=10)
    table.add_column("Avg (ms)", justify="right")
    table.add_column("Min (ms)", justify="right")
    table.add_column("Max (ms)", justify="right")
    table.add_column("Loss",     justify="right")

    for name, _, _, _ in pairs:
        udp = next((s for s in all_stats if s.server_name == name          and s.protocol == "udp"), None)
        dot = next((s for s in all_stats if s.server_name == f"{name} DoT" and s.protocol == "dot"), None)
        for s in [udp, dot]:
            if s is None:
                continue
            ok = s.n_success > 0
            proto_style = "blue" if s.protocol == "dot" else "green"
            loss_style  = "red" if s.loss_rate > 0.2 else ("yellow" if s.loss_rate > 0 else "green")
            table.add_row(
                s.server_name,
                Text(s.protocol.upper(), style=proto_style),
                FILTER_LABELS.get(s.filter_type, s.filter_type),
                _fmt_ms(s.avg_ms, ok),
                _fmt_ms(s.min_ms, ok),
                _fmt_ms(s.max_ms, ok),
                Text(s.loss_pct, style=loss_style),
            )
        table.add_section()

    console.print(table)

    if args.csv:
        _export_perf_csv(all_stats, args.csv)
        console.print(f"\n[green]Exported:[/green] {args.csv}")


# ---------------------------------------------------------------------------
# Command: full
# ---------------------------------------------------------------------------

def cmd_full(args: argparse.Namespace) -> None:
    """Full scan: query every test domain against every configured server."""
    all_results: dict[str, list[QueryResult]] = {}

    for domain, purpose in TEST_DOMAINS:
        console.rule(f"[bold]{domain}[/bold]  [dim]{purpose}[/dim]")

        results = scan_domain(domain, timeout=args.timeout)
        all_results[domain] = results
        blocks = detect_blocks(results)

        table = Table(box=box.SIMPLE)
        table.add_column("Server",    style="cyan", min_width=24)
        table.add_column("Filter",    min_width=10)
        table.add_column("RCODE",     min_width=10)
        table.add_column("IPs")
        table.add_column("ms", justify="right", min_width=7)
        table.add_column("Block",     min_width=14)

        for r in results:
            block_info = blocks.get(r.server_name)
            if block_info:
                btype, _ = block_info
                block_cell = Text(btype, style=BLOCK_STYLES.get(btype, "white"))
            else:
                block_cell = Text("")
            table.add_row(
                r.server_name,
                FILTER_LABELS.get(r.filter_type, r.filter_type),
                _rcode_text(r.rcode_name),
                _fmt_ips(r.ips),
                _fmt_ms(r.elapsed_ms),
                block_cell,
            )

        console.print(table)
        console.print()

    if args.csv:
        _export_full_csv(all_results, args.csv)
        console.print(f"\n[green]Exported:[/green] {args.csv}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dns-scanner",
        description="DNS analysis tool: censorship, performance and privacy (RFC 1035 / RFC 7858)",
    )
    parser.add_argument(
        "--timeout", type=float, default=3.0,
        help="Per-query timeout in seconds (default: 3.0)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Query a domain across all configured servers")
    p_scan.add_argument("domain", help="Domain name to query (e.g. www.example.com)")
    p_scan.add_argument("--csv", metavar="FILE", help="Export results to CSV")
    p_scan.set_defaults(func=cmd_scan)

    # perf
    p_perf = sub.add_parser("perf", help="Latency benchmark with server ranking")
    p_perf.add_argument("domain", help="Control domain (e.g. www.example.com)")
    p_perf.add_argument("-n", type=int, default=10, metavar="N",
                        help="Queries per server (default: 10)")
    p_perf.add_argument("--csv", metavar="FILE", help="Export ranking to CSV")
    p_perf.set_defaults(func=cmd_perf)

    # dot-perf
    p_dot = sub.add_parser("dot-perf", help="Compare UDP vs DNS over TLS latency")
    p_dot.add_argument("domain", help="Domain to test")
    p_dot.add_argument("-n", type=int, default=10, metavar="N",
                       help="Queries per protocol (default: 10)")
    p_dot.add_argument("--csv", metavar="FILE", help="Export comparison to CSV")
    p_dot.set_defaults(func=cmd_dot_perf)

    # full
    p_full = sub.add_parser("full", help="Full scan of all test domains")
    p_full.add_argument("--csv", metavar="FILE", default="results.csv",
                        help="Output CSV file (default: results.csv)")
    p_full.add_argument("--timeout", type=float, default=3.0,
                        help="Per-query timeout in seconds (default: 3.0)")
    p_full.set_defaults(func=cmd_full)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
