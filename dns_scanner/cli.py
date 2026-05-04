"""Interface de linha de comando do DNS Scanner."""
import argparse
import csv
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

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
    detect_blocks,
    perf_test,
    perf_test_all,
    scan_domain,
    BLOCK_REASONS,
)

console = Console()

# ---------------------------------------------------------------------------
# Helpers de formatação
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
    "nenhum":    "[dim]nenhum[/dim]",
    "segurança": "[cyan]segurança[/cyan]",
    "família":   "[magenta]família[/magenta]",
}

BLOCK_STYLES = {
    "NXDOMAIN":      "bold red",
    "REFUSED":       "yellow",
    "SERVFAIL":      "dark_orange",
    "TIMEOUT":       "dim",
    "NULL_IP":       "red",
    "IP_DIVERGENTE": "yellow",
    "SEM_RESPOSTA":  "dim",
}


def _rcode_text(rcode_name: str) -> Text:
    style = RCODE_STYLES.get(rcode_name, "white")
    return Text(rcode_name, style=style)


def _fmt_ips(ips: list[str]) -> str:
    return ", ".join(ips) if ips else "—"


def _fmt_ms(v: float, valid: bool = True) -> str:
    return f"{v:.1f}" if valid else "—"


# ---------------------------------------------------------------------------
# Exportação CSV
# ---------------------------------------------------------------------------

def _export_scan_csv(results: list[QueryResult], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["servidor_nome", "servidor_ip", "filtro", "dominio",
                    "rcode", "rcode_nome", "ips", "tempo_ms", "erro"])
        for r in results:
            w.writerow([
                r.server_name, r.server_ip, r.filter_type, r.domain,
                r.rcode, r.rcode_name, ";".join(r.ips),
                f"{r.elapsed_ms:.2f}", r.error or "",
            ])


def _export_perf_csv(stats_list: list[PerfStats], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["servidor_nome", "servidor_ip", "filtro", "dominio", "protocolo",
                    "n_consultas", "n_sucesso", "media_ms", "min_ms", "max_ms", "perda"])
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
                "dominio": domain,
                "servidor_nome": r.server_name,
                "servidor_ip": r.server_ip,
                "filtro": r.filter_type,
                "rcode": r.rcode,
                "rcode_nome": r.rcode_name,
                "ips": ";".join(r.ips),
                "tempo_ms": f"{r.elapsed_ms:.2f}",
                "erro": r.error or "",
            })
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


# ---------------------------------------------------------------------------
# Comando: scan
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> None:
    """Consulta um domínio em todos os servidores DNS configurados."""
    domain = args.domain
    console.rule(f"[bold]Consulta DNS: [cyan]{domain}[/cyan]")

    results = scan_domain(domain, timeout=args.timeout)

    table = Table(box=box.ROUNDED, title=f"Resultados — {domain}")
    table.add_column("Servidor",    style="cyan",  min_width=24)
    table.add_column("IP Servidor", style="dim",   min_width=14)
    table.add_column("Filtro",      min_width=10)
    table.add_column("RCODE",       min_width=10)
    table.add_column("Endereços IP retornados")
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

    # Detecção de bloqueio
    blocks = detect_blocks(results)
    if blocks:
        console.print("\n[bold yellow]Detecção de Bloqueio:[/bold yellow]")
        bt = Table(box=box.SIMPLE, show_header=False)
        bt.add_column("Servidor", style="cyan")
        bt.add_column("Tipo")
        bt.add_column("IPs", style="dim")
        bt.add_column("Descrição", style="dim")
        for srv, (btype, bips) in sorted(blocks.items()):
            style = BLOCK_STYLES.get(btype, "white")
            desc = BLOCK_REASONS.get(btype, "")
            bt.add_row(srv, Text(btype, style=style), _fmt_ips(bips), desc)
        console.print(bt)
    else:
        console.print("\n[green]Nenhum bloqueio detectado.[/green]")

    if args.csv:
        _export_scan_csv(results, args.csv)
        console.print(f"\n[green]Exportado:[/green] {args.csv}")


# ---------------------------------------------------------------------------
# Comando: perf
# ---------------------------------------------------------------------------

def cmd_perf(args: argparse.Namespace) -> None:
    """Teste de desempenho: múltiplas consultas por servidor, gera ranking."""
    domain = args.domain
    n = args.n
    console.rule(f"[bold]Desempenho UDP — [cyan]{domain}[/cyan] ({n} consultas/servidor)")

    with console.status("[bold]Executando testes de desempenho..."):
        stats_list = perf_test_all(domain, n=n)

    table = Table(box=box.ROUNDED, title=f"Ranking de Desempenho — {domain}")
    table.add_column("#",           justify="right", style="dim")
    table.add_column("Servidor",    style="cyan", min_width=24)
    table.add_column("Filtro",      min_width=10)
    table.add_column("Média (ms)",  justify="right")
    table.add_column("Mín (ms)",    justify="right")
    table.add_column("Máx (ms)",    justify="right")
    table.add_column("Perda",       justify="right")

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
        console.print(f"\n[green]Exportado:[/green] {args.csv}")


# ---------------------------------------------------------------------------
# Comando: dot-perf
# ---------------------------------------------------------------------------

def cmd_dot_perf(args: argparse.Namespace) -> None:
    """Compara latência UDP vs DNS over TLS para os mesmos provedores."""
    domain = args.domain
    n = args.n
    console.rule(f"[bold]UDP vs DoT — [cyan]{domain}[/cyan] ({n} consultas)")

    # Pares para comparação direta
    pairs = [
        ("Google",          "8.8.8.8",          "dns.google",      "nenhum"),
        ("Cloudflare",      "1.1.1.1",           "one.one.one.one", "nenhum"),
        ("Quad9 segurança", "9.9.9.9",           "dns.quad9.net",   "segurança"),
    ]

    all_stats: list[PerfStats] = []
    with console.status("[bold]Executando consultas UDP e DoT..."):
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = []
            for name, udp_ip, dot_host, ft in pairs:
                futures.append(executor.submit(perf_test, domain, name, udp_ip, ft, n, "udp"))
                futures.append(executor.submit(perf_test, domain, f"{name} DoT", dot_host, ft, n, "dot"))
            for future in as_completed(futures):
                all_stats.append(future.result())

    table = Table(box=box.ROUNDED, title=f"UDP vs DoT — {domain}")
    table.add_column("Servidor",   style="cyan", min_width=20)
    table.add_column("Protocolo",  min_width=8)
    table.add_column("Filtro",     min_width=10)
    table.add_column("Média (ms)", justify="right")
    table.add_column("Mín (ms)",   justify="right")
    table.add_column("Máx (ms)",   justify="right")
    table.add_column("Perda",      justify="right")

    for name, _, _, _ in pairs:
        udp = next((s for s in all_stats if s.server_name == name and s.protocol == "udp"), None)
        dot = next((s for s in all_stats if s.server_name == f"{name} DoT" and s.protocol == "dot"), None)
        for s in [udp, dot]:
            if s is None:
                continue
            ok = s.n_success > 0
            proto_style = "blue" if s.protocol == "dot" else "green"
            loss_style = "red" if s.loss_rate > 0.2 else ("yellow" if s.loss_rate > 0 else "green")
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
        console.print(f"\n[green]Exportado:[/green] {args.csv}")


# ---------------------------------------------------------------------------
# Comando: full
# ---------------------------------------------------------------------------

def cmd_full(args: argparse.Namespace) -> None:
    """Varredura completa: todos os domínios de teste em todos os servidores."""
    all_results: dict[str, list[QueryResult]] = {}

    for domain, purpose in TEST_DOMAINS:
        console.rule(f"[bold]{domain}[/bold]  [dim]{purpose}[/dim]")

        results = scan_domain(domain, timeout=args.timeout)
        all_results[domain] = results

        blocks = detect_blocks(results)

        table = Table(box=box.SIMPLE, show_header=True)
        table.add_column("Servidor",   style="cyan", min_width=24)
        table.add_column("Filtro",     min_width=10)
        table.add_column("RCODE",      min_width=10)
        table.add_column("IPs")
        table.add_column("ms", justify="right", min_width=7)
        table.add_column("Bloqueio", min_width=14)

        for r in results:
            block_info = blocks.get(r.server_name, None)
            if block_info:
                btype, bips = block_info
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
        console.print(f"\n[green]Dados exportados:[/green] {args.csv}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dns-scanner",
        description="Análise de DNS: censura, desempenho e privacidade (RFC 1035 / RFC 7858)",
    )
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="Timeout por consulta em segundos (padrão: 3.0)")
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Consultar um domínio em todos os servidores")
    p_scan.add_argument("domain", help="Nome de domínio a consultar (ex: www.example.com)")
    p_scan.add_argument("--csv", metavar="ARQUIVO", help="Exportar resultados para CSV")
    p_scan.set_defaults(func=cmd_scan)

    # perf
    p_perf = sub.add_parser("perf", help="Teste de desempenho com ranking")
    p_perf.add_argument("domain", help="Domínio de controle (ex: www.example.com)")
    p_perf.add_argument("-n", type=int, default=10, metavar="N",
                        help="Número de consultas por servidor (padrão: 10)")
    p_perf.add_argument("--csv", metavar="ARQUIVO", help="Exportar ranking para CSV")
    p_perf.set_defaults(func=cmd_perf)

    # dot-perf
    p_dot = sub.add_parser("dot-perf", help="Comparar latência UDP vs DNS over TLS")
    p_dot.add_argument("domain", help="Domínio a testar")
    p_dot.add_argument("-n", type=int, default=10, metavar="N",
                       help="Número de consultas (padrão: 10)")
    p_dot.add_argument("--csv", metavar="ARQUIVO", help="Exportar comparação para CSV")
    p_dot.set_defaults(func=cmd_dot_perf)

    # full
    p_full = sub.add_parser("full", help="Varredura completa de todos os domínios de teste")
    p_full.add_argument("--csv", metavar="ARQUIVO", default="resultados.csv",
                        help="Arquivo CSV de saída (padrão: resultados.csv)")
    p_full.add_argument("--timeout", type=float, default=3.0,
                        help="Timeout por consulta em segundos (padrão: 3.0)")
    p_full.set_defaults(func=cmd_full)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
