# dns-scanner

Command-line tool that sends the same DNS query to 20 public resolvers in parallel, compares the answers to detect blocking or redirection, and measures resolver latency over UDP and DNS over TLS.

DNS messages are built and parsed by the project's own code (`struct.pack`/`unpack`), without a DNS library. The only runtime dependency is `rich`, used for terminal tables.

## Protocols

- **DNS over UDP, port 53 (RFC 1035).** Queries are type A, class IN, with a random transaction ID and the RD flag set. The parser reads the header, question, answer, authority and additional sections, follows name compression pointers (with loop detection), and decodes A, AAAA, CNAME, NS, PTR and MX records.
- **DNS over TLS, port 853 (RFC 7858).** A TCP connection is opened, TLS is negotiated with Python's `ssl` default context (certificate and hostname verified), and each message is sent and read with a 2-byte big-endian length prefix. One connection is opened per query.

## Requirements

- Python 3.11 or later
- [uv](https://docs.astral.sh/uv/)

## Install and run

```bash
uv sync
uv run dns-scanner --help
```

Without uv:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
dns-scanner --help
```

## Commands

```
dns-scanner [--timeout SECONDS] {scan,perf,dot-perf,full} ...
```

`--timeout` is a global option placed before the subcommand. It sets the per-query UDP timeout (default 3.0 s) for `scan`. `full` has its own `--timeout` option placed after the subcommand, and its default overrides the global value.

| Command | Arguments | Description |
|---------|-----------|-------------|
| `scan DOMAIN` | `--csv FILE` | Queries `DOMAIN` on all 20 resolvers and prints the results and any detected blocks. |
| `full` | `--csv FILE` (default `results.csv`), `--timeout SECONDS` | Runs `scan` for each of the 9 built-in test domains. A CSV file is always written. |
| `perf DOMAIN` | `-n N` (default 10), `--csv FILE` | Sends `N` UDP queries to each resolver and ranks them by average latency. |
| `dot-perf DOMAIN` | `-n N` (default 10), `--csv FILE` | Sends `N` queries over UDP and `N` over DoT to Google, Cloudflare and Quad9 and compares latency. |

`perf` and `dot-perf` use fixed timeouts: 3 s per UDP query and 10 s per DoT query.

Examples:

```bash
uv run dns-scanner scan www.example.com
uv run dns-scanner --timeout 5 scan reddit.com --csv reddit.csv
uv run dns-scanner full --csv dados_bloqueio.csv
uv run dns-scanner perf www.example.com -n 10 --csv dados_perf.csv
uv run dns-scanner dot-perf www.example.com -n 10 --csv dados_dot_perf.csv
```

## Resolvers and test domains

Resolvers are defined in `dns_scanner/scanner.py` and grouped by filtering policy:

- **none:** Google (8.8.8.8, 8.8.4.4), Cloudflare (1.1.1.1, 1.0.0.1), Quad9 no filter (9.9.9.10), Verisign, Control D, DNS.Watch, Yandex DNS, Level3
- **security:** Quad9 (9.9.9.9), OpenDNS, CleanBrowsing Security, AdGuard DNS, Comodo Secure, Norton ConnectSafe
- **family:** Cloudflare Family, OpenDNS FamilyShield, CleanBrowsing Family, AdGuard Family

DoT endpoints: `dns.google`, `one.one.one.one`, `dns.quad9.net`.

Test domains used by `full`: `www.example.com`, `www.pucrs.br`, `internetbadguys.com`, `reddit.com`, `tinder.com`, `polymarket.com`, `www.google.com`, `thepiratebay.org`, `bet365.com`.

## Block detection

A consensus set of IPs is built from the resolvers in the `none` group that returned NOERROR. Each response is then classified:

| Label | Condition |
|-------|-----------|
| `NXDOMAIN` | RCODE 3 while at least half of the resolvers returned addresses |
| `REFUSED` | RCODE 5 |
| `SERVFAIL` | RCODE 2 |
| `NULL_IP` | Answer contains `0.0.0.0`, `127.0.0.1` or `::` |
| `DIVERGENT_IP` | Answer shares no address with the consensus set |
| `NO_RECORDS` | NOERROR with no A records |
| `TIMEOUT` | No response, while at least half of the resolvers responded |

## Output

Results are printed as tables. With `--csv`, the following columns are written:

- `scan`: `server_name, server_ip, filter, domain, rcode, rcode_name, ips, time_ms, error`
- `full`: `domain, server_name, server_ip, filter, rcode, rcode_name, ips, time_ms, error`
- `perf` and `dot-perf`: `server_name, server_ip, filter, domain, protocol, n_queries, n_success, avg_ms, min_ms, max_ms, loss_rate`

`ips` is a `;`-separated list. Times are in milliseconds. `loss_rate` is a fraction between 0 and 1.

## Repository contents

| Path | Content |
|------|---------|
| `dns_scanner/protocol.py` | DNS message encoding and parsing |
| `dns_scanner/client.py` | UDP and DoT clients |
| `dns_scanner/scanner.py` | Resolver and domain lists, parallel scan, block detection, latency tests |
| `dns_scanner/cli.py` | Command-line interface and CSV export |
| `dados_bloqueio.csv` | Output of `full` (9 domains, 20 resolvers) |
| `dados_perf.csv` | Output of `perf www.example.com -n 10` |
| `dados_dot_perf.csv` | Output of `dot-perf www.example.com -n 10` |
| `relatorio.md` | Report with the analysis of the results (Portuguese) |
| `screenshots/` | Wireshark and browser captures referenced by the report |

There is no test suite.

## Português

Ferramenta de linha de comando que consulta um domínio em 20 servidores DNS públicos, detecta bloqueios comparando as respostas e mede a latência sobre UDP (RFC 1035) e DNS over TLS (RFC 7858). As mensagens DNS são montadas e interpretadas pelo próprio código, sem biblioteca de DNS. Desenvolvida como trabalho da disciplina Laboratório de Redes de Computadores (PUCRS). A análise dos resultados está em `relatorio.md`.

```bash
uv sync
uv run dns-scanner scan www.example.com
```
