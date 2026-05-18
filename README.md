# dns-scanner

Ferramenta para análise de resolução DNS em múltiplos servidores simultaneamente.  
Implementa o protocolo DNS do zero (RFC 1035) sem uso de bibliotecas de abstração.  
Suporta DNS/UDP (porta 53) e DNS over TLS/DoT (porta 853, RFC 7858).

## Requisitos

- Python 3.11+

## Instalação

**Com uv (recomendado):**

```bash
uv sync
```

**Sem uv (pip padrão):**

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

> Com pip, substitua `uv run dns-scanner` por apenas `dns-scanner` nos comandos abaixo.

## Comandos

### Varredura multi-servidor

Consulta um domínio em todos os 20 servidores configurados:

```bash
uv run dns-scanner scan <domínio>
uv run dns-scanner scan <domínio> --csv resultados.csv
```

### Varredura completa

Consulta todos os domínios de teste em todos os servidores:

```bash
uv run dns-scanner full
uv run dns-scanner full --csv dados_bloqueio.csv
```

### Ranking de desempenho (UDP)

Executa N consultas por servidor e gera ranking por latência:

```bash
uv run dns-scanner perf <domínio> -n 10
uv run dns-scanner perf <domínio> -n 10 --csv ranking.csv
```

### Comparação UDP vs DNS over TLS

```bash
uv run dns-scanner dot-perf <domínio> -n 10
uv run dns-scanner dot-perf <domínio> -n 10 --csv dot.csv
```

## Servidores configurados (20)

**Sem filtragem:** Google, Google (sec.), Cloudflare, Cloudflare (sec.), Quad9 (no filter), Verisign, Control D, DNS.Watch, Yandex DNS, Level3

**Segurança (malware/phishing):** Quad9, OpenDNS, CleanBrowsing Security, AdGuard DNS, Comodo Secure, Norton ConnectSafe

**Familiar (adulto + segurança):** Cloudflare Family, OpenDNS FamilyShield, CleanBrowsing Family, AdGuard Family

## Domínios de teste (9)

`www.example.com`, `www.pucrs.br`, `www.google.com`, `internetbadguys.com`, `reddit.com`, `tinder.com`, `polymarket.com`, `thepiratebay.org`, `bet365.com`

## Detecção de bloqueio

A ferramenta detecta automaticamente:

- **NXDOMAIN** — quando a maioria dos servidores resolve normalmente
- **REFUSED** — servidor recusa a consulta
- **IP divergente** — IP diferente do consenso (possível redirecionamento)
- **Endereço nulo** — resposta com `0.0.0.0` ou `127.0.0.1`
- **TIMEOUT** — sem resposta dentro do prazo

## Arquivos de dados

| Arquivo | Conteúdo |
|---------|----------|
| `dados_bloqueio.csv` | Varredura completa — todos os domínios × todos os servidores |
| `dados_perf.csv` | Ranking de desempenho UDP (10 consultas/servidor) |
| `dados_dot_perf.csv` | Comparação UDP vs DoT (10 consultas/servidor) |
