"""Clientes DNS: UDP (porta 53) e DNS over TLS/DoT (porta 853, RFC 7858)."""
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from .protocol import build_query, parse_response, DNSResponse, QTYPE_A


@dataclass
class QueryResult:
    server_ip: str
    server_name: str
    filter_type: str
    domain: str
    response: Optional[DNSResponse]
    elapsed_ms: float
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.response is not None

    @property
    def ips(self) -> list[str]:
        return self.response.a_records if self.response else []

    @property
    def rcode(self) -> Optional[int]:
        return self.response.rcode if self.response else None

    @property
    def rcode_name(self) -> str:
        if self.response:
            return self.response.rcode_name
        return self.error or "TIMEOUT"


def query_udp(
    domain: str,
    server_ip: str,
    server_name: str = "",
    filter_type: str = "",
    port: int = 53,
    timeout: float = 3.0,
) -> QueryResult:
    """Consulta DNS via UDP na porta 53."""
    msg = build_query(domain)
    start = time.perf_counter()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(msg, (server_ip, port))
            data, _ = sock.recvfrom(4096)

        elapsed = (time.perf_counter() - start) * 1000
        response = parse_response(data)
        return QueryResult(server_ip, server_name, filter_type, domain, response, elapsed)

    except socket.timeout:
        elapsed = (time.perf_counter() - start) * 1000
        return QueryResult(server_ip, server_name, filter_type, domain, None, elapsed, "TIMEOUT")
    except ConnectionRefusedError:
        elapsed = (time.perf_counter() - start) * 1000
        return QueryResult(server_ip, server_name, filter_type, domain, None, elapsed, "REFUSED")
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return QueryResult(server_ip, server_name, filter_type, domain, None, elapsed, str(e))


def query_dot(
    domain: str,
    server_host: str,
    server_name: str = "",
    filter_type: str = "",
    port: int = 853,
    timeout: float = 10.0,
) -> QueryResult:
    """Consulta DNS over TLS (DoT) na porta 853 conforme RFC 7858.

    A mensagem DNS é prefixada com 2 bytes indicando o tamanho.
    """
    msg = build_query(domain)
    msg_with_len = struct.pack("!H", len(msg)) + msg
    start = time.perf_counter()

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((server_host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=server_host) as tls_sock:
                tls_sock.sendall(msg_with_len)

                # Lê prefixo de 2 bytes com o tamanho da resposta
                length_buf = b""
                while len(length_buf) < 2:
                    chunk = tls_sock.recv(2 - len(length_buf))
                    if not chunk:
                        raise ConnectionError("Conexão encerrada antes do tamanho")
                    length_buf += chunk

                resp_len = struct.unpack("!H", length_buf)[0]

                # Lê a resposta completa
                resp_data = b""
                while len(resp_data) < resp_len:
                    chunk = tls_sock.recv(resp_len - len(resp_data))
                    if not chunk:
                        raise ConnectionError("Conexão encerrada antes da resposta completa")
                    resp_data += chunk

        elapsed = (time.perf_counter() - start) * 1000
        response = parse_response(resp_data)
        return QueryResult(server_host, server_name, filter_type, domain, response, elapsed)

    except socket.timeout:
        elapsed = (time.perf_counter() - start) * 1000
        return QueryResult(server_host, server_name, filter_type, domain, None, elapsed, "TIMEOUT")
    except ssl.SSLError as e:
        elapsed = (time.perf_counter() - start) * 1000
        return QueryResult(server_host, server_name, filter_type, domain, None, elapsed, f"SSL_ERROR: {e}")
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return QueryResult(server_host, server_name, filter_type, domain, None, elapsed, str(e))
