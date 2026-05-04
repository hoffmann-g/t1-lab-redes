"""DNS message encoding/decoding per RFC 1035 — sem uso de bibliotecas DNS."""
import random
import struct
from dataclasses import dataclass, field
from typing import Optional

RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_CNAME = 5
QTYPE_NS = 2
QTYPE_MX = 15
QTYPE_PTR = 12
QCLASS_IN = 1


def encode_name(domain: str) -> bytes:
    """Codifica nome de domínio em labels DNS (RFC 1035 §3.1)."""
    result = b""
    for label in domain.rstrip(".").split("."):
        encoded = label.encode("ascii")
        result += bytes([len(encoded)]) + encoded
    return result + b"\x00"


def build_query(domain: str, qtype: int = QTYPE_A, qid: Optional[int] = None) -> bytes:
    """Constrói mensagem de consulta DNS binária (RFC 1035 §4)."""
    if qid is None:
        qid = random.randint(0, 65535)
    # Flags: QR=0 (query), OPCODE=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
    flags = 0x0100
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    question = encode_name(domain) + struct.pack("!HH", qtype, QCLASS_IN)
    return header + question


@dataclass
class DNSRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes
    rdata_decoded: str = ""

    @property
    def type_name(self) -> str:
        return {
            1: "A", 28: "AAAA", 5: "CNAME", 2: "NS", 15: "MX", 12: "PTR",
        }.get(self.rtype, str(self.rtype))


@dataclass
class DNSResponse:
    qid: int
    flags: int
    questions: list
    answers: list
    authority: list
    additional: list

    @property
    def rcode(self) -> int:
        return self.flags & 0xF

    @property
    def rcode_name(self) -> str:
        return RCODE_NAMES.get(self.rcode, f"UNKNOWN({self.rcode})")

    @property
    def a_records(self) -> list[str]:
        return [r.rdata_decoded for r in self.answers if r.rtype == QTYPE_A and r.rdata_decoded]

    @property
    def cname_records(self) -> list[str]:
        return [r.rdata_decoded for r in self.answers if r.rtype == QTYPE_CNAME and r.rdata_decoded]


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decodifica nome DNS com suporte a compressão de ponteiros (RFC 1035 §4.1.4)."""
    labels: list[str] = []
    next_offset: int = -1
    visited: set[int] = set()

    while True:
        if offset >= len(data):
            break

        if offset in visited:
            raise ValueError("Loop de ponteiro detectado")
        visited.add(offset)

        length = data[offset]

        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            # Ponteiro de compressão: 2 bytes com os 14 bits inferiores = offset
            if offset + 1 >= len(data):
                raise ValueError("Ponteiro truncado")
            if next_offset == -1:
                next_offset = offset + 2
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset = pointer
        else:
            offset += 1
            if offset + length > len(data):
                raise ValueError("Label excede tamanho da mensagem")
            labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
            offset += length

    return ".".join(labels), (next_offset if next_offset != -1 else offset)


def _decode_rdata(rtype: int, rdata: bytes, full_msg: bytes, rdata_start: int) -> str:
    if rtype == QTYPE_A and len(rdata) == 4:
        return ".".join(str(b) for b in rdata)
    elif rtype == QTYPE_AAAA and len(rdata) == 16:
        parts = [f"{rdata[i]:02x}{rdata[i + 1]:02x}" for i in range(0, 16, 2)]
        return ":".join(parts)
    elif rtype in (QTYPE_CNAME, QTYPE_NS, QTYPE_PTR):
        try:
            name, _ = decode_name(full_msg, rdata_start)
            return name
        except Exception:
            return rdata.hex()
    elif rtype == QTYPE_MX and len(rdata) >= 2:
        pref = struct.unpack("!H", rdata[:2])[0]
        try:
            name, _ = decode_name(full_msg, rdata_start + 2)
            return f"{pref} {name}"
        except Exception:
            return rdata.hex()
    return rdata.hex()


def parse_response(data: bytes) -> DNSResponse:
    """Faz o parsing da resposta DNS binária (RFC 1035 §4)."""
    if len(data) < 12:
        raise ValueError(f"Resposta muito curta: {len(data)} bytes")

    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    offset = 12

    questions = []
    for _ in range(qdcount):
        name, offset = decode_name(data, offset)
        if offset + 4 > len(data):
            raise ValueError("Seção de questão truncada")
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        questions.append((name, qtype, qclass))

    def parse_records(count: int) -> list[DNSRecord]:
        nonlocal offset
        records = []
        for _ in range(count):
            name, offset = decode_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            rdata_start = offset
            rdata = data[offset : offset + rdlength]
            offset += rdlength
            decoded = _decode_rdata(rtype, rdata, data, rdata_start)
            records.append(DNSRecord(name, rtype, rclass, ttl, rdata, decoded))
        return records

    answers = parse_records(ancount)
    authority = parse_records(nscount)
    additional = parse_records(arcount)

    return DNSResponse(qid, flags, questions, answers, authority, additional)
