"""SA-MP query protocol (UDP). Works without the RCON password; the server needs "query 1" in server.cfg.

Packet: b"SAMP" + IPv4 (4 bytes) + port (uint16 LE) + opcode (+ data).
Opcodes: 'i' server info, 'c' short player list, 'd' detailed player list, 'p' ping.
"""
import asyncio
import socket
import struct
import time
from dataclasses import dataclass, field

ENC = "cp1251"


@dataclass
class ServerInfo:
    password: bool
    players: int
    max_players: int
    hostname: str
    gamemode: str
    language: str
    ping_ms: int = 0
    port: int = 0


@dataclass
class Player:
    pid: int
    name: str
    score: int
    ping: int


class _Proto(asyncio.DatagramProtocol):
    def __init__(self):
        self.fut = asyncio.get_running_loop().create_future()

    def datagram_received(self, data, addr):
        if not self.fut.done():
            self.fut.set_result(data)

    def error_received(self, exc):
        if not self.fut.done():
            self.fut.set_exception(exc)


async def _resolve(host: str, port: int) -> str:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_DGRAM)
    return infos[0][4][0]


async def _request(host: str, port: int, opcode: bytes, extra: bytes = b"", timeout: float = 2.5, tries: int = 2) -> bytes:
    """Returns the payload after the 11-byte header. Raises asyncio.TimeoutError when the server does not answer."""
    ip = await _resolve(host, port)
    packet = b"SAMP" + socket.inet_aton(ip) + struct.pack("<H", port) + opcode + extra
    loop = asyncio.get_running_loop()
    last: Exception = asyncio.TimeoutError()
    for _ in range(tries):
        transport, proto = await loop.create_datagram_endpoint(_Proto, remote_addr=(ip, port))
        try:
            transport.sendto(packet)
            data = await asyncio.wait_for(proto.fut, timeout)
            if len(data) >= 11 and data[:4] == b"SAMP" and data[10:11] == opcode:
                return data[11:]
            last = ValueError("unexpected reply")
        except (asyncio.TimeoutError, OSError) as e:
            last = e
        finally:
            transport.close()
    raise last


def _read_str(buf: bytes, pos: int, size: int = 4):
    n = int.from_bytes(buf[pos:pos + size], "little")
    pos += size
    return buf[pos:pos + n].decode(ENC, errors="replace"), pos + n


async def query_info(host: str, port: int) -> ServerInfo:
    t0 = time.perf_counter()
    d = await _request(host, port, b"i")
    ping = int((time.perf_counter() - t0) * 1000)
    password = bool(d[0])
    players, max_players = struct.unpack_from("<HH", d, 1)
    pos = 5
    hostname, pos = _read_str(d, pos)
    gamemode, pos = _read_str(d, pos)
    language, pos = _read_str(d, pos)
    return ServerInfo(password, players, max_players, hostname, gamemode, language, ping, port)


async def query_players(host: str, port: int) -> list[Player]:
    """Detailed list ('d'). The server answers only while there are <= 100 players."""
    d = await _request(host, port, b"d")
    (count,) = struct.unpack_from("<H", d, 0)
    pos, out = 2, []
    for _ in range(count):
        pid = d[pos]
        n = d[pos + 1]
        name = d[pos + 2:pos + 2 + n].decode(ENC, errors="replace")
        pos += 2 + n
        score, ping = struct.unpack_from("<iI", d, pos)
        pos += 8
        out.append(Player(pid, name, score, ping))
    return out
