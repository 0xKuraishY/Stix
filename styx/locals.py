"""Local proxy spirits — test servers so `styx demo` needs no proxy list.

Raises a SOCKS5 gateway (optional username/password auth) and three HTTP
forward proxies with different header personalities (elite / anonymous /
transparent) on 127.0.0.1, on ephemeral ports.
"""

from __future__ import annotations

import asyncio
import base64
import socket
from typing import Optional

DEMO_USER = "charon"
DEMO_PASS = "obol"


async def _pipe(reader_a: asyncio.StreamReader, writer_a: asyncio.StreamWriter,
                reader_b: asyncio.StreamReader, writer_b: asyncio.StreamWriter) -> None:
    async def copy(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while chunk := await src.read(65536):
                dst.write(chunk)
                await dst.drain()
        except Exception:
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass

    tasks = [asyncio.create_task(copy(reader_a, writer_b)),
             asyncio.create_task(copy(reader_b, writer_a))]
    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in tasks:
        t.cancel()


# ---------------------------------------------------------------------------
# SOCKS5

async def _socks5_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                       require_auth: bool) -> None:
    try:
        head = await reader.readexactly(2)
        if head[0] != 0x05:
            return
        methods = await reader.readexactly(head[1])
        if require_auth and 0x02 in methods:
            writer.write(b"\x05\x02")
            await writer.drain()
            ver = (await reader.readexactly(1))[0]  # auth subnegotiation VER = 0x01
            ulen = (await reader.readexactly(1))[0]
            user = (await reader.readexactly(ulen)).decode(errors="replace")
            plen = (await reader.readexactly(1))[0]
            pwd = (await reader.readexactly(plen)).decode(errors="replace")
            if ver != 0x01 or (user, pwd) != (DEMO_USER, DEMO_PASS):
                writer.write(b"\x01\x01")
                await writer.drain()
                return
            writer.write(b"\x01\x00")
        elif 0x00 in methods:
            writer.write(b"\x05\x00")
        else:
            writer.write(b"\x05\xFF")
            await writer.drain()
            return
        await writer.drain()

        hdr = await reader.readexactly(4)
        if hdr[0] != 0x05 or hdr[1] != 0x01:  # only CONNECT
            writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
            await writer.drain()
            return
        atyp = hdr[3]
        if atyp == 0x01:
            addr = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 0x03:
            ln = (await reader.readexactly(1))[0]
            addr = (await reader.readexactly(ln)).decode(errors="replace")
        elif atyp == 0x04:
            addr = str(socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16)))
        else:
            return
        port = int.from_bytes(await reader.readexactly(2), "big")

        try:
            remote_r, remote_w = await asyncio.open_connection(addr, port)
        except OSError:
            writer.write(b"\x05\x05\x00\x01" + b"\x00" * 6)
            await writer.drain()
            return
        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        await _pipe(reader, writer, remote_r, remote_w)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# HTTP forward proxy

async def _http_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                     flavor: str) -> None:
    try:
        request_line = (await reader.readline()).decode(errors="replace").strip()
        if not request_line:
            return
        method, target, _version = request_line.split(" ", 2)
        headers: dict[str, str] = {}
        while True:
            line = (await reader.readline()).decode(errors="replace")
            if line in ("\r\n", "\n", ""):
                break
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()

        auth = headers.get("proxy-authorization", "")
        accepted = False
        if auth.lower().startswith("basic "):
            try:
                user, pwd = base64.b64decode(auth[6:]).decode().split(":", 1)
                accepted = (user, pwd) == (DEMO_USER, DEMO_PASS)
            except Exception:
                pass
        if not accepted:
            writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                         b"Proxy-Authenticate: Basic realm=\"styx\"\r\n"
                         b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return

        if method.upper() == "CONNECT":
            host, _, port_s = target.partition(":")
            try:
                remote_r, remote_w = await asyncio.open_connection(host, int(port_s or 443))
            except OSError:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
            await _pipe(reader, writer, remote_r, remote_w)
            return

        from urllib.parse import urlsplit

        url = urlsplit(target)
        host = url.hostname or ""
        port = url.port or 80
        path = url.path or "/"
        if url.query:
            path += "?" + url.query
        remote_r, remote_w = await asyncio.open_connection(host, port)
        # personality headers must be added to the OUTGOING request —
        # that is what the judge echoes back in its /headers report
        personality = b""
        if flavor == "anonymous":
            personality = b"Via: 1.1 styx-spirit (demo)\r\n"
        elif flavor == "transparent":
            peer_ip = writer.get_extra_info("peername")[0]
            personality = f"X-Forwarded-For: {peer_ip}\r\nVia: 1.1 styx-spirit (demo)\r\n".encode()
        upstream = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: styx-spirit\r\n"
                    f"Accept: */*\r\nConnection: close\r\n").encode() + personality + b"\r\n"
        remote_w.write(upstream)
        await remote_w.drain()
        raw = await remote_r.read()

        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        status = lines[0]
        fwd = [ln for ln in lines[1:] if not ln.lower().startswith(
            (b"connection:", b"keep-alive:", b"proxy-authenticate:"))]
        response = (status + b"\r\n" + b"\r\n".join(fwd) + b"\r\nConnection: close\r\n\r\n" + body)
        writer.write(response)
        await writer.drain()
    except (ConnectionResetError, asyncio.IncompleteReadError, ValueError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# public API

class LocalSpirits:
    """Running demo proxies. Use as an async context manager."""

    def __init__(self) -> None:
        self.servers: list[asyncio.base_events.Server] = []
        self.entries: list[str] = []

    async def __aenter__(self) -> "LocalSpirits":
        specs = [
            ("socks5", True),    # authenticated SOCKS5
            ("http", "elite"),
            ("http", "anonymous"),
            ("http", "transparent"),
        ]
        for kind, param in specs:
            if kind == "socks5":
                server = await asyncio.start_server(
                    lambda r, w: _socks5_conn(r, w, bool(param)), "127.0.0.1", 0)
                port = server.sockets[0].getsockname()[1]
                self.entries.append(f"{DEMO_USER}:{DEMO_PASS}@127.0.0.1:{port}")
            else:
                server = await asyncio.start_server(
                    lambda r, w, f=param: _http_conn(r, w, f), "127.0.0.1", 0)
                port = server.sockets[0].getsockname()[1]
                self.entries.append(f"127.0.0.1:{port}:{DEMO_USER}:{DEMO_PASS}")
            self.servers.append(server)
        return self

    async def __aexit__(self, *exc) -> None:
        for server in self.servers:
            server.close()
            await server.wait_closed()
