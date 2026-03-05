"""
mutant-dns-web: real-time visual interface for mutant-dns tunnel traffic.

Runs a mutant-dns-server on a local port and provides a web UI that shows
real DNS tunnel packets flowing with their mutations visualized.
"""

import asyncio
import sys
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import dnslib

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from ..server import DNSTunnelServer
from ..client import TunnelClient
from ..protocol import parse_packet, build_packet, qname_to_encoded
from ..mutations import ENCODING_STRATEGIES, CHUNKING_STRATEGIES, TIMING_STRATEGIES

# ── Globals ──────────────────────────────────────────────────────────────────

DOMAIN = "tunnel.mutant.local"
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5353
WEB_PORT = 9090

ws_clients: list = []
ws_lock = threading.Lock()
server_instance = None
server_thread = None

_event_queue: Optional[asyncio.Queue] = None


# ── Devnull output ───────────────────────────────────────────────────────────

class _DevNull:
    """Write-only sink that discards all data."""
    def write(self, data):
        return len(data)
    def flush(self):
        pass


# ── Broadcast to all WebSocket clients ───────────────────────────────────────

async def _broadcast_worker():
    """Drain the event queue and fan-out to all WebSocket clients."""
    while True:
        event = await _event_queue.get()
        with ws_lock:
            clients = list(ws_clients)
        dead = []
        for ws in clients:
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        if dead:
            with ws_lock:
                for ws in dead:
                    try:
                        ws_clients.remove(ws)
                    except ValueError:
                        pass


def enqueue_event(event: dict):
    """Thread-safe: put an event on the async queue."""
    if _event_queue is not None:
        _event_queue.put_nowait(event)


# ── Instrumented server that reports packets ─────────────────────────────────

class InstrumentedServer(DNSTunnelServer):
    """DNSTunnelServer subclass that broadcasts packet events via WebSocket."""

    def _handle(self, data, addr):
        try:
            request = dnslib.DNSRecord.parse(data)
        except Exception:
            return super()._handle(data, addr)

        qname = str(request.q.qname).lower().rstrip('.')
        subdomain = qname_to_encoded(qname, self.domain)

        if subdomain and not subdomain.startswith(('cncheck', 'cnfin', 'cnpoll', 'cndmcheck')):
            result = parse_packet(subdomain)
            if result is not None:
                payload, tunnel_id, seq, codec = result
                enqueue_event({
                    "type": "packet",
                    "tunnel_id": "{:04x}".format(tunnel_id),
                    "seq": seq,
                    "codec": codec,
                    "payload_size": len(payload),
                    "encoded_len": len(subdomain),
                    "qname_len": len(qname),
                    "timestamp": time.time(),
                    "payload_preview": payload[:40].hex(),
                })

        return super()._handle(data, addr)


# ── Server lifecycle ─────────────────────────────────────────────────────────

def start_dns_server():
    global server_instance
    server_instance = InstrumentedServer(
        domain=DOMAIN,
        host=SERVER_HOST,
        port=SERVER_PORT,
        output=_DevNull(),
        verbose=False,
    )
    server_instance.run()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global server_thread, _event_queue
    _event_queue = asyncio.Queue()

    bw = asyncio.create_task(_broadcast_worker())

    server_thread = threading.Thread(target=start_dns_server, daemon=True)
    server_thread.start()
    await asyncio.sleep(0.3)
    print('[mutant-dns-web] DNS server on {}:{}'.format(SERVER_HOST, SERVER_PORT),
          file=sys.stderr, flush=True)
    print('[mutant-dns-web] Open http://localhost:{}'.format(WEB_PORT),
          file=sys.stderr, flush=True)
    yield
    bw.cancel()
    if server_instance and server_instance._sock:
        server_instance._sock.close()


# ── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(title="mutant-dns-web", lifespan=lifespan)

static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
async def index():
    return FileResponse(str(static_dir / "index.html"))


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    with ws_lock:
        ws_clients.append(ws)
    try:
        while True:
            msg = await ws.receive_json()
            await handle_ws_message(msg, ws)
    except WebSocketDisconnect:
        pass
    finally:
        with ws_lock:
            try:
                ws_clients.remove(ws)
            except ValueError:
                pass


async def handle_ws_message(msg: dict, ws: WebSocket):
    action = msg.get("action")

    if action == "send":
        text = msg.get("text", "Hello from mutant-dns!")
        encoding = msg.get("encoding", "weighted")
        chunking = msg.get("chunking", "variable")
        timing = msg.get("timing", "burst")

        def do_send():
            client = TunnelClient(
                domain=DOMAIN,
                server=SERVER_HOST,
                port=SERVER_PORT,
                encoding=encoding,
                chunking=chunking,
                timing=timing,
                retries=2,
                verbose=False,
            )
            data = text.encode("utf-8")
            stats = client.send(data)
            client.send_fin()
            enqueue_event({
                "type": "transfer_complete",
                "stats": stats,
                "text": text,
                "tunnel_id": "{:04x}".format(stats['tunnel_id']),
            })

        threading.Thread(target=do_send, daemon=True).start()
        await ws.send_json({"type": "transfer_started", "text": text})

    elif action == "demo_compare":
        payload = msg.get("text", "secret exfiltrated data").encode("utf-8")

        codec = "hex"
        standard_encoded = build_packet(payload, 0xAAAA, 0, codec, position_frac=0.0)
        mutant_encoded = build_packet(payload, 0xBBBB, 0, codec, position_frac=None)

        await ws.send_json({
            "type": "compare",
            "standard": {
                "encoded": standard_encoded,
                "header_pos": 0,
                "total_len": len(standard_encoded),
            },
            "mutant": {
                "encoded": mutant_encoded,
                "total_len": len(mutant_encoded),
            },
            "payload_hex": payload.hex(),
        })

    elif action == "get_config":
        await ws.send_json({
            "type": "config",
            "encodings": list(ENCODING_STRATEGIES),
            "chunkings": list(CHUNKING_STRATEGIES),
            "timings": list(TIMING_STRATEGIES),
            "domain": DOMAIN,
            "server": "{}:{}".format(SERVER_HOST, SERVER_PORT),
        })


