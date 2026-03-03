"""
mutant-dns server.

Authoritative DNS server that:
  1. Receives DNS queries
  2. Strips the base domain suffix
  3. Concatenates subdomain labels → encoded string
  4. Tries hex/base32/base64 decode and searches for magic bytes 0xC1AE
  5. Extracts payload, tunnel_id, seq
  6. Reassembles ordered data → writes to stdout (data mode) or TUN (tun mode)
  7. Optionally piggybacks S2C data in TXT records of responses (tun mode)

Requires: dnslib
"""

import argparse
import os
import socket
import sys
import threading
from collections import defaultdict
from typing import Optional

import dnslib
from dnslib import A, DNSRecord, QTYPE, RCODE, RR, TXT

from .protocol import (
    FIN_PREFIX, build_packet, parse_packet, qname_to_encoded, choose_codec,
)
from .mutations import select_encoding, chunk_data


# ── Reassembly buffer ─────────────────────────────────────────────────────────

class ReassemblyBuffer:
    """
    Thread-safe per-tunnel reassembly buffer.

    Packets arrive with (tunnel_id, seq, payload).
    In-order payloads are flushed immediately; out-of-order ones are held
    until the gap is filled.
    """

    def __init__(self, output=None, verbose: bool = False):
        self._lock    = threading.Lock()
        self._hold    = defaultdict(dict)   # {tid: {seq: bytes}}
        self._next    = defaultdict(int)    # {tid: next expected seq}
        self._out     = output or sys.stdout.buffer
        self._verbose = verbose

    def _log(self, msg: str) -> None:
        if self._verbose:
            print('[mutant-dns server] {}'.format(msg), file=sys.stderr, flush=True)

    def add(self, payload: bytes, tunnel_id: int, seq: int) -> None:
        with self._lock:
            buf = self._hold[tunnel_id]
            if seq not in buf:
                buf[seq] = payload
                self._flush(tunnel_id)

    def _flush(self, tunnel_id: int) -> None:
        buf  = self._hold[tunnel_id]
        nxt  = self._next[tunnel_id]
        while nxt in buf:
            data = buf.pop(nxt)
            self._out.write(data)
            self._out.flush()
            self._log('flushed tid={:04x} seq={} len={}'.format(
                tunnel_id, nxt, len(data)))
            nxt += 1
        self._next[tunnel_id] = nxt

    def close(self, tunnel_id: int) -> None:
        with self._lock:
            remaining = self._hold.pop(tunnel_id, {})
            if remaining:
                self._log('tid={:04x} closed with {} out-of-order packets discarded'.format(
                    tunnel_id, len(remaining)))
            self._next.pop(tunnel_id, None)
            self._log('tid={:04x} tunnel closed'.format(tunnel_id))


# ── S2C queue (server-to-client, used in TUN mode) ───────────────────────────

class S2CQueue:
    """
    Queues outgoing (server-to-client) chunks to be piggybacked in DNS answers.
    In TUN mode, the server reads from TUN and enqueues here;
    the DNS handler dequeues and adds TXT records to the response.
    """

    def __init__(self):
        self._lock   = threading.Lock()
        self._queues = defaultdict(list)   # {tunnel_id: [encoded_str, ...]}

    def enqueue(self, tunnel_id: int, payload: bytes, seq: int) -> None:
        codec   = choose_codec()
        encoded = build_packet(payload, tunnel_id, seq, codec)
        with self._lock:
            self._queues[tunnel_id].append(encoded)

    def dequeue(self, tunnel_id: int) -> Optional[str]:
        """Pop one encoded chunk for this tunnel, or None if queue is empty."""
        with self._lock:
            q = self._queues.get(tunnel_id)
            if q:
                return q.pop(0)
        return None


# ── DNS server ────────────────────────────────────────────────────────────────

class DNSTunnelServer:
    """
    UDP DNS server that decodes mutant-dns tunnel traffic.

    data mode:  decoded bytes → output stream (stdout by default)
    tun mode:   decoded bytes → TUN interface; TUN reads → S2C queue → responses
    """

    def __init__(
        self,
        domain:  str,
        host:    str  = '0.0.0.0',
        port:    int  = 53,
        output         = None,    # writable binary stream
        verbose: bool  = False,
        tun_iface      = None,    # file-like TUN fd (tun.py)
    ):
        self.domain    = domain.lower().rstrip('.')
        self.host      = host
        self.port      = port
        self.verbose   = verbose
        self.tun_iface = tun_iface

        self._buf      = ReassemblyBuffer(output=output, verbose=verbose)
        self._s2c      = S2CQueue()
        self._sock     = None

        # If TUN mode, start reader thread
        if tun_iface is not None:
            self._tun_seq = defaultdict(int)
            t = threading.Thread(target=self._tun_reader_loop, daemon=True)
            t.start()

    def _log(self, msg: str) -> None:
        if self.verbose:
            print('[mutant-dns server] {}'.format(msg), file=sys.stderr, flush=True)

    # ── TUN reader (S2C path) ─────────────────────────────────────────────────

    def _tun_reader_loop(self) -> None:
        """Read IP packets from TUN and enqueue for delivery to clients."""
        while True:
            try:
                packet = self.tun_iface.read(65535)
                if not packet:
                    continue
                # We don't know the tunnel_id for TUN-originated packets;
                # broadcast to all active tunnels (tracked by reassembly buffer)
                with self._buf._lock:
                    active = list(self._buf._next.keys())
                for tid in active:
                    seq = self._tun_seq[tid]
                    self._s2c.enqueue(tid, packet, seq)
                    self._tun_seq[tid] += 1
            except OSError:
                break
            except Exception as e:
                self._log('TUN reader error: {}'.format(e))

    # ── Packet handler ────────────────────────────────────────────────────────

    def _handle(self, data: bytes, addr: tuple) -> bytes:
        try:
            request = DNSRecord.parse(data)
        except Exception:
            return b''

        qname = str(request.q.qname).lower().rstrip('.')
        self._log('query {} from {}:{}'.format(qname, addr[0], addr[1]))

        # Only handle queries for our domain
        if not (qname.endswith('.' + self.domain) or qname == self.domain):
            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            return reply.pack()

        subdomain = qname_to_encoded(qname, self.domain)

        # ── FIN control message ───────────────────────────────────────────────
        if subdomain.startswith(FIN_PREFIX):
            try:
                tid = int(subdomain[len(FIN_PREFIX):len(FIN_PREFIX) + 4], 16)
                self._buf.close(tid)
            except (ValueError, IndexError):
                pass
            return self._make_reply(request, tunnel_id=None)

        # ── Poll message (empty, client checking for S2C data) ───────────────
        if subdomain.startswith('cnpoll'):
            try:
                tid = int(subdomain[6:10], 16)
            except (ValueError, IndexError):
                tid = None
            return self._make_reply(request, tunnel_id=tid)

        # ── Data packet ───────────────────────────────────────────────────────
        if subdomain:
            result = parse_packet(subdomain)
            if result is not None:
                payload, tunnel_id, seq, codec = result
                self._log('tid={:04x} seq={} codec={} payload={}B'.format(
                    tunnel_id, seq, codec, len(payload)))
                # C2S: write to output or TUN
                if self.tun_iface is not None:
                    try:
                        self.tun_iface.write(payload)
                    except OSError as e:
                        self._log('TUN write error: {}'.format(e))
                else:
                    self._buf.add(payload, tunnel_id, seq)
                return self._make_reply(request, tunnel_id=tunnel_id)

        return self._make_reply(request, tunnel_id=None)

    def _make_reply(self, request: DNSRecord, tunnel_id: Optional[int]) -> bytes:
        """Build a DNS reply. Piggyback S2C data in TXT record if available."""
        reply = request.reply()
        reply.header.rcode = RCODE.NOERROR

        # Always add a dummy A record (keeps resolvers happy)
        reply.add_answer(RR(
            rname=request.q.qname,
            rtype=QTYPE.A,
            ttl=1,
            rdata=A('10.0.0.1'),
        ))

        # Piggyback S2C data in TXT record (TUN mode or if queue has data)
        if tunnel_id is not None:
            encoded = self._s2c.dequeue(tunnel_id)
            if encoded:
                # TXT strings are limited to 255 bytes each
                chunks = [encoded[i:i + 255] for i in range(0, len(encoded), 255)]
                reply.add_answer(RR(
                    rname=request.q.qname,
                    rtype=QTYPE.TXT,
                    ttl=1,
                    rdata=TXT([c.encode() for c in chunks]),
                ))

        return reply.pack()

    # ── Main loop ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))

        print('[mutant-dns server] Listening on {}:{} for domain={}'.format(
            self.host, self.port, self.domain), file=sys.stderr, flush=True)

        while True:
            try:
                data, addr = self._sock.recvfrom(4096)
                reply = self._handle(data, addr)
                if reply:
                    self._sock.sendto(reply, addr)
            except KeyboardInterrupt:
                print('\n[mutant-dns server] Stopped.', file=sys.stderr)
                break
            except Exception as e:
                self._log('Error: {}'.format(e))


# ── CLI entry point ───────────────────────────────────────────────────────────

def _parse_args():
    from mutant_dns import __version__

    p = argparse.ArgumentParser(
        prog='mutant-dns-server',
        description='DNS tunnel server — decodes variable-position header mutations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  mutant-dns-server --domain tunnel.example.com
  mutant-dns-server --domain tunnel.example.com --port 5353 --output decoded.bin -v
  sudo mutant-dns-server --domain tunnel.example.com --tun --tun-ip 10.0.0.1

DNS delegation (for real-world use):
  Add to your zone file:
    tunnel.example.com.  NS  ns1.example.com.
    ns1.example.com.     A   <server public IP>

  For local testing, point the client directly with --server <ip>.
        """,
    )
    p.add_argument('--version', action='version', version='mutant-dns ' + __version__)

    req = p.add_argument_group('required')
    req.add_argument('--domain', required=True,
                     help='Tunnel base domain  (e.g. tunnel.example.com)')

    net = p.add_argument_group('network')
    net.add_argument('--host', default='0.0.0.0',
                     help='Bind address  [default: 0.0.0.0]')
    net.add_argument('--port', type=int, default=53,
                     help='UDP listen port  [default: 53]')

    out = p.add_argument_group('data mode output')
    out.add_argument('--output', default='-',
                     help='Output file for decoded data  (- for stdout)  [default: stdout]')

    tun = p.add_argument_group('TUN mode  (requires root, Linux)')
    tun.add_argument('--tun',      action='store_true',
                     help='Enable TUN mode — full IP tunnel like iodined')
    tun.add_argument('--tun-ip',   default='10.0.0.1',
                     help='Server TUN IP  [default: 10.0.0.1]')
    tun.add_argument('--tun-name', default='tun0',
                     help='TUN interface name  [default: tun0]')
    tun.add_argument('--tun-mtu',  type=int, default=1200,
                     help='TUN MTU  [default: 1200]')

    p.add_argument('--verbose', '-v', action='store_true',
                   help='Verbose logging to stderr')
    return p.parse_args()


def main():
    args = _parse_args()
    tun_fd = None

    if args.tun:
        from mutant_dns.tun import configure_tun, create_tun

        if os.geteuid() != 0:
            print('[error] TUN mode requires root (sudo).', file=sys.stderr)
            sys.exit(1)

        print('[mutant-dns server] Creating {}...'.format(args.tun_name), file=sys.stderr)
        tun_fd = create_tun(args.tun_name)
        configure_tun(args.tun_name, args.tun_ip, '0.0.0.0', mtu=args.tun_mtu)
        print('[mutant-dns server] TUN up: {}/{} MTU={}'.format(
            args.tun_name, args.tun_ip, args.tun_mtu), file=sys.stderr)

    if args.tun:
        output_stream = None
    elif args.output == '-':
        output_stream = sys.stdout.buffer
    else:
        try:
            output_stream = open(args.output, 'wb')
        except OSError as e:
            print('[error] {}'.format(e), file=sys.stderr)
            sys.exit(1)

    server = DNSTunnelServer(
        domain=args.domain, host=args.host, port=args.port,
        output=output_stream, verbose=args.verbose, tun_iface=tun_fd,
    )

    try:
        server.run()
    except PermissionError:
        print('[error] Cannot bind to port {}. '
              'Use --port 5353 or run with sudo.'.format(args.port), file=sys.stderr)
        sys.exit(1)
    finally:
        if tun_fd is not None:
            from mutant_dns.tun import teardown_tun
            teardown_tun(args.tun_name, tun_fd)
            print('[mutant-dns server] TUN removed.', file=sys.stderr)
        if output_stream and args.output != '-':
            output_stream.close()
