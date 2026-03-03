"""
mutant-dns client.

Data-mode:   reads from stdin (or file) → encodes → DNS queries
TUN-mode:    reads IP packets from TUN interface → encodes → DNS queries
             also polls server for responses → decodes → writes to TUN
"""

import argparse
import os
import random
import socket
import sys
import threading
import time
from typing import Optional

import dns.exception
import dns.message
import dns.query
import dns.rdatatype

from .mutations import apply_timing, chunk_data, select_encoding
from .protocol import (
    FIN_PREFIX, MAGIC, build_packet, choose_codec, encoded_to_qname,
    parse_packet, qname_to_encoded,
)

# ── DNS query type weights (from paper empirical distribution) ────────────────
_QTYPES = ['A', 'AAAA', 'TXT', 'NULL', 'CNAME', 'MX', 'NS']
_QWEIGHTS = [35, 10, 40, 5, 5, 2, 2]

_RDTYPE_MAP = {
    'A':     dns.rdatatype.A,
    'AAAA':  dns.rdatatype.AAAA,
    'TXT':   dns.rdatatype.TXT,
    'NULL':  dns.rdatatype.NULL,
    'CNAME': dns.rdatatype.CNAME,
    'MX':    dns.rdatatype.MX,
    'NS':    dns.rdatatype.NS,
}


def _choose_qtype() -> str:
    return random.choices(_QTYPES, weights=_QWEIGHTS, k=1)[0]


# ── Low-level DNS send ────────────────────────────────────────────────────────

def _send_dns(qname: str, qtype: str, server: str, port: int,
              timeout: float = 3.0) -> tuple:
    """
    Send a single DNS query.
    Returns (success: bool, rdata_txt: list[str])
      rdata_txt contains TXT record strings from the answer (for S2C data).
    """
    rdtype = _RDTYPE_MAP.get(qtype, dns.rdatatype.A)
    try:
        q = dns.message.make_query(qname, rdtype)
        q.use_edns(0, 0, 1232)
        resp = dns.query.udp(q, server, port=port, timeout=timeout)
        ok = (resp.rcode() == 0)

        # Extract TXT records from answer (server may piggyback S2C data)
        txt_data = []
        for rrset in resp.answer:
            if rrset.rdtype == dns.rdatatype.TXT:
                for rdata in rrset:
                    for string in rdata.strings:
                        txt_data.append(string.decode('latin-1'))
        return ok, txt_data

    except (dns.exception.DNSException, socket.error, OSError):
        return False, []


# ── Tunnel client ─────────────────────────────────────────────────────────────

class TunnelClient:
    """
    DNS tunnel client with 4-dimensional structural mutations.

    Usage (data mode):
        client = TunnelClient(domain='t.example.com', server='1.2.3.4')
        stats  = client.send(data_bytes)
        client.send_fin()

    Usage (TUN mode):
        client = TunnelClient(domain='t.example.com', server='1.2.3.4',
                              tun_iface=tun_fd)
        client.run_tun()   # blocking loop
    """

    def __init__(
        self,
        domain:    str,
        server:    str,
        port:      int  = 53,
        encoding:  str  = 'weighted',
        chunking:  str  = 'variable',
        timing:    str  = 'random',
        retries:   int  = 3,
        verbose:   bool = False,
        tun_iface  = None,      # file-like TUN fd (from tun.py)
        poll_interval: float = 0.2,
    ):
        self.domain        = domain
        self.server        = server
        self.port          = port
        self.encoding      = encoding
        self.chunking      = chunking
        self.timing        = timing
        self.retries       = retries
        self.verbose       = verbose
        self.tun_iface     = tun_iface
        self.poll_interval = poll_interval

        self.tunnel_id  = random.randint(1, 0xFFFF)
        self.seq        = 0
        self._s2c_buf   = bytearray()   # server-to-client reassembly
        self._s2c_next  = 0

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        if self.verbose:
            print('[mutant-dns client] {}'.format(msg), file=sys.stderr, flush=True)

    # ── Single chunk send ─────────────────────────────────────────────────────

    def _send_chunk(self, chunk: bytes) -> bool:
        codec   = select_encoding(self.encoding)
        encoded = build_packet(chunk, self.tunnel_id, self.seq, codec)
        qname   = encoded_to_qname(encoded, self.domain)
        qtype   = _choose_qtype()

        for attempt in range(self.retries):
            ok, txt = _send_dns(qname, qtype, self.server, self.port)
            self._process_s2c(txt)
            if ok:
                self._log('seq={} codec={} chunk={}B qtype={} OK'.format(
                    self.seq, codec, len(chunk), qtype))
                self.seq += 1
                return True
            if attempt < self.retries - 1:
                time.sleep(0.3)

        self._log('seq={} FAILED after {} attempts'.format(self.seq, self.retries))
        return False

    # ── Server-to-client data (piggyback in TXT records) ─────────────────────

    def _process_s2c(self, txt_records: list) -> None:
        """Parse S2C data from TXT records and write to TUN (if active)."""
        for txt in txt_records:
            result = parse_packet(txt)
            if result is None:
                continue
            payload, _tid, seq, _codec = result
            # Simple in-order delivery for TUN mode
            if self.tun_iface and seq == self._s2c_next:
                try:
                    self.tun_iface.write(payload)
                except OSError:
                    pass
                self._s2c_next += 1

    # ── Control messages ──────────────────────────────────────────────────────

    def send_fin(self) -> None:
        """Signal end-of-tunnel to the server."""
        label = '{}{:04x}{:04x}'.format(FIN_PREFIX, self.tunnel_id, self.seq)
        qname = '{}.{}'.format(label, self.domain)
        _send_dns(qname, 'TXT', self.server, self.port)
        self._log('FIN sent tunnel_id={:04x}'.format(self.tunnel_id))

    def _send_poll(self) -> list:
        """Send an empty poll query; return any TXT records (S2C data)."""
        label = 'cnpoll{:04x}{:04x}'.format(self.tunnel_id, self.seq)
        qname = '{}.{}'.format(label, self.domain)
        _, txt = _send_dns(qname, 'TXT', self.server, self.port)
        return txt

    # ── Public API: data mode ─────────────────────────────────────────────────

    def send(self, data: bytes) -> dict:
        """
        Send arbitrary data over the DNS tunnel.
        Returns a stats dict: {tunnel_id, chunks, sent, failed, bytes}.
        """
        chunks = chunk_data(data, self.chunking)
        total  = len(chunks)
        self._log('tunnel_id={:04x} chunks={} encoding={} chunking={} timing={}'.format(
            self.tunnel_id, total, self.encoding, self.chunking, self.timing))

        sent = 0
        failed = 0
        for i, chunk in enumerate(chunks):
            if i > 0:
                apply_timing(self.timing)
            if self._send_chunk(chunk):
                sent += 1
            else:
                failed += 1

        return {
            'tunnel_id': self.tunnel_id,
            'chunks':    total,
            'sent':      sent,
            'failed':    failed,
            'bytes':     len(data),
        }

    # ── Public API: TUN mode ──────────────────────────────────────────────────

    def run_tun(self) -> None:
        """
        Blocking loop for TUN (IP tunnel) mode.

        Reads IP packets from TUN → encodes → DNS queries.
        Polls server for S2C data → decodes → writes back to TUN.
        """
        if self.tun_iface is None:
            raise RuntimeError('tun_iface required for TUN mode')

        self._log('TUN mode started. tunnel_id={:04x}'.format(self.tunnel_id))

        # Start polling thread for S2C data
        poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        poll_thread.start()

        while True:
            try:
                # Read one IP packet from TUN (up to 65535 bytes)
                packet = self.tun_iface.read(65535)
                if not packet:
                    time.sleep(0.01)
                    continue

                chunks = chunk_data(packet, self.chunking)
                for i, chunk in enumerate(chunks):
                    if i > 0:
                        apply_timing(self.timing)
                    self._send_chunk(chunk)

            except KeyboardInterrupt:
                self._log('TUN mode stopped.')
                break
            except OSError as e:
                self._log('TUN read error: {}'.format(e))
                break

    def _poll_loop(self) -> None:
        """Background thread: periodically polls server for S2C data."""
        while True:
            time.sleep(self.poll_interval)
            try:
                txt = self._send_poll()
                self._process_s2c(txt)
            except Exception:
                pass


# ── CLI entry point ───────────────────────────────────────────────────────────

def _parse_args():
    from .mutations import ENCODING_STRATEGIES, CHUNKING_STRATEGIES, TIMING_STRATEGIES
    from mutant_dns import __version__

    p = argparse.ArgumentParser(
        prog='mutant-dns-client',
        description='DNS tunnel client — variable-position header mutations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  echo "secret" | mutant-dns-client --domain tunnel.example.com --server 1.2.3.4
  cat file.bin  | mutant-dns-client --domain tunnel.example.com --server 1.2.3.4 -v
  sudo mutant-dns-client --domain tunnel.example.com --server 1.2.3.4 --tun
        """,
    )
    p.add_argument('--version', action='version', version='mutant-dns ' + __version__)

    req = p.add_argument_group('required')
    req.add_argument('--domain', required=True,
                     help='Tunnel base domain  (e.g. tunnel.example.com)')
    req.add_argument('--server', required=True,
                     help='IP address of the mutant-dns-server')

    conn = p.add_argument_group('connection')
    conn.add_argument('--port',    type=int, default=53,
                      help='DNS server port [default: 53]')
    conn.add_argument('--retries', type=int, default=3,
                      help='Retries per failed chunk [default: 3]')

    mut = p.add_argument_group('mutations')
    mut.add_argument('--encoding', default='weighted',
                     choices=ENCODING_STRATEGIES,
                     help='Encoding: weighted|hex|base32|base64  [default: weighted]')
    mut.add_argument('--chunking', default='variable',
                     choices=CHUNKING_STRATEGIES,
                     help='Chunking: variable|fixed40|fixed35|fixed16  [default: variable]')
    mut.add_argument('--timing',   default='random',
                     choices=TIMING_STRATEGIES,
                     help='Timing: burst|steady|random|human|burst_pause  [default: random]')

    data = p.add_argument_group('data mode')
    data.add_argument('--input', default='-',
                      help='Input file  (- for stdin)  [default: stdin]')

    tun = p.add_argument_group('TUN mode  (requires root, Linux)')
    tun.add_argument('--tun',           action='store_true',
                     help='Enable TUN mode — full IP tunnel like iodine')
    tun.add_argument('--tun-ip',        default='10.0.0.2',
                     help='Client TUN IP  [default: 10.0.0.2]')
    tun.add_argument('--tun-gw',        default='10.0.0.1',
                     help='Server (gateway) TUN IP  [default: 10.0.0.1]')
    tun.add_argument('--tun-name',      default='tun0',
                     help='TUN interface name  [default: tun0]')
    tun.add_argument('--tun-mtu',       type=int, default=1200,
                     help='TUN MTU  [default: 1200]')
    tun.add_argument('--default-route', action='store_true',
                     help='Route all traffic through the tunnel')
    tun.add_argument('--poll-interval', type=float, default=0.2,
                     help='S2C poll interval in seconds  [default: 0.2]')

    p.add_argument('--verbose', '-v', action='store_true',
                   help='Verbose output to stderr')
    return p.parse_args()


def main():
    args = _parse_args()

    if args.tun:
        from mutant_dns.tun import add_route, configure_tun, create_tun, teardown_tun

        if os.geteuid() != 0:
            print('[error] TUN mode requires root (sudo).', file=sys.stderr)
            sys.exit(1)

        print('[mutant-dns client] Starting TUN mode...', file=sys.stderr)
        tun = None
        try:
            tun = create_tun(args.tun_name)
            configure_tun(args.tun_name, args.tun_ip, args.tun_gw, mtu=args.tun_mtu)
            print('[mutant-dns client] TUN up: {}/{} MTU={}'.format(
                args.tun_name, args.tun_ip, args.tun_mtu), file=sys.stderr)

            if args.default_route:
                add_route('0.0.0.0/0', args.tun_gw, args.tun_name)
                print('[mutant-dns client] Default route → {}'.format(
                    args.tun_gw), file=sys.stderr)

            client = TunnelClient(
                domain=args.domain, server=args.server, port=args.port,
                encoding=args.encoding, chunking=args.chunking,
                timing=args.timing, retries=args.retries,
                verbose=args.verbose, tun_iface=tun,
                poll_interval=args.poll_interval,
            )
            client.run_tun()

        except KeyboardInterrupt:
            pass
        finally:
            if tun is not None:
                teardown_tun(args.tun_name, tun)
                print('\n[mutant-dns client] TUN removed.', file=sys.stderr)
        return

    # Data mode
    if args.input == '-':
        data = sys.stdin.buffer.read()
    else:
        try:
            with open(args.input, 'rb') as f:
                data = f.read()
        except OSError as e:
            print('[error] {}'.format(e), file=sys.stderr)
            sys.exit(1)

    if not data:
        print('[error] No data to send.', file=sys.stderr)
        sys.exit(1)

    client = TunnelClient(
        domain=args.domain, server=args.server, port=args.port,
        encoding=args.encoding, chunking=args.chunking,
        timing=args.timing, retries=args.retries,
        verbose=args.verbose,
    )

    stats = client.send(data)
    client.send_fin()

    ok = stats['failed'] == 0
    status = 'OK' if ok else 'PARTIAL ({} failed)'.format(stats['failed'])
    print('[mutant-dns client] {} — {}/{} chunks, {} bytes, tunnel_id={:04x}'.format(
        status, stats['sent'], stats['chunks'], stats['bytes'], stats['tunnel_id']),
        file=sys.stderr)
    sys.exit(0 if ok else 1)
