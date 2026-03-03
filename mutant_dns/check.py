"""
mutant-dns-check — connectivity and encoding verification tool.

Runs a series of checks against a mutant-dns-server and reports
pass/fail with actionable suggestions for each failure.

Checks performed:
  1. UDP reachable      — basic network connectivity + RTT
  2. Server identity    — is a mutant-dns-server actually listening?
  3. Domain accepted    — server handles our domain (not NXDOMAIN)
  4. Encoding hex       — real tunnel packet, codec=hex
  5. Encoding base32    — real tunnel packet, codec=base32
  6. Encoding base64    — real tunnel packet, codec=base64
"""

import argparse
import socket
import sys
import time
from typing import List, Tuple, Optional

import dns.exception
import dns.message
import dns.query
import dns.rdatatype

from .protocol import build_packet, encoded_to_qname, FIN_PREFIX


# ── Individual checks ─────────────────────────────────────────────────────────

def _udp_query(qname: str, qtype, server: str, port: int,
               timeout: float = 3.0) -> Tuple[Optional[object], float]:
    """Send one DNS query. Returns (response, rtt_ms) or (None, 0) on failure."""
    try:
        q = dns.message.make_query(qname, qtype)
        q.use_edns(0, 0, 1232)
        t0 = time.time()
        resp = dns.query.udp(q, server, port=port, timeout=timeout)
        return resp, (time.time() - t0) * 1000
    except dns.exception.Timeout:
        return None, 0
    except (dns.exception.DNSException, socket.error, OSError):
        return None, 0


def check_udp(server: str, port: int, domain: str) -> Tuple[bool, str]:
    """Check 1: basic UDP reachability."""
    resp, rtt = _udp_query(domain, dns.rdatatype.A, server, port)
    if resp is None:
        return False, (
            'timeout — is port {} open on {}?\n'
            '  Try: nc -uz {} {}\n'
            '  If testing locally, use --port 5353 to avoid needing root'
            .format(port, server, server, port)
        )
    return True, 'RTT {:.1f} ms'.format(rtt)


def check_server_identity(server: str, port: int, domain: str) -> Tuple[bool, str]:
    """Check 2: verify a mutant-dns-server is responding (cncheck probe)."""
    probe = 'cncheck.{}'.format(domain)
    resp, rtt = _udp_query(probe, dns.rdatatype.TXT, server, port)
    if resp is None:
        return False, 'no response to check probe'

    # Look for our TXT signature
    for rrset in resp.answer:
        if rrset.rdtype == dns.rdatatype.TXT:
            for rdata in rrset:
                for s in rdata.strings:
                    if s.startswith(b'mutant-dns:ok:'):
                        version = s.split(b':')[-1].decode()
                        return True, 'mutant-dns-server v{} detected'.format(version)

    if resp.rcode() == 0:
        return False, (
            'got NOERROR but no mutant-dns signature — '
            'another DNS server may be answering on {}:{}'
            .format(server, port)
        )
    rcode_name = dns.rcode.to_text(resp.rcode())
    return False, (
        '{} — is mutant-dns-server running with --domain {}?'
        .format(rcode_name, domain)
    )


def check_domain_accepted(server: str, port: int, domain: str) -> Tuple[bool, str]:
    """Check 3: domain is handled (not NXDOMAIN for a random subdomain)."""
    probe = 'cndmcheck.{}'.format(domain)
    resp, _ = _udp_query(probe, dns.rdatatype.A, server, port)
    if resp is None:
        return False, 'no response'
    if resp.rcode() == 3:  # NXDOMAIN
        return False, (
            'NXDOMAIN — server does not handle domain "{}"\n'
            '  Check that --domain on the server matches exactly'
            .format(domain)
        )
    return True, 'domain accepted'


def check_encoding(server: str, port: int, domain: str, codec: str) -> Tuple[bool, str]:
    """Check 4-6: send a real tunnel packet and verify NOERROR."""
    payload = b'mutant-dns check packet'
    try:
        encoded = build_packet(payload, tunnel_id=0xFFFE, seq=0, codec=codec)
        qname   = encoded_to_qname(encoded, domain)
        resp, rtt = _udp_query(qname, dns.rdatatype.A, server, port)
        if resp is None:
            return False, 'timeout'
        if resp.rcode() == 0:
            return True, 'RTT {:.1f} ms'.format(rtt)
        return False, 'rcode={}'.format(dns.rcode.to_text(resp.rcode()))
    except Exception as e:
        return False, str(e)


# ── Runner ────────────────────────────────────────────────────────────────────

CheckResult = Tuple[str, bool, str]   # (label, passed, detail)


def run_checks(server: str, port: int, domain: str) -> List[CheckResult]:
    results: List[CheckResult] = []

    ok, detail = check_udp(server, port, domain)
    results.append(('UDP reachable', ok, detail))
    if not ok:
        # No point continuing if we can't reach the server
        for label in ('Server identity', 'Domain accepted',
                      'Encoding hex', 'Encoding base32', 'Encoding base64'):
            results.append((label, False, 'skipped (UDP failed)'))
        return results

    ok, detail = check_server_identity(server, port, domain)
    results.append(('Server identity', ok, detail))

    ok, detail = check_domain_accepted(server, port, domain)
    results.append(('Domain accepted', ok, detail))

    for codec in ('hex', 'base32', 'base64'):
        ok, detail = check_encoding(server, port, domain, codec)
        results.append(('Encoding {}'.format(codec), ok, detail))

    return results


def print_results(results: List[CheckResult], server: str, port: int, domain: str) -> bool:
    PASS = '[+]'
    FAIL = '[!]'

    print()
    print('mutant-dns-check  {}:{}  domain={}'.format(server, port, domain))
    print('-' * 55)

    all_passed = True
    for label, passed, detail in results:
        marker = PASS if passed else FAIL
        print('  {}  {:<22} {}'.format(marker, label, detail))
        if not passed:
            all_passed = False

    print('-' * 55)
    if all_passed:
        print('  All checks passed. Ready to tunnel.')
    else:
        print('  Some checks failed. See suggestions above.')
    print()
    return all_passed


# ── CLI ───────────────────────────────────────────────────────────────────────

def _parse_args():
    from mutant_dns import __version__
    p = argparse.ArgumentParser(
        prog='mutant-dns-check',
        description='Verify connectivity and encoding support for a mutant-dns-server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  mutant-dns-check --domain tunnel.example.com --server 1.2.3.4
  mutant-dns-check --domain tunnel.example.com --server 127.0.0.1 --port 5353
        """,
    )
    p.add_argument('--version', action='version', version='mutant-dns ' + __version__)
    p.add_argument('--domain', required=True,
                   help='Tunnel base domain (must match the server)')
    p.add_argument('--server', required=True,
                   help='IP address of the mutant-dns-server')
    p.add_argument('--port',   type=int, default=53,
                   help='DNS server port [default: 53]')
    return p.parse_args()


def main():
    args = _parse_args()
    results  = run_checks(args.server, args.port, args.domain)
    all_ok   = print_results(results, args.server, args.port, args.domain)
    sys.exit(0 if all_ok else 1)
