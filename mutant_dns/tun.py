"""
TUN interface module for mutant-dns (Linux only, requires root).

Creates a Layer-3 (TUN) virtual network interface and configures it
with an IP address, enabling full IP tunneling like iodine.

Usage:
    from mutant_dns.tun import create_tun, configure_tun

    tun = create_tun('tun0')
    configure_tun('tun0', '10.0.0.2', '10.0.0.1', mtu=1200)
    # tun.read(65535)  → IP packet bytes
    # tun.write(data)  → inject IP packet into the interface
"""

import fcntl
import os
import struct
import subprocess
import sys
from typing import Optional

# ── Linux TUN constants ───────────────────────────────────────────────────────
_TUNSETIFF  = 0x400454CA
_IFF_TUN    = 0x0001
_IFF_NO_PI  = 0x1000     # No packet info header (we just want raw IP)
_TUN_DEVICE = '/dev/net/tun'


def create_tun(name: str = 'tun0'):
    """
    Create and return an open TUN file object.

    The returned object supports:
        read(n)    → bytes  (one IP packet, up to n bytes)
        write(b)   → int    (inject IP packet)
        close()

    Raises:
        PermissionError  if not running as root
        OSError          if /dev/net/tun is unavailable
    """
    if not os.path.exists(_TUN_DEVICE):
        raise OSError(
            '{} not found. Is the tun kernel module loaded? '
            'Try: modprobe tun'.format(_TUN_DEVICE)
        )

    try:
        tun = open(_TUN_DEVICE, 'r+b', buffering=0)
    except PermissionError:
        raise PermissionError(
            'Cannot open {}. Run mutant-dns as root (sudo).'.format(_TUN_DEVICE)
        )

    # Configure the interface name and flags
    ifr = struct.pack('16sH', name.encode()[:15], _IFF_TUN | _IFF_NO_PI)
    try:
        fcntl.ioctl(tun, _TUNSETIFF, ifr)
    except OSError as e:
        tun.close()
        raise OSError('ioctl TUNSETIFF failed: {}'.format(e))

    return tun


def configure_tun(
    name:       str,
    local_ip:   str,
    remote_ip:  str,
    netmask:    str = '255.255.255.0',
    mtu:        int = 1200,
) -> None:
    """
    Assign IP address and bring up the TUN interface.

    Args:
        name       interface name (e.g. 'tun0')
        local_ip   this machine's tunnel IP (e.g. '10.0.0.2')
        remote_ip  peer's tunnel IP (e.g. '10.0.0.1')
        netmask    subnet mask
        mtu        MTU — keep below DNS payload limit (default 1200)
    """
    cmds = [
        ['ip', 'addr', 'add', '{}/24'.format(local_ip), 'dev', name],
        ['ip', 'link', 'set', 'dev', name, 'mtu', str(mtu)],
        ['ip', 'link', 'set', 'dev', name, 'up'],
    ]
    for cmd in cmds:
        result = subprocess.run(cmd, capture_output=True)
        if result.returncode != 0:
            raise OSError('Failed: {}\n{}'.format(
                ' '.join(cmd), result.stderr.decode()))


def add_route(network: str, gateway: str, dev: str) -> None:
    """
    Add a routing table entry through the tunnel.

    Example:
        add_route('0.0.0.0/0', '10.0.0.1', 'tun0')  # default route
    """
    subprocess.run(
        ['ip', 'route', 'add', network, 'via', gateway, 'dev', dev],
        check=True
    )


def delete_route(network: str) -> None:
    """Remove a routing table entry (best-effort, ignores errors)."""
    subprocess.run(
        ['ip', 'route', 'del', network],
        capture_output=True
    )


def teardown_tun(name: str, tun_fd=None) -> None:
    """Close TUN fd and remove the interface."""
    if tun_fd is not None:
        try:
            tun_fd.close()
        except OSError:
            pass
    subprocess.run(['ip', 'link', 'del', name], capture_output=True)


# ── MTU / fragmentation helpers ───────────────────────────────────────────────

def max_payload_bytes(domain: str, encoding: str = 'hex') -> int:
    """
    Estimate the maximum data bytes we can fit in one DNS query given
    the encoding overhead, DNS label limits, and the 9-byte protocol header.

    DNS name limit: 253 chars total
    Domain overhead: len(domain) + 1 (for the separating dot)
    Available for subdomain: 253 - len(domain) - 1
    Each label: max 63 chars
    Number of labels: floor(available / 64)  (63 chars + 1 dot)

    Encoding expansion (per byte):
        hex    → 2 chars
        base32 → 1.6 chars  (8/5)
        base64 → 1.33 chars (4/3)
    """
    domain     = domain.rstrip('.')
    available  = 253 - len(domain) - 1   # chars for subdomain labels
    # subtract dot separators: n labels need n-1 dots (round conservatively)
    n_labels   = available // 64
    label_chars = n_labels * 63

    expansion = {'hex': 2.0, 'base32': 1.6, 'base64': 1.34}.get(encoding, 2.0)
    # header is 9 bytes → expands the same way
    header_chars = int(9 * expansion)
    data_chars   = label_chars - header_chars
    return max(1, int(data_chars / expansion))
