
<p align="center">
  <img src="https://raw.githubusercontent.com/ByteBeem/pentra/main/pentra-banner.png" alt="Pentra Banner" />
</p>

**Pentra** is a lightweight, modular desktop penetration testing platform built with Rust. It is designed for speed, flexibility, and extensibility—giving security engineers and researchers a powerful toolkit without the overhead of bulky frameworks.

---

## Overview

Pentra aims to provide a clean, efficient, and customizable environment for performing penetration testing tasks. Built in Rust, it emphasizes:

* High performance
* Memory safety
* Modular architecture
* Native desktop experience

---

## Features

* **Modular Plugin System**
  Easily add, remove, or customize modules without affecting the core system.

* **Fast Execution Engine**
  Rust-powered concurrency ensures fast scanning and analysis.

* **Cross-Platform Support**
  Runs on Windows, Linux, and macOS.

* **Interactive CLI**
  A clean, expressive command-line interface with rich output formatting.

* **Custom Tool Integration**
  Plug in external tools or scripts (Python, Bash, etc.).

* **Secure by Design**
  Memory-safe architecture reduces vulnerabilities in the tool itself.

---

## Installation

### Prerequisites

* Rust (latest stable)
* Cargo

### Build from Source

```bash
git clone https://github.com/ByteBeem/pentra.git
cd pentra
cargo build --release
```

### Run

```bash
./target/release/pentra --help
```

---

## Usage

### Port Scanner

Pentra's port scanner is a multi-strategy, async TCP/UDP scanner with service detection, banner grabbing, and OS fingerprinting.

#### Basic Scan

```bash
# Scan top 1000 ports on a host
pentra scan --target 192.168.1.1

# Scan a hostname with banner grabbing and OS detection
pentra scan --target scanme.nmap.org --banners --os-detect
```

#### Port Specification

```bash
# Named sets
pentra scan -t 192.168.1.1 -p top100        # Nmap-style top 100 ports
pentra scan -t 192.168.1.1 -p top1000       # Top 1000 ports (default)
pentra scan -t 192.168.1.1 -p all           # All 65535 ports
pentra scan -t 192.168.1.1 -p web           # HTTP/HTTPS variants
pentra scan -t 192.168.1.1 -p db            # Common database ports
pentra scan -t 192.168.1.1 -p mail          # SMTP, IMAP, POP3, etc.
pentra scan -t 192.168.1.1 -p smb           # SMB/NetBIOS
pentra scan -t 192.168.1.1 -p voip          # SIP, RTP
pentra scan -t 192.168.1.1 -p infra         # Docker, Kubernetes, etcd, Consul

# Ranges and lists
pentra scan -t 192.168.1.1 -p 1-1024
pentra scan -t 192.168.1.1 -p 22,80,443,8080
pentra scan -t 192.168.1.1 -p 8000-9000
```

#### Scan Techniques

```bash
pentra scan -t 192.168.1.1 --technique connect   # Full TCP connect (default, no root required)
pentra scan -t 192.168.1.1 --technique syn        # SYN half-open (requires root)
pentra scan -t 192.168.1.1 --technique fin        # FIN scan — bypasses some firewalls
pentra scan -t 192.168.1.1 --technique xmas       # Xmas scan — FIN+URG+PSH flags
pentra scan -t 192.168.1.1 --technique null       # Null scan — no flags
pentra scan -t 192.168.1.1 --technique ack        # ACK scan — maps firewall rulesets
pentra scan -t 192.168.1.1 --technique window     # Window scan — ACK variant
pentra scan -t 192.168.1.1 --technique udp        # UDP scan with protocol-specific probes
```

#### Timing Profiles

Timing profiles control speed and stealth. They map 1:1 with Nmap's T0–T5.

| Flag | Alias | Timeout | Concurrency | Use Case |
|------|-------|---------|-------------|----------|
| `-T paranoid` | T0 | 5000ms | 1 | Maximum evasion, IDS bypass |
| `-T sneaky` | T1 | 5000ms | 5 | Slow and low |
| `-T polite` | T2 | 3000ms | 20 | Avoid congesting the target |
| `-T normal` | T3 | 1000ms | 250 | Default |
| `-T aggressive` | T4 | 500ms | 500 | Fast, assumes reliable network |
| `-T insane` | T5 | 250ms | 1000 | Maximum speed |

```bash
pentra scan -t 192.168.1.1 -T aggressive
pentra scan -t 192.168.1.1 -T paranoid
pentra scan -t 192.168.1.1 -T 4             # Numeric shorthand
```

#### Output & Reporting

```bash
# Output formats
pentra scan -t 192.168.1.1 -o table         # Rich terminal table (default)
pentra scan -t 192.168.1.1 -o json          # JSON
pentra scan -t 192.168.1.1 -o csv           # CSV

# Save to file
pentra scan -t 192.168.1.1 -o json -f results.json
pentra scan -t 192.168.1.1 -o csv  -f results.csv

# Only show open ports
pentra scan -t 192.168.1.1 --open-only
```

#### Full Option Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-t`, `--target` | *(required)* | Target IP, hostname |
| `-p`, `--ports` | `top1000` | Port spec: range, list, or named set |
| `--technique` | `connect` | Scan technique (see above) |
| `-T`, `--timing` | `normal` | Timing profile T0–T5 |
| `--concurrency` | `250` | Max parallel connections |
| `--timeout` | `1000` | Per-port timeout in ms |
| `-b`, `--banners` | off | Grab service banners |
| `--os-detect` | off | Heuristic OS fingerprinting |
| `-o`, `--output` | `table` | Output format: `table`, `json`, `csv` |
| `-f`, `--file` | — | Save output to file |
| `--open-only` | off | Suppress closed/filtered ports |
| `-r`, `--randomize` | off | Randomize port order |
| `--retries` | `1` | Retries per port (UDP / unreliable) |
| `--source-port` | `0` | Source port (0 = random) |
| `--dns` | `on` | DNS mode: `on`, `off`, `reverse` |
| `-q`, `--quiet` | off | Suppress banner |

#### Example: Full Recon Scan

```bash
pentra scan \
  --target 10.10.10.5 \
  --ports top1000 \
  --technique connect \
  -T aggressive \
  --banners \
  --os-detect \
  --open-only \
  --output json \
  --file recon-10.10.10.5.json
```

---

## Security Notice

Pentra is intended for **authorized security testing only**.
Do not use this tool on systems you do not own or have explicit permission to test.

---

## Roadmap

* [x] Port scanner — TCP/UDP, multi-technique, banner grabbing, OS detection
* [ ] CIDR range scanning
* [ ] Raw socket SYN/FIN/Xmas/Null/ACK (root mode)
* [ ] Service version detection
* [ ] Plugin marketplace
* [ ] Distributed scanning
* [ ] AI-assisted vulnerability analysis
* [ ] Reporting engine (PDF/HTML)

---

## Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Submit a pull request

---

## License

MIT License

---

## Vision

Pentra is built to be a modern alternative to traditional pentesting frameworks—minimal, fast, and developer-friendly. Whether you're a cybersecurity engineer, researcher, or student, Pentra gives you the tools to build and test efficiently.

---
