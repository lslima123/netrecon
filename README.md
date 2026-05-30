# NetRecon

NetRecon is a lightweight multi-threaded network reconnaissance tool focused on TCP port scanning, host discovery, and basic service enumeration.

Designed for:
- learning
- CTFs
- lab environments
- security research practice
- penetration testing fundamentals

---

# Features

- CIDR network scanning (e.g. /24 support)
- TCP-based host discovery
- Multi-threaded port scanning (host + port level concurrency)
- Service identification via port mapping
- Banner grabbing
- HTTP server header detection
- Structured JSON report generation
- TXT report fallback
- CLI interface

---

# Installation

```bash
git clone https://github.com/your-username/netrecon.git

cd netrecon

python3 -m venv venv

source venv/bin/activate
````

---

# Usage

## Basic Scan (Single Host)

```bash
python3 scanner.py 127.0.0.1 -p 1-1000
```

---

## Network Scan (CIDR)

```bash
python3 scanner.py 192.168.1.0/24 -p 1-1000
```

---

## High Intensity Scan

```bash
python3 scanner.py 192.168.1.0/24 -p 1-10000 -t 300
```

---

## Export Results (JSON)

```bash
python3 scanner.py 192.168.1.0/24 -p 1-10000 -o scan.json
```

---

## Export Results (TXT)

```bash
python3 scanner.py 192.168.1.0/24 -p 1-10000 -o scan.txt
```

---

# Example Output

## Host Discovery

* 192.168.1.10
* 192.168.1.25

---

## Open Ports

* 22/tcp OPEN (SSH)
* 80/tcp OPEN (HTTP)
* 3306/tcp OPEN (MYSQL)

---

## Banner Examples

* SSH-2.0-OpenSSH_10.0p2
* 220 Exim SMTP Ready
* Apache/2.4.x

---

# JSON Report

A structured JSON report is generated when using `-o scan.json`:

```json
{
    "127.0.0.1": [
        {
            "port": 22,
            "service": "SSH",
            "banner": "SSH-2.0-OpenSSH_10.0p2",
            "server": null
        },
        {
            "port": 80,
            "service": "HTTP",
            "banner": null,
            "server": "Apache"
        }
    ]
}
```

---

# Limitations

* TCP-based host discovery only (no ICMP/ARP)
* No UDP scanning
* No advanced service fingerprinting
* No stealth SYN scan implementation

---

# Future Improvements

* SYN scan support (raw sockets)
* Advanced service fingerprinting (-sV style)
* Top ports scanning presets
* Async IO performance version
* HTML report generation
* Nmap-compatible output format

---

# Disclaimer

This tool is intended for:

* educational purposes
* authorized security testing
* lab environments

Do not use it against systems without explicit permission.

