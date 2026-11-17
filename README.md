# Python Port & Banner Auditor (`python-port-banner-auditor`)

A zero-dependency Python command-line network security auditing utility that scans target hosts across common TCP ports, grabs live service banners, flags exposed infrastructure risks, and exports structured JSON reports.

## Features

- **Concurrent Socket Scanning:** Uses `ThreadPoolExecutor` and non-blocking TCP sockets for fast multi-port enumeration.
- **Protocol Banner Grabbing:** Captures initial server responses and probes HTTP endpoints for server headers.
- **Risk Classification:** Automatically flags cleartext protocols (Telnet, FTP) and exposed databases (MySQL, PostgreSQL, Redis).
- **Zero External Dependencies:** Runs natively with Python 3 standard library modules.

## Usage

Scan localhost across common service ports:

```bash
python3 audit.py 127.0.0.1
```
