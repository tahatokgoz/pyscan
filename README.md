# pyScan — Lightweight nmap-like async port scanner
A simple, educational port scanner written in Python.
- Async scanning with `asyncio`
- Banner grabbing (HTTP/SSH/TLS)
- JSON output
- Authorized-use only

## Quick start
python step5_banner_json.py scanme.nmap.org -p 22,80,443,8080 --json scanme.json

## Examples
See `examples/` for sample outputs.

## Legal/Ethics
Use only on systems you own or have explicit permission to test.
