import argparse
import sys
from src.auditor import run_host_audit
from src.reporter import print_terminal_report, save_json_report

def parse_ports(port_arg: str) -> list[int]:
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-", 1))
            ports.update(range(start, end + 1))
        elif part.isdigit():
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)

def main():
    parser = argparse.ArgumentParser(description="TCP Port & Service Banner Security Auditor")
    parser.add_argument("target", nargs="?", default="127.0.0.1", help="Target hostname or IP (default: 127.0.0.1)")
    parser.add_argument("-p", "--ports", default="", help="Comma-separated ports or ranges (e.g., 22,80,8000-8010)")
    parser.add_argument("--save", action="store_true", help="Export JSON report to reports/ directory")
    args = parser.parse_args()

    custom_ports = parse_ports(args.ports) if args.ports else None

    print(f"[*] Starting TCP banner audit against {args.target}...")
    try:
        report = run_host_audit(args.target, ports=custom_ports)
        print_terminal_report(report)
        if args.save:
            saved_file = save_json_report(report)
            print(f"[+] JSON report saved to: {saved_file}")
    except ValueError as err:
        print(f"[!] Audit failed: {err}")
        sys.exit(1)

if __name__ == "__main__":
    main()