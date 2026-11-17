import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from src.scanner import probe_port
from src.signatures import COMMON_PORTS

def run_host_audit(target: str, ports: list[int] | None = None, workers: int = 20) -> dict:
    target_ports = ports if ports else sorted(COMMON_PORTS.keys())
    started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve hostname '{target}': {exc}") from exc

    open_findings = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(probe_port, resolved_ip, p): p for p in target_ports}
        for future in as_completed(futures):
            finding = future.result()
            if finding:
                open_findings.append(finding)

    open_findings.sort(key=lambda item: item["port"])

    return {
        "target": target,
        "resolved_ip": resolved_ip,
        "scanned_at": started_at,
        "ports_scanned": len(target_ports),
        "open_ports_count": len(open_findings),
        "findings": open_findings,
    }