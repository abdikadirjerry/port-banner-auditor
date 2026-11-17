import socket
from src.signatures import identify_service

def probe_port(host: str, port: int, timeout: float = 1.2) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result != 0:
                return None

            banner = ""
            try:
                # Send lightweight HTTP HEAD probe for web ports
                if port in (80, 8000, 8080, 8443):
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                raw = sock.recv(512)
                banner = raw.decode("utf-8", errors="replace").strip().splitlines()[0] if raw else ""
            except Exception:
                banner = "No banner returned"

            service_name, risk_note = identify_service(port, banner)
            return {
                "port": port,
                "state": "OPEN",
                "service": service_name,
                "banner": banner[:100] if banner else "Silent open port",
                "risk": risk_note,
            }
    except (socket.gaierror, OSError):
        return None