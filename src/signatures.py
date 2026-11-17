COMMON_PORTS = {
    21: ("FTP", "High - Unencrypted file transfer"),
    22: ("SSH", "Medium - Remote shell access"),
    23: ("Telnet", "Critical - Cleartext remote terminal"),
    25: ("SMTP", "Low - Mail transfer agent"),
    53: ("DNS", "Low - Domain name resolution"),
    80: ("HTTP", "Low - Unencrypted web traffic"),
    110: ("POP3", "Medium - Unencrypted mail retrieval"),
    143: ("IMAP", "Medium - Mail access protocol"),
    443: ("HTTPS", "Low - Encrypted TLS web traffic"),
    3306: ("MySQL", "High - Exposed relational database"),
    5432: ("PostgreSQL", "High - Exposed relational database"),
    6379: ("Redis", "Critical - Exposed in-memory datastore"),
    8000: ("HTTP-Alt", "Low - Development web server"),
    8080: ("HTTP-Proxy", "Low - Alternate web/proxy service"),
}

def identify_service(port: int, banner: str) -> tuple[str, str]:
    default_name, risk = COMMON_PORTS.get(port, ("Unknown", "Info - Custom TCP port"))
    banner_lower = banner.lower()

    if "ssh-" in banner_lower:
        return ("SSH", risk)
    if "http/" in banner_lower or "html" in banner_lower:
        return ("HTTP", risk)
    if "smtp" in banner_lower or banner.startswith("220 "):
        return ("SMTP/FTP", risk)
    if "mysql" in banner_lower or "mariadb" in banner_lower:
        return ("MySQL/MariaDB", "High - Exposed relational database")
    if "redis" in banner_lower or "-err" in banner_lower:
        return ("Redis", "Critical - Exposed in-memory datastore")

    return (default_name, risk)