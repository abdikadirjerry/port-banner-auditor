import json
from pathlib import Path

def print_terminal_report(report: dict) -> None:
    print("\n" + "=" * 68)
    print(f"SECURITY PORT & BANNER AUDIT REPORT // {report['target']} ({report['resolved_ip']})")
    print(f"Timestamp: {report['scanned_at']} | Ports Checked: {report['ports_scanned']}")
    print("=" * 68)

    if not report["findings"]:
        print("\n[+] No open TCP ports detected in the scanned range.\n")
        return

    print(f"\n{'PORT':<8} {'SERVICE':<15} {'BANNER':<32} {'RISK LEVEL'}")
    print("-" * 68)
    for item in report["findings"]:
        print(f"{item['port']:<8} {item['service']:<15} {item['banner'][:30]:<32} {item['risk'].split(' - ')[0]}")
    print()

def save_json_report(report: dict, output_dir: str = "reports") -> Path:
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    safe_host = report["target"].replace(".", "_").replace(":", "_")
    file_path = out_path / f"audit_{safe_host}.json"
    file_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return file_path