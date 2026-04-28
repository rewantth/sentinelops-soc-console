import json
import random
from datetime import datetime, timedelta
from pathlib import Path

from faker import Faker


fake = Faker()
ALERT_TYPES = [
    "brute_force",
    "port_scan",
    "phishing_email",
    "malware_download",
    "suspicious_login",
    "powershell_execution",
    "command_and_control",
    "web_attack",
    "lateral_movement",
    "dns_tunneling",
    "privilege_escalation",
    "data_exfiltration",
]
SEVERITIES = ["low", "medium", "high", "critical"]


def timestamp_string(value):
    """Format timestamps with second-level precision."""
    return value.strftime("%Y-%m-%d %H:%M:%S")


def severity_for_type(alert_type):
    """Choose realistic severity distribution for an alert type."""
    if alert_type in {"data_exfiltration", "privilege_escalation", "command_and_control"}:
        return random.choices(SEVERITIES, weights=[8, 22, 42, 28], k=1)[0]
    if alert_type in {"brute_force", "web_attack", "lateral_movement", "dns_tunneling"}:
        return random.choices(SEVERITIES, weights=[14, 35, 38, 13], k=1)[0]
    return random.choices(SEVERITIES, weights=[25, 42, 26, 7], k=1)[0]


def safe_raw_log(alert_type, timestamp, source_ip, dest_ip):
    """Create realistic but safe defensive log text."""
    host = random.choice(["fw-edge-01", "ids-sensor-02", "mail-sec-01", "edr-core-04", "waf-prod-01", "dns-guard-01"])
    user = fake.user_name()
    domain = fake.domain_name()
    templates = {
        "brute_force": f"{timestamp} {host} auth: repeated failed login attempts user={user} src={source_ip} dst={dest_ip} count={random.randint(8, 31)} action=blocked",
        "port_scan": f"{timestamp} {host} ids: possible port scan src={source_ip} dst={dest_ip} ports_sample=22,80,443,3389 action=monitored",
        "phishing_email": f"{timestamp} {host} mail: possible phishing email recipient={user}@example.com sender=external-notice@{domain} url_reputation=suspicious action=quarantined",
        "malware_download": f"{timestamp} {host} proxy: risky executable download observed src={source_ip} dst={dest_ip} filename=invoice_viewer.exe action=blocked",
        "suspicious_login": f"{timestamp} {host} iam: unusual successful login user={user} src={source_ip} dst={dest_ip} reason=new_device_new_location",
        "powershell_execution": f"{timestamp} {host} edr: suspicious PowerShell process behavior host={source_ip} parent=office_app child=powershell.exe action=alerted",
        "command_and_control": f"{timestamp} {host} netflow: periodic outbound beacon pattern src={source_ip} dst={dest_ip} interval_seconds=300 protocol=https action=monitored",
        "web_attack": f"{timestamp} {host} waf: suspicious web exploit pattern src={source_ip} dst={dest_ip} uri=/login parameter_anomaly=true action=blocked",
        "lateral_movement": f"{timestamp} {host} windows: unusual remote service authentication src={source_ip} dst={dest_ip} protocol=smb user={user} action=alerted",
        "dns_tunneling": f"{timestamp} {host} dns: high entropy DNS query pattern src={source_ip} domain={domain} query_length={random.randint(75, 160)} action=monitored",
        "privilege_escalation": f"{timestamp} {host} edr: unexpected privilege change attempt host={source_ip} process=system_utility.exe target={dest_ip} action=blocked",
        "data_exfiltration": f"{timestamp} {host} dlp: unusual outbound data volume src={source_ip} dst={dest_ip} bytes_out={random.randint(12000000, 850000000)} action=investigate",
    }
    return templates[alert_type]


def build_alert(index, timestamp=None, alert_id=None):
    """Build one safe simulated SOC alert."""
    alert_time = timestamp or (datetime.now() - timedelta(seconds=random.randint(0, 24 * 60 * 60)))
    formatted = timestamp_string(alert_time)
    alert_type = random.choice(ALERT_TYPES)
    source_ip = fake.ipv4_private()
    dest_ip = fake.ipv4_public()
    return {
        "alert_id": alert_id or f"ALERT-2026-{index:04d}",
        "timestamp": formatted,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "alert_type": alert_type,
        "severity": severity_for_type(alert_type),
        "raw_log": safe_raw_log(alert_type, formatted, source_ip, dest_ip),
        "status": "new",
    }


def generate_alerts(count=50):
    """Generate newest-first alerts across the last 24 hours."""
    alerts = [build_alert(index + 1) for index in range(count)]
    alerts.sort(key=lambda item: item["timestamp"], reverse=True)
    return alerts


def main():
    """Write simulated alerts to data/alerts.json."""
    random.seed()
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    alerts = generate_alerts(50)
    Path("data/alerts.json").write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    print("Generated 50 safe simulated SOC alerts in data/alerts.json")


if __name__ == "__main__":
    main()
