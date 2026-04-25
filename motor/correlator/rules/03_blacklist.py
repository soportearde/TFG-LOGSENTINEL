from datetime import datetime, timezone

BLACKLIST = {"201.33.50.10", "123.45.67.89"}

def run(event):
    ip = event.get("source_ip")
    now = datetime.now(timezone.utc)

    if ip in BLACKLIST:
        return {
            "rule_name": "blacklist_ip",
            "severity_id": 3,
            "source_ip": ip,
            "username": event.get("username"),
            "title": "IP en lista negra",
            "message": f"La IP {ip} esta marcada como maliciosa",
            "metadata": event,
            "event_timestamp": now
        }

    return None
