from datetime import datetime, timezone

TOR_IPS = {"185.220.101.1", "185.220.102.4"}

def run(event):
    ip = event.get("source_ip")
    now = datetime.now(timezone.utc)

    if ip in TOR_IPS:
        return {
            "rule_name": "tor_exit_node",
            "severity_id": 2,
            "source_ip": ip,
            "username": event.get("username"),
            "title": "Acceso desde nodo TOR",
            "message": f"Conexion detectada desde TOR: {ip}",
            "metadata": event,
            "event_timestamp": now
        }

    return None
