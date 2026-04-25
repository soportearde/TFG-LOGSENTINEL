from datetime import datetime, timezone

WINDOW = 10
THRESHOLD = 20
requests_ip = {}

def run(event):
    ip = event.get("source_ip")
    now = datetime.now(timezone.utc)

    requests_ip.setdefault(ip, [])
    requests_ip[ip].append(now)

    requests_ip[ip] = [
        t for t in requests_ip[ip]
        if (now - t).total_seconds() <= WINDOW
    ]

    if len(requests_ip[ip]) >= THRESHOLD:
        return {
            "rule_name": "dos_detection",
            "severity_id": 3,
            "source_ip": ip,
            "username": event.get("username"),
            "title": "Posible ataque DoS",
            "message": f"{len(requests_ip[ip])} peticiones en {WINDOW}s",
            "metadata": event,
            "event_timestamp": now
        }

    return None
