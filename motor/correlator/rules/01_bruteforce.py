from datetime import datetime, timezone

THRESHOLD = 5
WINDOW_SECONDS = 180
failed_logins = {}

def run(event):
    if event.get("event_type") != "login_failed":
        return None

    ip = event.get("source_ip")
    username = event.get("username")
    key = f"{ip}|{username}"
    now = datetime.now(timezone.utc)

    failed_logins.setdefault(key, [])
    failed_logins[key].append(now)

    failed_logins[key] = [
        t for t in failed_logins[key]
        if (now - t).total_seconds() <= WINDOW_SECONDS
    ]

    if len(failed_logins[key]) >= THRESHOLD:
        return {
            "rule_name": "failed_login_bruteforce",
            "severity_id": 3,
            "source_ip": ip,
            "username": event.get("username"),
            "title": "Intentos de fuerza bruta",
            "message": f"Mas de {THRESHOLD} fallos en {WINDOW_SECONDS} segundos",
            "metadata": event,
            "event_timestamp": now
        }

    return None
