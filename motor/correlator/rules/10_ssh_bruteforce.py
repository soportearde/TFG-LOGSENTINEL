from datetime import datetime, timezone, timedelta

THRESHOLD = 3
WINDOW = timedelta(minutes=5)

# estado en memoria (global) por usuario+ip
_state = {}

def run(event):
    source_system = (event.get("source_system") or "").lower()
    if "ssh" not in source_system and "sshd" not in source_system:
        return None

    if event.get("event_type") != "login_failed":
        return None

    username = event.get("username")
    source_ip = event.get("source_ip")

    if not username or not source_ip:
        return None

    now = datetime.now(timezone.utc)
    key = f"{username}:{source_ip}"

    user_state = _state.setdefault(key, {
        "count": 0,
        "first_attempt": now
    })

    if now - user_state["first_attempt"] > WINDOW:
        user_state["count"] = 0
        user_state["first_attempt"] = now

    user_state["count"] += 1

    if user_state["count"] < THRESHOLD:
        return None

    _state.pop(key, None)

    return {
        "rule_name": "ssh_bruteforce_user",
        "severity_id": 4,
        "source_ip": source_ip,
        "username": username,
        "source_system": "ssh",
        "title": "Posible fuerza bruta SSH",
        "message": f"El usuario '{username}' ha fallado {THRESHOLD} intentos de login SSH",
        "metadata": {
            "attempts": THRESHOLD,
            "window_minutes": WINDOW.total_seconds() / 60
        },
        "event_timestamp": now
    }
