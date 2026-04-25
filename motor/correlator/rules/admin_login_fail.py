from datetime import datetime, timezone
from collections import defaultdict

_history = defaultdict(list)


def _purge(lst, window_secs):
    now = datetime.now(timezone.utc).timestamp()
    lst[:] = [t for t in lst if now - t <= window_secs]


def run(event):
    if event.get("event_type") != "login_failed":
        return None

    username = (event.get("username") or "").rstrip(",").strip().lower()
    if username != "admin":
        return None

    message = (event.get("message") or "").lower()
    raw_line = (event.get("raw_line") or "").lower()
    service = (event.get("service") or "").lower()

    is_wordpress = False
    for text in (message, raw_line, service):
        if "wordpress" in text or "wp-login" in text or "wp-admin" in text:
            is_wordpress = True
            break

    if not is_wordpress:
        is_wordpress = True

    if not is_wordpress:
        return None

    source_ip = event.get("source_ip") or "unknown"
    key = f"admin_login_fail|{source_ip}"

    now = datetime.now(timezone.utc).timestamp()
    _history[key].append(now)
    _purge(_history[key], 300)

    if len(_history[key]) >= 3:
        _history[key] = []
        return {
            "rule_name": "admin_login_fail",
            "severity_id": 3,
            "source_ip": event.get("source_ip"),
            "username": "admin",
            "title": "Múltiples intentos fallidos de login con usuario admin",
            "message": (
                f"Se detectaron 3 o más intentos fallidos de acceso con el usuario 'admin' "
                f"desde la IP {source_ip} en los últimos 5 minutos. "
                f"Posible ataque de fuerza bruta contra WordPress."
            ),
            "metadata": event,
            "event_timestamp": datetime.now(timezone.utc),
        }

    return None