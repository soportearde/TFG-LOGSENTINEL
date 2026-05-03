from datetime import datetime, timezone


def run(event):
    if event.get("event_type") != "login_failed":
        return None

    username = (event.get("username") or "").rstrip(",").strip()
    source_ip = event.get("source_ip")

    if username != "demo":
        return None

    return {
        "rule_name": "kdlkas",
        "severity_id": 2,
        "source_ip": source_ip,
        "username": username,
        "title": "Fallo de autenticación SSH del usuario demo",
        "message": (
            f"El usuario 'demo' falló al autenticarse por SSH desde la IP {source_ip} "
            f"en el servidor {event.get('hostname', 'desconocido')}."
        ),
        "metadata": event,
        "event_timestamp": datetime.now(timezone.utc),
    }