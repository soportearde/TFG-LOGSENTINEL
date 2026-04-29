from datetime import datetime, timezone


def run(event):
    if event.get("event_type") != "user_created":
        return None

    username = event.get("username", "").rstrip(",").strip()
    hostname = event.get("hostname", "desconocido")

    if not username:
        return None

    return {
        "rule_name": "admin_server",
        "severity_id": 4,
        "source_ip": event.get("source_ip"),
        "username": username,
        "title": "Nuevo usuario creado en el sistema",
        "message": (
            f"Se ha detectado la creación del usuario '{username}' "
            f"en el host '{hostname}'. Esta acción requiere revisión inmediata "
            f"para verificar que fue autorizada."
        ),
        "metadata": event,
        "event_timestamp": datetime.now(timezone.utc),
    }