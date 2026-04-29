from datetime import datetime, timezone


def run(event):
    if event.get("event_type") != "user_created":
        return None

    username = event.get("username", "").rstrip(",").strip().lower()

    if username != "admin":
        return None

    return {
        "rule_name": "usuario_admin",
        "severity_id": 4,
        "source_ip": event.get("source_ip"),
        "username": username,
        "title": "Creación de usuario admin detectada",
        "message": (
            f"Se ha creado un usuario con nombre 'admin' en el servidor "
            f"'{event.get('hostname', 'desconocido')}'. "
            f"Esta acción puede representar un riesgo de seguridad crítico."
        ),
        "metadata": event,
        "event_timestamp": datetime.now(timezone.utc),
    }