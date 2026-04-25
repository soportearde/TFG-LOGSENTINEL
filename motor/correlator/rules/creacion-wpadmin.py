from datetime import datetime, timezone


def run(event):
    raw_line = event.get("raw_line", "")
    if "new_admin_created" not in raw_line:
        return None

    username = event.get("username", "").rstrip(",").strip()

    if not username:
        return None

    return {
        "rule_name": "creacion-wpadmin",
        "severity_id": 4,
        "source_ip": event.get("source_ip"),
        "username": username,
        "title": "Creación de usuario administrador en WordPress detectada",
        "message": (
            f"Se ha detectado la creación del usuario '{username}' con privilegios de "
            f"administrador en WordPress en el host '{event.get('hostname', 'desconocido')}'. "
            f"Esto puede indicar una intrusión o compromiso del sitio web."
        ),
        "metadata": event,
        "event_timestamp": datetime.now(timezone.utc),
    }
