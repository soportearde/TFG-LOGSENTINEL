from datetime import datetime, timezone


def run(event):
    if event.get("event_type") != "user_created":
        return None

    username = event.get("username", "").rstrip(",").strip()

    if not username:
        return None

    message = event.get("message", "").lower()
    raw_line = event.get("raw_line", "").lower()

    admin_indicators = [
        "sudo",
        "wheel",
        "admin",
        "root",
        "gid=0",
        "group=sudo",
        "group=wheel",
        "group=admin",
        "group=root",
        "-g 0",
        "-G sudo",
        "-G wheel",
        "-G admin",
        "-G root",
        "groups=sudo",
        "groups=wheel",
        "groups=admin",
        "groups=root",
    ]

    combined_text = f"{message} {raw_line}"

    is_admin = False
    matched_indicator = ""

    for indicator in admin_indicators:
        if indicator in combined_text:
            is_admin = True
            matched_indicator = indicator
            break

    if not is_admin:
        return None

    hostname = event.get("hostname", "desconocido")

    return {
        "rule_name": "admin_server_created",
        "severity_id": 4,
        "source_ip": event.get("source_ip"),
        "username": username,
        "title": "Creación de usuario con privilegios de administrador",
        "message": (
            f"Se ha creado el usuario '{username}' con privilegios de administrador "
            f"en el servidor '{hostname}'. Indicador detectado: '{matched_indicator}'. "
            f"Verifique que esta acción fue autorizada."
        ),
        "metadata": event,
        "event_timestamp": datetime.now(timezone.utc),
    }