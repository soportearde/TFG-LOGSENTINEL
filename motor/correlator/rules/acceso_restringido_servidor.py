from datetime import datetime, timezone


_RESTRICTED_RESOURCES = [
    {"path": "/etc/shadow", "allowed_users": ["root"]},
    {"path": "/var/www/app/config", "allowed_users": ["www-data", "root"]},
    {"path": "/home/datos-secretos", "allowed_users": ["admin", "root"]},
]


def run(event):
    if event.get("event_type") != "permission_denied" and event.get("event_type") != "sudo_command":
        return None

    username = event.get("username", "").rstrip(",").strip()
    if not username:
        return None

    message = event.get("message", "")
    raw_line = event.get("raw_line", "")

    combined_text = f"{message} {raw_line}"

    for resource in _RESTRICTED_RESOURCES:
        path = resource["path"]
        allowed_users = resource["allowed_users"]

        if path in combined_text:
            if username not in allowed_users:
                severity = 4 if path == "/etc/shadow" else 3

                return {
                    "rule_name": "acceso_restringido_servidor",
                    "severity_id": severity,
                    "source_ip": event.get("source_ip"),
                    "username": username,
                    "title": "Acceso no autorizado a recurso restringido",
                    "message": (
                        f"El usuario '{username}' ha intentado acceder al recurso "
                        f"restringido '{path}' sin estar en la lista de usuarios "
                        f"permitidos ({', '.join(allowed_users)}). "
                        f"Servidor: {event.get('hostname', 'desconocido')}."
                    ),
                    "metadata": event,
                    "event_timestamp": datetime.now(timezone.utc),
                }

    return None