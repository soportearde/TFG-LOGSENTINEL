from datetime import datetime, timezone


_RESTRICTED_RESOURCES = [
    {"path": "/etc/shadow", "allowed_users": ["root"]},
    {"path": "/var/www/app/config", "allowed_users": ["www-data", "root"]},
    {"path": "/home/datos-secretos", "allowed_users": ["miguel", "root"]},
]


def run(event):
    event_type = event.get("event_type", "")
    if event_type not in ("permission_denied", "unauthorized_access", "sudo_command"):
        return None

    username = event.get("username", "").rstrip(",").strip()
    if not username:
        return None

    # FileGuardian (auditd): la ruta está en metadata
    metadata = event.get("metadata") or {}
    accessed_path = metadata.get("accessed_path") or metadata.get("restricted_path") or ""

    # Auth.log/syslog: la ruta está en el mensaje
    message  = event.get("message", "")
    raw_line = event.get("raw_line", "")
    text     = f"{accessed_path} {message} {raw_line}"

    for resource in _RESTRICTED_RESOURCES:
        path          = resource["path"]
        allowed_users = resource["allowed_users"]

        if path not in text:
            continue

        if username in allowed_users:
            continue

        severity = 4 if path == "/etc/shadow" else 3

        return {
            "rule_name":       "acceso_restringido_servidor",
            "severity_id":     severity,
            "source_ip":       event.get("source_ip"),
            "username":        username,
            "title":           "Acceso no autorizado a recurso restringido",
            "message": (
                f"El usuario '{username}' intentó acceder al recurso restringido "
                f"'{path}'. Usuarios permitidos: {', '.join(allowed_users)}. "
                f"Servidor: {event.get('hostname', 'desconocido')}."
            ),
            "metadata":        event,
            "event_timestamp": datetime.now(timezone.utc),
        }

    return None