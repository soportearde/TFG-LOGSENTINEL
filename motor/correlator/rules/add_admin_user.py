from datetime import datetime, timezone

_ADMIN_INDICATORS = [
    "sudo", "admin", "wheel", "root",
    "-g sudo", "-g admin", "-g wheel",
    "--groups sudo", "--groups admin",
    "usermod -ag", "gpasswd -a",
    "sudoers", "/etc/sudoers",
    "uid=0", "-o -u 0",
]


def run(event):
    event_type = (event.get("event_type") or "").lower()
    message    = (event.get("message")    or "").lower()
    raw_line   = (event.get("raw_line")   or "").lower()
    action     = (event.get("action")     or "").lower()
    resource   = (event.get("resource")   or "").lower()
    combined   = f"{event_type} {message} {raw_line} {action} {resource}"

    username  = event.get("username") or ""
    source_ip = event.get("source_ip") or ""

    # Detectar creación de usuario
    is_user_creation = event_type == "user_created" or any(
        cmd in combined
        for cmd in ["useradd", "adduser", "new user", "create_user", "user_add"]
    )
    if not is_user_creation:
        return None

    is_admin = any(ind in combined for ind in _ADMIN_INDICATORS)

    title       = "Usuario administrador creado en el sistema" if is_admin else "Nuevo usuario creado en el sistema"
    severity_id = 4 if is_admin else 3
    target_user = username or "unknown"
    msg = f"Se ha creado el usuario '{target_user}' en el sistema."
    if source_ip:
        msg += f" Desde {source_ip}"

    return {
        "rule_name":        "user_created",
        "severity_id":      severity_id,
        "source_ip":        source_ip,
        "username":         username,
        "title":            title,
        "message":          msg,
        "metadata":         event,
        "event_timestamp":  datetime.now(timezone.utc),
    }
