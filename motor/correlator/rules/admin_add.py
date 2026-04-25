from datetime import datetime, timezone


def run(event):
    if event.get("event_type") != "user_created":
        return None

    username = event.get("username", "").rstrip(",").strip().lower()

    if not username:
        return None

    admin_keywords = ["admin", "administrator", "root", "superuser"]

    is_admin = any(keyword in username for keyword in admin_keywords)

    if not is_admin:
        return None

    return {
        "rule_name": "admin_add",
        "severity_id": 4,
        "source_ip": event.get("source_ip"),
        "username": username,
        "title": "Creación de usuario con privilegios de administrador detectada",
        "message": (
            f"Se ha creado el usuario '{username}' en el host "
            f"'{event.get('hostname', 'desconocido')}'. El nombre del usuario "
            f"sugiere privilegios de administrador, lo cual puede representar "
            f"un riesgo de seguridad si no fue autorizado."
        ),
        "metadata": event,
        "event_timestamp": datetime.now(timezone.utc),
    }