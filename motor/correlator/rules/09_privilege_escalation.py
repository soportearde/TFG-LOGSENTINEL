from datetime import datetime, timezone

PRIVILEGED_GROUPS = {
    "sudo", "admin", "wheel", "root",
    "administrators", "domain admins", "schema admins", "enterprise admins",
}


def run(event):
    now = datetime.now(timezone.utc)
    event_type = (event.get("event_type") or "").lower()

    # Comandos sudo detectados por el normalizador
    if event_type == "sudo_command":
        return {
            "rule_name": "privilege_escalation",
            "severity_id": 3,
            "source_ip": event.get("source_ip"),
            "username": event.get("username"),
            "title": "Comando sudo ejecutado",
            "message": f"Escalada de privilegios via sudo: {event.get('message', '')}",
            "metadata": event,
            "event_timestamp": now,
        }

    # Adición a grupo privilegiado (Active Directory / syslog)
    if "group_member_added" in event_type:
        resource = (event.get("resource") or "").lower()
        message  = (event.get("message")  or "").lower()
        combined = f"{resource} {message}"
        if any(grp in combined for grp in PRIVILEGED_GROUPS):
            return {
                "rule_name": "privilege_escalation",
                "severity_id": 3,
                "source_ip": event.get("source_ip"),
                "username": event.get("username"),
                "title": "Miembro añadido a grupo privilegiado",
                "message": (
                    f"Usuario '{event.get('username')}' añadido a grupo privilegiado: "
                    f"{event.get('resource', '')}"
                ),
                "metadata": event,
                "event_timestamp": now,
            }

    return None
