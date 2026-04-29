from datetime import datetime, timezone

PRIVILEGED_GROUPS = {
    "sudo", "admin", "wheel", "root", "adm",
    "administrators", "domain admins", "schema admins", "enterprise admins",
}


def run(event):
    now = datetime.now(timezone.utc)
    event_type = (event.get("event_type") or "").lower()

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

    if event_type == "user_added_to_group":
        group_name = (event.get("group_name") or "").lower()
        if event.get("privileged") or group_name in PRIVILEGED_GROUPS:
            user = event.get("username", "desconocido")
            return {
                "rule_name": "privilege_escalation",
                "severity_id": 4,
                "source_ip": event.get("source_ip"),
                "username": user,
                "title": f"Usuario anadido al grupo privilegiado '{group_name}'",
                "message": (
                    f"El usuario '{user}' ha sido anadido al grupo '{group_name}' en "
                    f"{event.get('hostname', 'desconocido')}. Esto le otorga privilegios administrativos."
                ),
                "metadata": event,
                "event_timestamp": now,
            }

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
                "title": "Miembro anadido a grupo privilegiado",
                "message": (
                    f"Usuario '{event.get('username')}' anadido a grupo privilegiado: "
                    f"{event.get('resource', '')}"
                ),
                "metadata": event,
                "event_timestamp": now,
            }

    return None
