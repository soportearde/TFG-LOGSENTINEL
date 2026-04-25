from datetime import datetime, timezone


def run(event, state):
    if event.get("event_type") != "permission_denied":
        return None

    if event.get("status_code") != 403:
        return None

    path = event.get("resource") or event.get("path") or ""
    if "/panel/admin" not in path:
        return None

    now       = datetime.now(timezone.utc)
    source_ip = event.get("source_ip")

    return {
        "rule_name":       "restricted_area_access",
        "severity_id":     2,
        "source_ip":       source_ip,
        "username":        event.get("username"),
        "source_system":   event.get("source_system", "LogSentinel"),
        "title":           "Intento de acceso a zona restringida",
        "message":         f"Intento de acceso no autorizado a {path} desde la IP {source_ip}",
        "metadata":        event,
        "event_timestamp": now,
    }
