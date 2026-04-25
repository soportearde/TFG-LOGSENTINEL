from datetime import datetime, timezone


def run(event, state):
    event_type = (event.get("event_type") or "").lower()

    # Solo procesar eventos del FileGuardian
    if event.get("source_system") != "file_guardian":
        return None

    if event_type not in ("permission_denied", "unauthorized_access"):
        return None

    user     = event.get("username") or "unknown"
    metadata = event.get("metadata") or {}
    path     = metadata.get("accessed_path") or event.get("resource") or event.get("path") or "desconocida"
    source_ip = event.get("source_ip") or "127.0.0.1"
    allowed  = metadata.get("allowed_users") or []
    command  = metadata.get("command") or metadata.get("executable") or "desconocido"
    denied   = metadata.get("denied_by_os", False)
    unauth   = metadata.get("unauthorized", False)

    if denied:
        title = f"Acceso denegado a archivo restringido: {path}"
        msg   = (
            f"El sistema denegó el acceso de '{user}' a '{path}'. "
            f"Comando: '{command}'. "
            f"Usuarios permitidos: {allowed or 'sin restricción explícita'}"
        )
        severity = 3
    else:
        title = f"Acceso no autorizado a archivo restringido: {path}"
        msg   = (
            f"El usuario '{user}' accedió a '{path}' sin estar en la lista de permitidos. "
            f"Comando: '{command}'. "
            f"Usuarios permitidos: {allowed}"
        )
        severity = 4

    return {
        "rule_name":       "file_access_denied",
        "severity_id":     severity,
        "source_ip":       source_ip,
        "username":        user,
        "source_system":   "file_guardian",
        "title":           title,
        "message":         msg,
        "metadata":        metadata,
        "event_timestamp": datetime.now(timezone.utc),
    }
