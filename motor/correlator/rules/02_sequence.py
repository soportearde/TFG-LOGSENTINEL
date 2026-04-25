from datetime import datetime, timezone

last_failed = {}
MAX_AGE = 3600  # segundos

def run(event):
    ip = event.get("source_ip")
    etype = event.get("event_type")
    now = datetime.now(timezone.utc)

    if etype == "login_failed":
        last_failed[ip] = now
        # limpieza ligera
        for k, t in list(last_failed.items()):
            if (now - t).total_seconds() > MAX_AGE:
                del last_failed[k]
        return None

    if etype == "login_success" and ip in last_failed:
        if (now - last_failed[ip]).total_seconds() <= 60:
            return {
                "rule_name": "login_sequence",
                "severity_id": 2,
                "source_ip": ip,
                "username": event.get("username"),
                "title": "Secuencia sospechosa de login",
                "message": "Fallos seguidos de exito en menos de 60s",
                "metadata": event,
                "event_timestamp": now
            }

    return None
