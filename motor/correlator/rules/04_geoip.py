from datetime import datetime, timezone

ALLOWED_COUNTRIES = {"ES", "FR", "PT"}

def run(event):
    now = datetime.now(timezone.utc)

    country = event.get("country")
    if not country:
        return None

    if country in ALLOWED_COUNTRIES:
        return None

    return {
        "rule_name": "geoip_restriction",
        "severity_id": 2,
        "source_ip": event.get("source_ip"),
        "username": event.get("username"),
        "source_system": event.get("source_system", "LogSentinel"),
        "title": "Acceso desde pais no permitido",
        "message": f"Acceso desde {country}",
        "metadata": {
            "country": country,
            "source_ip": event.get("source_ip")
        },
        "event_timestamp": now
    }
