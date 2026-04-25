from datetime import datetime, timezone

BAD_ASNS = {"AS12345", "AS99999"}

def run(event):
    now = datetime.now(timezone.utc)

    asn = event.get("asn")  # debe venir ya enriquecido
    if not asn:
        return None

    if asn not in BAD_ASNS:
        return None

    return {
        "rule_name": "asn_block_rule",
        "severity_id": 3,
        "source_ip": event.get("source_ip"),
        "username": event.get("username"),
        "source_system": event.get("source_system", "LogSentinel"),
        "title": "Bloqueo por ASN malicioso",
        "message": f"ASN detectado: {asn}",
        "metadata": {
            "asn": asn,
            "source_ip": event.get("source_ip")
        },
        "event_timestamp": now
    }
