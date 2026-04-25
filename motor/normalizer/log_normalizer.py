#!/usr/bin/env python3
from datetime import datetime, timezone
from flask import Flask, request, jsonify
import requests
import json
import logging
import sys

# ---------------------------------------------------------
# LOGGING
# ---------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("normalizer")

app = Flask(__name__)

CORRELATOR_URL    = "http://correlator:7000/event"
CORRELATOR_TIMEOUT = 5   # segundos


# ─────────────────────────────────────────────────────────────────────────────
# DETECCIÓN DEL TIPO DE FUENTE
# ─────────────────────────────────────────────────────────────────────────────

_SOURCE_KEYWORDS = {
    "web_server":        ["nginx", "apache", "iis", "haproxy", "caddy", "http", "web"],
    "active_directory":  ["active_directory", "activedirectory", "ldap", "ad",
                          "windows_security", "windows", "kerberos", "ntlm",
                          "dc", "domain_controller"],
    "erp":               ["erp", "sap", "odoo", "oracle_erp", "dynamics",
                          "netsuite", "sage"],
    "ssh":               ["ssh", "openssh", "sftp", "sshd"],
    "firewall":          ["firewall", "pfsense", "fortinet", "iptables",
                          "cisco_asa", "checkpoint", "palo_alto", "ufw"],
    "database":          ["mysql", "postgresql", "mssql", "oracle_db",
                          "mongodb", "database", "db"],
}

def detect_source_type(payload: dict) -> str:
    source_system = (payload.get("source_system") or "").lower()
    event_type    = (payload.get("event_type")    or "").lower()
    combined      = source_system + " " + event_type

    for source_type, keywords in _SOURCE_KEYWORDS.items():
        if any(kw in combined for kw in keywords):
            return source_type

    if "method" in payload and "path" in payload:
        return "web_server"
    if "event_id" in payload or "logon_type" in payload:
        return "active_directory"
    if "src_port" in payload or "dst_port" in payload:
        return "firewall"
    if "command" in payload or "auth_method" in payload:
        return "ssh"
    if "module" in payload or "transaction" in payload:
        return "erp"
    if "query_type" in payload or "db_user" in payload:
        return "database"

    return "generic"


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

_SEVERITY_ORDER = ["low", "medium", "high", "critical"]

def _max_severity(*levels):
    ranked = [l for l in levels if l in _SEVERITY_ORDER]
    return max(ranked, key=lambda x: _SEVERITY_ORDER.index(x), default="low")

def _infer_severity_http(status_code, event_type=""):
    event_type = (event_type or "").lower()
    if any(w in event_type for w in ("attack", "brute", "exploit", "injection")):
        return "critical"
    if status_code is None:
        return "low"
    if status_code >= 500:
        return "high"
    if status_code in (401, 403):
        return "medium"
    if status_code >= 400:
        return "low"
    return "low"

def _service_from_source(source_system: str, default: str) -> str:
    """Infiere el nombre del servicio desde source_system."""
    s = (source_system or "").lower()
    for svc in ("nginx", "apache", "iis", "haproxy", "caddy",
                "mysql", "postgresql", "mssql", "mongodb",
                "sshd", "openssh", "kerberos", "ldap",
                "pfsense", "fortinet", "iptables", "cisco_asa",
                "sap", "odoo", "oracle"):
        if svc in s:
            return svc
    return default


# ─────────────────────────────────────────────────────────────────────────────
# NORMALIZADORES POR TIPO DE FUENTE
# Todos devuelven los campos del esquema del correlator:
#   hostname, service, username, message
#   + campos extendidos propios del tipo de fuente
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_web_server(payload: dict) -> dict:
    raw_code = payload.get("status") or payload.get("status_code") or payload.get("http_status")
    try:
        status_code = int(raw_code)
    except (TypeError, ValueError):
        status_code = None

    if status_code is None:
        status = payload.get("status") or "unknown"
    elif status_code < 400:
        status = "success"
    elif status_code < 500:
        status = "failure"
    else:
        status = "error"

    method   = (payload.get("method") or "").upper() or None
    resource = payload.get("path") or payload.get("url") or payload.get("request_uri") or "/"
    username = payload.get("username") or payload.get("remote_user")

    return {
        "source_type":    "web_server",
        "hostname":       (payload.get("hostname") or
                           payload.get("destination_ip") or
                           payload.get("server_ip")),
        "service":        _service_from_source(payload.get("source_system"), "http"),
        "action":         method or "request",
        "resource":       resource,
        "method":         method,
        "status":         status,
        "status_code":    status_code,
        "username":       username,
        "user_agent":     payload.get("user_agent") or payload.get("http_user_agent"),
        "destination_ip": payload.get("destination_ip") or payload.get("server_ip"),
        "message":        f"{method or 'REQUEST'} {resource} → {status_code or status}",
        "severity":       _infer_severity_http(status_code, payload.get("event_type")),
    }


_AD_EVENT_IDS = {
    4624: ("login",                       "success"),
    4625: ("login",                       "failure"),
    4634: ("logout",                      "success"),
    4647: ("logout",                      "success"),
    4648: ("login_explicit_credentials",  "success"),
    4720: ("account_created",             "success"),
    4722: ("account_enabled",             "success"),
    4723: ("password_change",             "success"),
    4724: ("password_reset",              "success"),
    4725: ("account_disabled",            "success"),
    4726: ("account_deleted",             "success"),
    4728: ("group_member_added",          "success"),
    4732: ("local_group_member_added",    "success"),
    4740: ("account_locked",              "failure"),
    4756: ("universal_group_member_added","success"),
    4768: ("kerberos_tgt_request",        "success"),
    4769: ("kerberos_service_ticket",     "success"),
    4771: ("kerberos_pre_auth_failed",    "failure"),
    4776: ("ntlm_auth",                   "success"),
}

_AD_KERBEROS_IDS = {4768, 4769, 4771}

def _normalize_active_directory(payload: dict) -> dict:
    event_id = payload.get("event_id")
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        event_id = None

    action = payload.get("action") or payload.get("event_type") or "ad_event"
    status = payload.get("status") or "unknown"

    if event_id and event_id in _AD_EVENT_IDS:
        action, status = _AD_EVENT_IDS[event_id]

    severity = "low"
    if status == "failure":
        severity = "medium"
    if "lock" in action or "delete" in action or "escalat" in action:
        severity = "high"

    username = (payload.get("subject_user") or payload.get("username") or
                payload.get("account_name"))

    if event_id in _AD_KERBEROS_IDS:
        service = "kerberos"
    elif event_id in (4776,):
        service = "ntlm"
    else:
        service = _service_from_source(payload.get("source_system"), "ad")

    return {
        "source_type":    "active_directory",
        "hostname":       (payload.get("computer") or
                           payload.get("workstation_name") or
                           payload.get("hostname")),
        "service":        service,
        "action":         action,
        "resource":       (payload.get("target_user") or payload.get("resource") or
                           payload.get("computer")),
        "method":         f"EventID:{event_id}" if event_id else payload.get("logon_type"),
        "status":         status,
        "status_code":    event_id,
        "username":       username,
        "user_agent":     None,
        "destination_ip": payload.get("workstation_ip") or payload.get("destination_ip"),
        "message":        payload.get("message") or f"AD: {action} ({status})",
        "severity":       severity,
    }


_ERP_SENSITIVE_OPS = {"delete", "export", "permission", "admin", "config",
                      "payroll", "invoice", "grant", "revoke", "purge"}

def _normalize_erp(payload: dict) -> dict:
    action   = (payload.get("action")      or payload.get("operation") or
                payload.get("transaction") or payload.get("event_type") or "operation")
    resource = (payload.get("module")  or payload.get("object") or
                payload.get("resource") or payload.get("table") or "unknown")
    status   = payload.get("status") or ("success" if payload.get("success") else "unknown")

    severity = "low"
    if any(op in action.lower() for op in _ERP_SENSITIVE_OPS):
        severity = "high"
    elif status in ("failure", "error"):
        severity = "medium"

    return {
        "source_type":    "erp",
        "hostname":       (payload.get("hostname") or
                           payload.get("server_ip") or
                           payload.get("destination_ip")),
        "service":        _service_from_source(payload.get("source_system"), "erp"),
        "action":         action,
        "resource":       resource,
        "method":         payload.get("method") or payload.get("http_method"),
        "status":         status,
        "status_code":    payload.get("status_code") or payload.get("error_code"),
        "username":       (payload.get("username") or payload.get("user_id") or
                           payload.get("operator")),
        "user_agent":     payload.get("client") or payload.get("user_agent"),
        "destination_ip": payload.get("server_ip") or payload.get("destination_ip"),
        "message":        (payload.get("description") or payload.get("message") or
                           f"ERP {action} on {resource}"),
        "severity":       severity,
    }


_SSH_ACTION_MAP = {
    "user_created":  ("account_created", "success"),
    "accepted":      ("login",           "success"),
    "failed":        ("login",           "failure"),
    "invalid":       ("login",           "failure"),
    "disconnected":  ("logout",          "success"),
    "closed":        ("logout",          "success"),
    "error":         ("session",         "error"),
    "connection":    ("connection",      "success"),
    "opened":        ("session",         "success"),
}

def _normalize_ssh(payload: dict) -> dict:
    event_type = (payload.get("event_type") or "").lower()
    action, status = "ssh_event", "unknown"

    for keyword, (a, s) in _SSH_ACTION_MAP.items():
        if keyword in event_type:
            action, status = a, s
            break

    if payload.get("action"):
        action = payload["action"]
    if payload.get("status"):
        status = payload["status"]

    severity = "low"
    if status == "failure":
        severity = "medium"
    if "invalid user" in (payload.get("message") or "").lower():
        severity = "high"

    return {
        "source_type":    "ssh",
        "hostname":       (payload.get("hostname") or
                           payload.get("server_ip") or
                           payload.get("destination_ip")),
        "service":        "sshd",
        "action":         action,
        "resource":       payload.get("command") or payload.get("resource") or "shell",
        "method":         payload.get("auth_method") or payload.get("method") or "password",
        "status":         status,
        "status_code":    payload.get("exit_code") or payload.get("status_code"),
        "username":       payload.get("username"),
        "user_agent":     payload.get("client_version") or payload.get("ssh_client"),
        "destination_ip": payload.get("server_ip") or payload.get("destination_ip"),
        "message":        payload.get("message") or f"SSH {action} ({status})",
        "severity":       severity,
    }


_FW_BLOCK_ACTIONS  = {"drop", "deny", "block", "reject"}
_FW_SENSITIVE_PORTS = {22, 23, 3389, 445, 1433, 3306, 5432, 6379, 27017}

def _normalize_firewall(payload: dict) -> dict:
    action   = (payload.get("action") or payload.get("disposition") or
                payload.get("event_type") or "packet").lower()
    status   = "failure" if action in _FW_BLOCK_ACTIONS else "success"

    dst_port = payload.get("dst_port")  or payload.get("destination_port") or payload.get("port")
    proto    = (payload.get("protocol") or payload.get("proto") or "")

    try:
        dst_port_int = int(dst_port)
    except (TypeError, ValueError):
        dst_port_int = None

    resource = f"{proto}/{dst_port}" if dst_port else payload.get("resource") or "network"

    severity = "low"
    if action in _FW_BLOCK_ACTIONS:
        severity = "medium"
    if dst_port_int in _FW_SENSITIVE_PORTS:
        severity = _max_severity(severity, "high")

    dst_ip = payload.get("destination_ip") or payload.get("dst_ip")
    src_ip = payload.get("source_ip")

    return {
        "source_type":    "firewall",
        "hostname":       (payload.get("hostname") or dst_ip),
        "service":        _service_from_source(payload.get("source_system"), "firewall"),
        "action":         action,
        "resource":       resource,
        "method":         proto.upper() if proto else None,
        "status":         status,
        "status_code":    payload.get("rule_id") or payload.get("policy_id"),
        "username":       payload.get("username"),
        "user_agent":     None,
        "destination_ip": dst_ip,
        "message":        (payload.get("message") or
                           f"Firewall {action}: {src_ip} → {dst_ip}:{dst_port}"),
        "severity":       severity,
    }


_DB_SENSITIVE_OPS = {"DROP", "DELETE", "TRUNCATE", "UPDATE", "ALTER",
                     "GRANT", "REVOKE", "CREATE", "EXEC", "EXECUTE"}

def _normalize_database(payload: dict) -> dict:
    raw_action = (payload.get("action")     or payload.get("query_type") or
                  payload.get("operation")  or payload.get("event_type") or "query")
    action = raw_action.upper()
    # Extract first word so "DELETE FROM table" correctly matches "DELETE"
    action_word = action.split()[0] if action else ""

    resource = (payload.get("database")   or payload.get("table") or
                payload.get("resource")   or "unknown")
    status   = payload.get("status") or ("failure" if payload.get("error") else "success")

    severity = "high" if action_word in _DB_SENSITIVE_OPS else "low"
    if status in ("failure", "error"):
        severity = _max_severity(severity, "medium")

    return {
        "source_type":    "database",
        "hostname":       (payload.get("hostname") or
                           payload.get("db_host") or
                           payload.get("destination_ip")),
        "service":        _service_from_source(payload.get("source_system"), "database"),
        "action":         action,
        "resource":       resource,
        "method":         action,
        "status":         status,
        "status_code":    payload.get("error_code") or payload.get("status_code"),
        "username":       (payload.get("db_user")  or payload.get("username")),
        "user_agent":     payload.get("client_host") or payload.get("application"),
        "destination_ip": payload.get("db_host") or payload.get("destination_ip"),
        "message":        (payload.get("message") or payload.get("query") or
                           f"DB {action} on {resource}"),
        "severity":       severity,
    }


def _normalize_generic(payload: dict) -> dict:
    status = payload.get("status") or "unknown"
    if isinstance(status, int):
        status = "success" if status < 400 else "failure"

    raw_code = payload.get("status_code")
    try:
        raw_code = int(raw_code)
    except (TypeError, ValueError):
        raw_code = None

    return {
        "source_type":    "generic",
        "hostname":       payload.get("hostname"),
        "service":        (payload.get("service") or
                           _service_from_source(payload.get("source_system"), "unknown")),
        "action":         payload.get("action") or payload.get("event_type") or "event",
        "resource":       (payload.get("resource") or payload.get("path") or
                           payload.get("object")),
        "method":         payload.get("method"),
        "status":         status,
        "status_code":    raw_code,
        "username":       payload.get("username"),
        "user_agent":     payload.get("user_agent"),
        "destination_ip": payload.get("destination_ip"),
        "message":        payload.get("message") or payload.get("description") or "Generic event",
        "severity":       _infer_severity_http(raw_code, payload.get("event_type")),
    }


# ─────────────────────────────────────────────────────────────────────────────
# DISPATCH TABLE
# ─────────────────────────────────────────────────────────────────────────────

_NORMALIZERS = {
    "web_server":       _normalize_web_server,
    "active_directory": _normalize_active_directory,
    "erp":              _normalize_erp,
    "ssh":              _normalize_ssh,
    "firewall":         _normalize_firewall,
    "database":         _normalize_database,
    "generic":          _normalize_generic,
}


# ─────────────────────────────────────────────────────────────────────────────
# DERIVACIÓN DEL EVENT_TYPE CANÓNICO
# Mapea (action, status, source_type) a los tipos que el correlator conoce,
# con fallback a action_failed / action_success para tipos desconocidos.
# ─────────────────────────────────────────────────────────────────────────────

# Mapeo directo (action, status) → event_type canónico del correlator
_ACTION_STATUS_TO_EVENT_TYPE: dict[tuple[str, str], str] = {
    ("login",                       "success"): "login_success",
    ("login_explicit_credentials",  "success"): "login_success",
    ("kerberos_tgt_request",        "success"): "login_success",
    ("kerberos_service_ticket",     "success"): "login_success",
    ("ntlm_auth",                   "success"): "login_success",
    ("login",                       "failure"): "login_failed",
    ("login_explicit_credentials",  "failure"): "login_failed",
    ("kerberos_pre_auth_failed",    "failure"): "login_failed",
    ("account_locked",              "failure"): "login_failed",
    ("ntlm_auth",                   "failure"): "login_failed",
    ("account_created",             "success"): "user_created",
    ("account_created",             "failure"): "user_created",
}

def _derive_event_type(action: str, status: str, source_type: str = "") -> str:
    action_l  = (action or "").lower()
    status_l  = (status or "").lower()

    # 1. Tabla de mapeo directo
    mapped = _ACTION_STATUS_TO_EVENT_TYPE.get((action_l, status_l))
    if mapped:
        return mapped

    # 2. Sudo / escalada de privilegios
    if "sudo" in action_l or "escalat" in action_l:
        return "sudo_command"

    # 3. Permiso denegado: bloqueos de firewall o acciones con "denied"/"forbidden"
    if source_type == "firewall" and status_l in ("failure", "error"):
        return "permission_denied"
    if any(w in action_l for w in ("permission_denied", "denied", "forbidden", "access_denied")):
        return "permission_denied"

    # 4. Fallback genérico
    if status_l in ("failure", "error", "failed"):
        return f"{action_l}_failed" if action_l else "event_failed"
    if status_l == "success":
        return f"{action_l}_success" if action_l else "event_success"

    return action_l or "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# FUNCIÓN PRINCIPAL DE NORMALIZACIÓN
# ─────────────────────────────────────────────────────────────────────────────

def normalize(payload: dict) -> dict:
    """
    Detecta la fuente del payload, aplica el normalizador correspondiente y
    devuelve un evento con el esquema completo esperado por el correlator:

      event_type, source_system, username, source_ip,
      hostname, service, message, raw_line,
      agent_system_name, agent_timestamp
    """
    source_type   = detect_source_type(payload)
    normalizer_fn = _NORMALIZERS.get(source_type, _normalize_generic)
    type_specific = normalizer_fn(payload)

    # Si el payload original ya trae un event_type semántico (ej: desde el
    # plugin de WordPress), lo preservamos en lugar de derivarlo del método HTTP.
    _SEMANTIC_TYPES = {
        "login_failed", "login_success", "logout", "user_created",
        "user_deleted", "password_change", "role_change", "plugin_installed",
        "sudo_command", "permission_denied",
    }
    original_event_type = (payload.get("event_type") or "").lower()
    if original_event_type in _SEMANTIC_TYPES:
        event_type = original_event_type
    else:
        event_type = _derive_event_type(
            type_specific.get("action"),
            type_specific.get("status"),
            source_type,
        )

    # raw_line debe ser str (línea de log original); nunca el dict completo
    raw_line = payload.get("raw_line") or payload.get("raw")
    if isinstance(raw_line, dict):
        raw_line = json.dumps(raw_line)
    elif not isinstance(raw_line, str):
        raw_line = json.dumps(payload)

    return {
        # ── Esquema canónico del correlator ───────────────────────────────
        "event_type":        event_type,
        "source_system":     payload.get("source_system") or source_type,
        "username":          type_specific.get("username"),
        "source_ip":         payload.get("source_ip"),
        "hostname":          type_specific.get("hostname"),
        "service":           type_specific.get("service"),
        "message":           type_specific.get("message"),
        "raw_line":          raw_line,
        "agent_system_name": (payload.get("agent_system_name") or
                              payload.get("source_system") or
                              source_type),
        "agent_timestamp":   (payload.get("agent_timestamp") or
                              payload.get("timestamp") or
                              datetime.now(timezone.utc).isoformat()),
        # ── Campos extendidos / enriquecimiento ───────────────────────────
        "source_type":       source_type,
        "action":            type_specific.get("action"),
        "resource":          type_specific.get("resource"),
        "method":            type_specific.get("method"),
        "status":            type_specific.get("status"),
        "status_code":       type_specific.get("status_code"),
        "destination_ip":    type_specific.get("destination_ip"),
        "user_agent":        type_specific.get("user_agent"),
        "severity":          type_specific.get("severity", "low"),
        "country":           payload.get("country"),
        "asn":               payload.get("asn"),
        "city":              payload.get("city"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINT
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/normalize")
def normalize_log():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "JSON inválido o Content-Type incorrecto"}), 400

    try:
        normalized = normalize(payload)
    except Exception as e:
        log.exception("Error normalizando payload: %s", e)
        return jsonify({"status": "error", "message": f"Error de normalización: {e}"}), 500

    corr_status: int | str = "not_sent"
    corr_resp   = ""
    try:
        r           = requests.post(CORRELATOR_URL, json=normalized, timeout=CORRELATOR_TIMEOUT)
        corr_status = r.status_code
        corr_resp   = r.text
    except requests.Timeout:
        corr_status = "timeout"
        corr_resp   = f"El correlator no respondió en {CORRELATOR_TIMEOUT}s"
        log.warning("Timeout enviando evento al correlator.")
    except Exception as e:
        corr_status = "error"
        corr_resp   = str(e)
        log.error("Error enviando evento al correlator: %s", e)

    return jsonify({
        "status":               "ok",
        "source_type_detected": normalized.get("source_type"),
        "normalized_event":     normalized,
        "sent_to_correlator": {
            "status":   corr_status,
            "response": corr_resp,
        },
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6000)
