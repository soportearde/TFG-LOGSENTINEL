#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time
import re
import os
import pwd
import signal
import socket
import logging
import subprocess
from datetime import datetime, timezone
from collections import defaultdict
import requests

# -------------------------------------------------------------
# CONFIG
# -------------------------------------------------------------

LOGSENTINEL_URL    = os.getenv("LOGSENTINEL_URL", "http://localhost:5000/log")
API_KEY            = os.getenv("LOGSENTINEL_API_KEY")
SYSTEM_NAME        = os.getenv("LOGSENTINEL_SYSTEM_NAME", socket.gethostname())
SEND_INTERVAL      = int(os.getenv("LOGSENTINEL_INTERVAL", "5"))
RESTRICTED_PATHS   = []   # se carga desde agent.conf

STATE_FILE  = "/var/lib/logsentinel/agent_state.json"
BUFFER_FILE = "/var/lib/logsentinel/buffer.json"

LOG_SOURCES = [
    {"path": "/var/log/auth.log", "source_system": "ssh"},
    {"path": "/var/log/syslog",   "source_system": "linux_syslog"},
]

# -------------------------------------------------------------
# LOGGING
# -------------------------------------------------------------

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

session = requests.Session()

# -------------------------------------------------------------
# CONFIG FILE
# -------------------------------------------------------------

def load_config():
    path = "/etc/logsentinel/agent.conf"
    if not os.path.exists(path):
        return

    with open(path) as f:
        config = json.load(f)

    global LOGSENTINEL_URL, API_KEY, SYSTEM_NAME, SEND_INTERVAL, RESTRICTED_PATHS
    LOGSENTINEL_URL  = config.get("url",              LOGSENTINEL_URL)
    API_KEY          = config.get("api_key",          API_KEY)
    SYSTEM_NAME      = config.get("system_name",      SYSTEM_NAME)
    SEND_INTERVAL    = config.get("interval",         SEND_INTERVAL)
    RESTRICTED_PATHS = config.get("restricted_paths", [])

# -------------------------------------------------------------
# STATE + BUFFER
# -------------------------------------------------------------

def load_json(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}

def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f)

# -------------------------------------------------------------
# TIMESTAMP NORMALIZATION
# -------------------------------------------------------------

def normalize_timestamp(ts):
    try:
        if "T" in ts:
            return datetime.fromisoformat(ts).astimezone(timezone.utc).isoformat()
        else:
            dt = datetime.strptime(ts, "%b %d %H:%M:%S")
            dt = dt.replace(year=datetime.now().year)
            return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()

# -------------------------------------------------------------
# REGEX
# -------------------------------------------------------------

AUTH_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T[\d:.+-]+|\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.+)$"
)

SSH_FAILED_PATTERN     = re.compile(r"Failed password for (?:(invalid user) )?(\S+) from ([\d.]+)")
SSH_SUCCESS_PATTERN    = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)")
SUDO_PATTERN           = re.compile(r"sudo:\s+(\S+)\s+:.*COMMAND=(.+)")
USER_CREATE_PATTERN    = re.compile(r"new user:\s+name=([^,\s]+)|useradd\[.*\]:\s+new user.*name=([^,\s]+)")
GROUP_ADDITION_PATTERN = re.compile(r"add '(\S+)' to group '(\S+)'")
GROUP_GPASSWD_PATTERN  = re.compile(r"user (\S+) added by \S+ to group (\S+)")
PERM_DENIED_PATTERN    = re.compile(r"[Pp]ermission denied|DENIED|authentication failure")

# Grupos que confieren privilegios administrativos en Linux
PRIVILEGED_GROUPS = {"sudo", "admin", "wheel", "root", "adm"}

# Anti-ruido: agrega fallos de SSH para usuarios inválidos en bursts.
# Estructura: {(source_ip, hostname): {"count": N, "users": set, "first_ts": ts}}
_invalid_user_buckets = {}
INVALID_USER_FLUSH_SECS = 60   # cada 60s emitir un resumen y limpiar
INVALID_USER_MIN_COUNT  = 3    # con 3 o más intentos a usuarios inválidos -> "scan"

# -------------------------------------------------------------
# PARSERS
# -------------------------------------------------------------

def parse_auth_line(line, source_system):
    match = AUTH_PATTERN.match(line)
    if not match:
        return None

    ts, hostname, service, message = match.groups()

    event = {
        "timestamp":     normalize_timestamp(ts),
        "source_system": source_system,
        "hostname":      hostname,
        "service":       service,
        "message":       message,
        "raw_line":      line.strip(),
    }

    if (m := SSH_FAILED_PATTERN.search(message)):
        invalid_marker, username, source_ip = m.group(1), m.group(2), m.group(3)
        # Filtro anti-ruido: si es un usuario inválido (no existe en el sistema),
        # no emitimos un evento por intento. Lo agregamos en un "scan" resumen.
        if invalid_marker:
            key = (source_ip, event["hostname"])
            bucket = _invalid_user_buckets.setdefault(key, {
                "count": 0, "users": set(), "first_ts": time.time()
            })
            bucket["count"] += 1
            bucket["users"].add(username)
            return None  # no event individual; lo emite flush_invalid_user_buckets()
        event.update({"event_type": "login_failed", "username": username, "source_ip": source_ip})
        return event

    if (m := SSH_SUCCESS_PATTERN.search(message)):
        event.update({"event_type": "login_success", "username": m.group(1), "source_ip": m.group(2)})
        return event

    if (m := SUDO_PATTERN.search(message)):
        event.update({"event_type": "sudo_command", "username": m.group(1), "command": m.group(2).strip()})
        return event

    if (m := USER_CREATE_PATTERN.search(message)):
        event.update({"event_type": "user_created", "username": m.group(1) or m.group(2)})
        return event

    if (m := GROUP_ADDITION_PATTERN.search(message)):
        username, group_name = m.group(1), m.group(2)
        event.update({
            "event_type":  "user_added_to_group",
            "username":    username,
            "group_name":  group_name,
            "privileged":  group_name.lower() in PRIVILEGED_GROUPS,
        })
        return event

    if (m := GROUP_GPASSWD_PATTERN.search(message)):
        username, group_name = m.group(1), m.group(2)
        event.update({
            "event_type":  "user_added_to_group",
            "username":    username,
            "group_name":  group_name,
            "privileged":  group_name.lower() in PRIVILEGED_GROUPS,
        })
        return event

    if PERM_DENIED_PATTERN.search(message):
        event["event_type"] = "permission_denied"
        return event

    return None


def flush_invalid_user_buckets():
    """
    Emite un evento de tipo 'ssh_scan' por cada IP que ha intentado N o más logins
    a usuarios inválidos en la ventana actual. Se ejecuta cada SEND_INTERVAL.
    """
    now = time.time()
    out = []
    for key in list(_invalid_user_buckets.keys()):
        bucket = _invalid_user_buckets[key]
        elapsed = now - bucket["first_ts"]
        if elapsed >= INVALID_USER_FLUSH_SECS or bucket["count"] >= INVALID_USER_MIN_COUNT * 5:
            source_ip, hostname = key
            if bucket["count"] >= INVALID_USER_MIN_COUNT:
                out.append({
                    "timestamp":     datetime.now(timezone.utc).isoformat(),
                    "source_system": "ssh",
                    "hostname":      hostname,
                    "service":       "sshd",
                    "event_type":    "ssh_scan",
                    "source_ip":     source_ip,
                    "username":      None,
                    "message":       f"Escaneo SSH: {bucket['count']} intentos a usuarios inexistentes ({', '.join(sorted(bucket['users'])[:10])}) en {int(elapsed)}s",
                    "metadata": {
                        "attempt_count":   bucket["count"],
                        "tried_usernames": sorted(bucket["users"]),
                        "window_seconds":  int(elapsed),
                    },
                })
            del _invalid_user_buckets[key]
    return out


def parse_syslog_line(line, source_system):
    match = AUTH_PATTERN.match(line)
    if not match:
        return None

    ts, hostname, service, message = match.groups()

    event = {
        "timestamp":     normalize_timestamp(ts),
        "source_system": source_system,
        "hostname":      hostname,
        "service":       service,
        "message":       message,
        "raw_line":      line.strip(),
    }

    if (m := USER_CREATE_PATTERN.search(message)):
        event.update({"event_type": "user_created", "username": m.group(1) or m.group(2)})
        return event

    if PERM_DENIED_PATTERN.search(message):
        event["event_type"] = "permission_denied"
        return event

    return None


def parse_line(line, source_system):
    if source_system == "ssh":
        return parse_auth_line(line, source_system)
    if source_system == "linux_syslog":
        return parse_syslog_line(line, source_system)
    return None

# -------------------------------------------------------------
# READ LOGS
# -------------------------------------------------------------

def read_new_lines(filepath, state):
    if not os.path.exists(filepath):
        return []

    last_pos = state.get(filepath, 0)
    size     = os.path.getsize(filepath)

    if size < last_pos:
        last_pos = 0

    with open(filepath, "r", errors="replace") as f:
        f.seek(last_pos)
        lines = f.readlines()
        state[filepath] = f.tell()

    return lines

# -------------------------------------------------------------
# FILE GUARDIAN
# Usa auditd para detectar accesos a rutas restringidas.
#
# Configuración en /etc/logsentinel/agent.conf:
# {
#   ...
#   "restricted_paths": [
#     {
#       "path": "/etc/shadow",
#       "allowed_users": ["root"]
#     },
#     {
#       "path": "/var/www/app/config",
#       "allowed_users": ["www-data", "root"]
#     }
#   ]
# }
# -------------------------------------------------------------

AUDIT_LOG = "/var/log/audit/audit.log"
AUDIT_KEY = "ls_guard"


def _uid_to_name(uid_str):
    try:
        return pwd.getpwuid(int(uid_str)).pw_name
    except Exception:
        return uid_str


def _extract(text, pattern):
    m = re.search(pattern, text)
    return m.group(1) if m else None


def setup_audit_rules(restricted_paths):
    """
    Registra reglas en auditd para cada ruta restringida.
    Monitoriza lectura (r), escritura (w) y cambios de atributos (a).
    """
    if not os.path.exists("/sbin/auditctl"):
        logging.warning("[FileGuardian] auditd no encontrado — instala: apt-get install -y auditd")
        return

    # Eliminar reglas previas de esta clave para no duplicar en reinicios
    subprocess.run(["auditctl", "-D", "-k", AUDIT_KEY], capture_output=True)

    for entry in restricted_paths:
        path = entry.get("path", "").strip()
        if not path:
            continue
        result = subprocess.run(
            ["auditctl", "-w", path, "-p", "rwa", "-k", AUDIT_KEY],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            logging.info(f"[FileGuardian] Vigilando: {path}  (permitidos: {entry.get('allowed_users', 'todos')})")
        else:
            logging.warning(f"[FileGuardian] No se pudo vigilar {path}: {result.stderr.strip()}")


def read_audit_events(state, restricted_paths):
    """
    Lee nuevas líneas del log de auditd y devuelve eventos de acceso
    denegado o de usuario no autorizado sobre rutas restringidas.
    """
    if not restricted_paths or not os.path.exists(AUDIT_LOG):
        return []

    # Mapa normalizado: ruta -> config
    path_map = {}
    for entry in restricted_paths:
        p = os.path.normpath(entry.get("path", "").strip())
        if p and p != ".":
            path_map[p] = entry

    lines = read_new_lines(AUDIT_LOG, state)
    if not lines:
        return []

    # Paso 1: agrupar TODAS las líneas por serial.
    # Cada evento auditd tiene varias líneas con el mismo serial
    # (SYSCALL, PATH, CWD, PROCTITLE...) pero solo SYSCALL lleva ls_guard.
    all_by_serial = defaultdict(list)
    for line in lines:
        m = re.search(r"msg=audit\([\d.]+:(\d+)\)", line)
        if m:
            all_by_serial[m.group(1)].append(line.strip())

    # Paso 2: procesar solo los seriales que tienen nuestra clave de auditoría
    events = []
    for serial, event_lines in all_by_serial.items():
        if not any(AUDIT_KEY in l for l in event_lines):
            continue
        event = _parse_audit_record(event_lines, path_map)
        if event:
            events.append(event)

    return events


def _parse_audit_record(lines, path_map):
    """
    Parsea un grupo de líneas auditd con el mismo serial y genera
    un evento si el acceso fue denegado o el usuario no está autorizado.
    """
    syscall_line = next((l for l in lines if "type=SYSCALL" in l), None)
    path_line    = next((l for l in lines if "type=PATH"    in l), None)

    if not syscall_line:
        return None

    # Campos del SYSCALL
    uid      = _extract(syscall_line, r"\buid=(\d+)")
    auid     = _extract(syscall_line, r"\bauid=(\d+)")
    success  = _extract(syscall_line, r"\bsuccess=(\w+)")
    exit_val = _extract(syscall_line, r"\bexit=(-?\d+)")
    comm     = _extract(syscall_line, r'\bcomm="([^"]+)"')
    exe      = _extract(syscall_line, r'\bexe="([^"]+)"')
    pid      = _extract(syscall_line, r"\bpid=(\d+)")

    # uid = usuario que ejecutó realmente el syscall (puede ser un su/sudo).
    # auid = usuario que inició sesión.
    # Para FileGuardian preferimos uid: nos interesa quién *intentó* el acceso,
    # no quién abrió originalmente la sesión. 4294967295 = no asignado (kernel).
    effective_uid = uid if (uid and uid not in ("4294967295", "")) else auid
    username      = _uid_to_name(effective_uid) if effective_uid else "unknown"

    # Ruta accedida
    if not path_line:
        return None
    accessed_path = _extract(path_line, r'\bname="([^"]+)"')
    if not accessed_path:
        return None
    accessed_path = os.path.normpath(accessed_path)

    # Buscar qué regla aplica
    matching = None
    for restricted_path, config in path_map.items():
        if accessed_path == restricted_path or accessed_path.startswith(restricted_path + "/"):
            matching = config
            break

    if not matching:
        return None

    allowed_users = [u.strip() for u in matching.get("allowed_users", [])]

    # exit=-13 es EACCES (permiso denegado por el kernel)
    is_denied = (success == "no" and exit_val == "-13")
    is_unauth = bool(allowed_users and username not in allowed_users)

    # Sin alerta si el acceso fue legítimo y el usuario está permitido
    if not is_denied and not is_unauth:
        return None

    if is_denied:
        event_type = "permission_denied"
        msg = (
            f"Acceso denegado por el sistema a '{accessed_path}' "
            f"— usuario: '{username}', comando: '{comm or exe}'. "
            f"Usuarios permitidos: {allowed_users or 'sin restricción explícita'}"
        )
    else:
        event_type = "unauthorized_access"
        msg = (
            f"Acceso NO autorizado a '{accessed_path}' "
            f"— usuario: '{username}', comando: '{comm or exe}'. "
            f"Usuarios permitidos: {allowed_users}"
        )

    return {
        "event_type":    event_type,
        "source_system": "file_guardian",
        "username":      username,
        "source_ip":     "127.0.0.1",
        "hostname":      socket.gethostname(),
        "service":       "file_guardian",
        "message":       msg,
        "raw_line":      f"pid={pid} comm={comm} exe={exe} path={accessed_path} success={success} exit={exit_val}",
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "metadata": {
            "accessed_path":   accessed_path,
            "restricted_path": matching["path"],
            "allowed_users":   allowed_users,
            "command":         comm,
            "executable":      exe,
            "pid":             pid,
            "denied_by_os":    is_denied,
            "unauthorized":    is_unauth,
        }
    }

# -------------------------------------------------------------
# NETWORK (BATCH + RETRY)
# -------------------------------------------------------------

BATCH_SIZE = 50   # máximo de eventos por petición HTTP

def send_events(events):
    """Envía eventos en lotes de BATCH_SIZE para evitar payloads gigantes."""
    all_ok = True
    for i in range(0, max(len(events), 1), BATCH_SIZE):
        batch = events[i:i + BATCH_SIZE]
        payload = {
            "agent": {
                "name":    "logsentinel-agent",
                "system":  SYSTEM_NAME,
                "sent_at": datetime.now(timezone.utc).isoformat()
            },
            "events": batch
        }
        headers = {"Content-Type": "application/json"}
        if API_KEY:
            headers["X-API-Key"] = API_KEY
        try:
            r = session.post(LOGSENTINEL_URL, json=payload, headers=headers, timeout=10)
            if r.status_code != 200:
                all_ok = False
        except Exception as e:
            logging.warning(f"Error de red: {e}")
            all_ok = False
    return all_ok

# -------------------------------------------------------------
# CONTROL
# -------------------------------------------------------------

running = True

def stop(_sig, _frame):
    global running
    running = False

signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)

# -------------------------------------------------------------
# MAIN
# -------------------------------------------------------------

def main():
    load_config()

    if not API_KEY:
        raise ValueError("LOGSENTINEL_API_KEY no configurada")

    if RESTRICTED_PATHS:
        setup_audit_rules(RESTRICTED_PATHS)
        logging.info(f"[FileGuardian] {len(RESTRICTED_PATHS)} ruta(s) bajo vigilancia")
    else:
        logging.info("[FileGuardian] Sin rutas restringidas configuradas")

    state  = load_json(STATE_FILE)
    buffer = load_json(BUFFER_FILE).get("events", [])

    logging.info("Agent v4 iniciado")

    while running:
        new_events = []

        # — Logs del sistema (SSH, syslog) —
        for src in LOG_SOURCES:
            lines = read_new_lines(src["path"], state)
            for line in lines:
                event = parse_line(line.strip(), src["source_system"])
                if event:
                    new_events.append(event)

        # — File Guardian (auditd) —
        if RESTRICTED_PATHS:
            guardian_events = read_audit_events(state, RESTRICTED_PATHS)
            if guardian_events:
                logging.info(f"[FileGuardian] {len(guardian_events)} acceso(s) sospechoso(s)")
                new_events.extend(guardian_events)

        # — Resumen de escaneos SSH (anti-ruido) —
        scan_events = flush_invalid_user_buckets()
        if scan_events:
            logging.info(f"[SSH-Scan] {len(scan_events)} resumen(es) de escaneo")
            new_events.extend(scan_events)

        buffer.extend(new_events)

        if buffer:
            success = send_events(buffer)
            if success:
                logging.info(f"Enviados {len(buffer)} eventos")
                buffer = []
            else:
                logging.warning("Fallo de envio - buffer retenido")

        save_json(STATE_FILE, state)
        save_json(BUFFER_FILE, {"events": buffer})

        time.sleep(SEND_INTERVAL)

    save_json(STATE_FILE, state)
    save_json(BUFFER_FILE, {"events": buffer})


if __name__ == "__main__":
    main()
