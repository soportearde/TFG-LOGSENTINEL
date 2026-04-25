#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time
import re
import os
import signal
import socket
import logging
from datetime import datetime, timezone
import requests

# -------------------------------------------------------------
# CONFIG
# -------------------------------------------------------------

LOGSENTINEL_URL = os.getenv("LOGSENTINEL_URL", "http://localhost:5000/log")
API_KEY = os.getenv("LOGSENTINEL_API_KEY")
SYSTEM_NAME = os.getenv("LOGSENTINEL_SYSTEM_NAME", socket.gethostname())
SEND_INTERVAL = int(os.getenv("LOGSENTINEL_INTERVAL", "5"))

STATE_FILE = "/var/lib/logsentinel/agent_state.json"
BUFFER_FILE = "/var/lib/logsentinel/buffer.json"

LOG_SOURCES = [
    {"path": "/var/log/auth.log", "source_system": "ssh"},
    {"path": "/var/log/syslog", "source_system": "linux_syslog"},
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

    global LOGSENTINEL_URL, API_KEY, SYSTEM_NAME, SEND_INTERVAL
    LOGSENTINEL_URL = config.get("url", LOGSENTINEL_URL)
    API_KEY = config.get("api_key", API_KEY)
    SYSTEM_NAME = config.get("system_name", SYSTEM_NAME)
    SEND_INTERVAL = config.get("interval", SEND_INTERVAL)

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

SSH_FAILED_PATTERN = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)")
SSH_SUCCESS_PATTERN = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)")
SUDO_PATTERN = re.compile(r"sudo:\s+(\S+)\s+:.*COMMAND=(.+)")
USER_CREATE_PATTERN = re.compile(r"new user:\s+name=([^,\s]+)|useradd\[.*\]:\s+new user.*name=([^,\s]+)")
PERM_DENIED_PATTERN = re.compile(r"[Pp]ermission denied|DENIED|authentication failure")

# -------------------------------------------------------------
# PARSERS
# -------------------------------------------------------------

def parse_auth_line(line, source_system):
    match = AUTH_PATTERN.match(line)
    if not match:
        return None

    ts, hostname, service, message = match.groups()

    event = {
        "timestamp": normalize_timestamp(ts),
        "source_system": source_system,
        "hostname": hostname,
        "service": service,
        "message": message,
        "raw_line": line.strip(),
    }

    if (m := SSH_FAILED_PATTERN.search(message)):
        event.update({"event_type": "login_failed", "username": m.group(1), "source_ip": m.group(2)})
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

    if PERM_DENIED_PATTERN.search(message):
        event["event_type"] = "permission_denied"
        return event

    return None


def parse_syslog_line(line, source_system):
    match = AUTH_PATTERN.match(line)
    if not match:
        return None

    ts, hostname, service, message = match.groups()

    event = {
        "timestamp": normalize_timestamp(ts),
        "source_system": source_system,
        "hostname": hostname,
        "service": service,
        "message": message,
        "raw_line": line.strip(),
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
    size = os.path.getsize(filepath)

    if size < last_pos:
        last_pos = 0

    with open(filepath, "r", errors="replace") as f:
        f.seek(last_pos)
        lines = f.readlines()
        state[filepath] = f.tell()

    return lines

# -------------------------------------------------------------
# NETWORK (BATCH + RETRY)
# -------------------------------------------------------------

def send_events(events):
    payload = {
        "agent": {
            "name": "logsentinel-agent",
            "system": SYSTEM_NAME,
            "sent_at": datetime.now(timezone.utc).isoformat()
        },
        "events": events
    }

    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["X-API-Key"] = API_KEY

    try:
        r = session.post(LOGSENTINEL_URL, json=payload, headers=headers, timeout=5)
        return r.status_code == 200
    except Exception as e:
        logging.warning(f"Error de red: {e}")
        return False

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

    state = load_json(STATE_FILE)
    buffer = load_json(BUFFER_FILE).get("events", [])

    logging.info("Agent v3 iniciado")

    while running:
        new_events = []

        for src in LOG_SOURCES:
            lines = read_new_lines(src["path"], state)
            for line in lines:
                event = parse_line(line.strip(), src["source_system"])
                if event:
                    new_events.append(event)

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
