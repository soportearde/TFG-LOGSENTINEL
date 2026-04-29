#!/usr/bin/env python3

import json
import logging
from datetime import datetime

import requests
from flask import Flask, request, jsonify, Response
from logging.handlers import RotatingFileHandler

import psycopg2
from psycopg2.extras import Json


HOST = "0.0.0.0"
PORT = 5000

LOG_FILE = "received_logs.log"
MAX_LOG_SIZE = 5 * 1024 * 1024
BACKUP_COUNT = 5

NORMALIZER_URL = "http://normalizer:6000/normalize"

app = Flask(__name__)

# -----------------------------------------------------
# CONEXIÓN A POSTGRESQL (ALMACÉN DE LOGS EN BRUTO)
# -----------------------------------------------------

pg = psycopg2.connect(
    host="host.docker.internal",
    port=5432,
    database="log_collector",
    user="postgres",
    password="NuevaPasswordSegura!"
)

pg_cursor = pg.cursor()
print("Conectado a PostgreSQL (log_collector)")


# -----------------------------------------------------
# LOGGING LOCAL (FICHEROS)
# -----------------------------------------------------
log_format = "%(asctime)s | %(levelname)s | %(remote_addr)s | %(message)s"

file_handler = RotatingFileHandler(
    LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT, encoding="utf-8"
)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter(log_format))

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter(log_format))

logger = logging.getLogger("log-server")
logger.setLevel(logging.INFO)
if not logger.handlers:
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
logger.propagate = False


# -----------------------------------------------------
# FUNCIÓN: GUARDAR LOG EN POSTGRESQL (RAW)
# -----------------------------------------------------
def save_raw_log(event):
    pg_cursor.execute(
        """
        INSERT INTO raw_logs
        (source_system, source_ip, username, event_type, raw_data, created_at)
        VALUES (%s, %s, %s, %s, %s, NOW());
        """,
        (
            event.get("source_system"),
            event.get("source_ip"),
            event.get("username"),
            event.get("event_type"),
            Json(event),
        )
    )
    pg.commit()
    print("[RAW LOG GUARDADO EN POSTGRESQL]")


# -----------------------------------------------------
# FUNCIÓN: PROCESAR UN EVENTO INDIVIDUAL
# -----------------------------------------------------
def process_event(event, client_ip, user_agent):
    full_event = {
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "source_ip": client_ip,
        "user_agent": user_agent,
        **event
    }

    save_raw_log(full_event)

    try:
        r = requests.post(NORMALIZER_URL, json=full_event, timeout=3)
        return {"status": r.status_code, "response": r.text}
    except Exception as e:
        return {"status": "error", "response": str(e)}


# -----------------------------------------------------
# RECIBIR LOGS
# -----------------------------------------------------
@app.route("/log", methods=["POST"])
def receive_log():
    client_ip = request.remote_addr or "unknown"
    user_agent = (request.headers.get("User-Agent") or "unknown")[:200]

    if request.is_json:
        payload = request.get_json()
    else:
        raw = request.data.decode("utf-8", errors="replace").strip()
        try:
            payload = json.loads(raw)
        except Exception:
            payload = {"raw": raw}

    logger.info(json.dumps(payload), extra={"remote_addr": client_ip})

    # Formato batch del nuevo agente: {"agent": {...}, "events": [...]}
    if isinstance(payload, dict) and "events" in payload:
        agent_info = payload.get("agent", {})
        events = payload["events"]
        results = []

        for event in events:
            # Propagar metadatos del agente a cada evento
            event.setdefault("agent_system_name", agent_info.get("system"))
            event.setdefault("agent_timestamp", agent_info.get("sent_at"))
            result = process_event(event, client_ip, user_agent)
            results.append(result)

        return jsonify({
            "status": "received",
            "events_processed": len(results),
            "sent_to_normalizer": results
        }), 200

    # Formato legacy: evento único en el root del payload
    result = process_event(payload, client_ip, user_agent)
    return jsonify({
        "status": "received",
        "sent_to_normalizer": result
    }), 200


# -----------------------------------------------------
# INDEX
# -----------------------------------------------------
@app.route("/")
def index():
    return Response("LogCollector activo y guardando RAW en PostgreSQL", mimetype="text/plain")


# -----------------------------------------------------
# MAIN
# -----------------------------------------------------
if __name__ == "__main__":
    print(f"LogCollector escuchando en http://localhost:{PORT}/log")
    app.run(host=HOST, port=PORT, debug=False)
