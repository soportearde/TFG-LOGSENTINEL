#!/usr/bin/env python3
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timezone
from psycopg2 import pool as pg_pool
import json
import importlib
import sys
import os
import threading
import logging
import anthropic

# ---------------------------------------------------------
# LOGGING
# ---------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("correlator")

RULES_DIR = "/app/rules"

# Credenciales desde variables de entorno
DB_HOST           = os.getenv("POSTGRES_HOST",     "host.docker.internal")
DB_PORT           = int(os.getenv("POSTGRES_PORT", "5432"))
DB_NAME           = os.getenv("POSTGRES_DB",       "alerts_db")
DB_USER           = os.getenv("POSTGRES_USER",     "postgres")
DB_PASSWORD       = os.getenv("POSTGRES_PASSWORD", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

app = Flask(__name__)
CORS(app)

# Lock para acceso concurrente al rule_id_map
_rule_id_map_lock = threading.Lock()


def _json_default(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

# Estado compartido entre reglas (brute force, secuencias, etc.)
state = {}

RULE_SYSTEM_PROMPT = """
Eres un generador de reglas de correlación para LogSentinel, un sistema SIEM.
Genera un módulo Python con una función run(event) que detecte eventos de seguridad.

════════════════════════════════════════════════
ESTRUCTURA REAL DEL EVENTO (campos disponibles)
════════════════════════════════════════════════
{
    "event_type":        str,   # tipo del evento (ver lista abajo)
    "source_system":     str,   # "ssh" | "linux_syslog"
    "username":          str,   # usuario implicado (puede tener coma al final en user_created)
    "source_ip":         str,   # IP de origen (puede ser None)
    "hostname":          str,   # nombre del servidor
    "service":           str,   # servicio que generó el log: "sshd", "useradd", "sudo", etc.
    "message":           str,   # texto del mensaje de log
    "raw_line":          str,   # línea completa del log original
    "agent_system_name": str,   # nombre del sistema monitorizado
    "agent_timestamp":   str,   # timestamp ISO 8601 del agente
}

⚠️  NO existe ningún campo "raw" ni "user". Usa siempre los campos directamente.
⚠️  En event_type "user_created", el campo username puede venir como "mario,"
    Límpialo siempre con: username = event.get("username", "").rstrip(",").strip()

════════════════════════════════════════════════
TIPOS DE EVENTOS DISPONIBLES (event_type)
════════════════════════════════════════════════
- "login_failed"       → intento SSH fallido       (tiene source_ip, username)
- "login_success"      → login SSH exitoso          (tiene source_ip, username)
- "sudo_command"       → ejecución de sudo          (tiene username, message con el comando)
- "user_created"       → creación de usuario        (tiene username con posible coma al final)
- "permission_denied"  → acceso denegado            (tiene message con la ruta)

════════════════════════════════════════════════
FORMATO OBLIGATORIO DEL DICT DE RETORNO
════════════════════════════════════════════════
{
    "rule_name":       "<rule_name exacto tal como se indica>",
    "severity_id":     <1=low | 2=medium | 3=high | 4=critical>,
    "source_ip":       event.get("source_ip"),
    "username":        <username limpio>,
    "title":           "<título corto en español>",
    "message":         "<mensaje descriptivo en español>",
    "metadata":        event,
    "event_timestamp": datetime.now(timezone.utc)
}

════════════════════════════════════════════════
REGLAS DE UMBRAL (N eventos en T segundos)
════════════════════════════════════════════════
Cuando la descripción implique "más de N veces", "repetidos", "brute force", etc.:
- Declara a nivel de módulo: from collections import defaultdict; _history = defaultdict(list)
- Función _purge(lst, window_secs) que elimina entradas más antiguas que window_secs
- Tras disparar la alerta, resetea la lista del key afectado para evitar duplicados

════════════════════════════════════════════════
REGLAS ABSOLUTAS
════════════════════════════════════════════════
- Importa solo: from datetime import datetime, timezone  y lo que realmente uses
- Una sola función pública: def run(event):
- Retorna el dict cuando detecta la amenaza, None en cualquier otro caso
- Sin prints, sin logging, sin efectos secundarios
- Devuelve SOLO el código Python, sin explicaciones ni bloques markdown
"""


# ---------------------------------------------------------
# POOL DE CONEXIONES
# ---------------------------------------------------------
def create_pool() -> pg_pool.ThreadedConnectionPool:
    return pg_pool.ThreadedConnectionPool(
        minconn=2,
        maxconn=10,
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    )


# ---------------------------------------------------------
# CARGAR REGLAS  —  limpia caché para hot-reload
# ---------------------------------------------------------
def load_rules() -> list:
    if not os.path.isdir(RULES_DIR):
        log.warning("RULES_DIR '%s' no existe o no es un directorio. No se cargaron reglas.", RULES_DIR)
        return []

    stale = [k for k in sys.modules if k.startswith("rules.")]
    for k in stale:
        del sys.modules[k]

    rules = []
    for filename in sorted(os.listdir(RULES_DIR)):
        if filename.endswith(".py") and not filename.startswith("__"):
            module_name = filename[:-3]
            try:
                module = importlib.import_module(f"rules.{module_name}")
                if not callable(getattr(module, "run", None)):
                    log.warning("Módulo '%s' no expone una función run() válida. Ignorado.", filename)
                    continue
                rules.append(module)
            except Exception as e:
                log.error("Error cargando %s: %s", filename, e)
    log.info("%d reglas cargadas.", len(rules))
    return rules


# ---------------------------------------------------------
# CARGAR rule_name → rule_id DESDE LA BD
# ---------------------------------------------------------
def load_rule_ids(conn) -> dict:
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, rule_name
            FROM correlation_rules
            WHERE enabled = true
        """)
        return {row[1]: row[0] for row in cur.fetchall()}


def refresh_rule_id_map():
    db_pool = app.config.get("db_pool")
    if db_pool is None:
        log.error("refresh_rule_id_map: db_pool no inicializado.")
        return

    conn = None
    try:
        conn = db_pool.getconn()
        new_map = load_rule_ids(conn)
        with _rule_id_map_lock:
            app.config["rule_id_map"] = new_map
        log.info("rule_id_map recargado desde BD (%d reglas activas).", len(new_map))
    except Exception as e:
        log.error("Error recargando rule_id_map: %s", e)
    finally:
        if conn is not None:
            db_pool.putconn(conn)


# ---------------------------------------------------------
# GENERACIÓN AUTOMÁTICA DE CÓDIGO DE REGLA
# ---------------------------------------------------------
def generate_rule_code(rule_name: str, description: str) -> str:
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    message = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=2048,
        system=RULE_SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": (
                    f"Genera la regla de correlación con los siguientes parámetros:\n\n"
                    f"rule_name: {rule_name}\n"
                    f"Descripción: {description}\n\n"
                    f"Recuerda: usa event.get('username') y event.get('source_ip') directamente, "
                    f"NO uses event.get('raw') ni event.get('user'). "
                    f"El rule_name en el return debe ser exactamente: {rule_name}"
                )
            }
        ]
    )

    block = next((b for b in message.content if hasattr(b, "text")), None)
    code = block.text.strip() if block is not None else None

    if not code:
        raise ValueError("La API no devolvió ningún bloque de texto.")

    # Eliminar bloques markdown si el motor los incluye
    if code.startswith("```python"):
        code = code[9:]
    elif code.startswith("```"):
        code = code[3:]
    if code.endswith("```"):
        code = code[:-3]
    return code.strip()


# ---------------------------------------------------------
# INSERTAR ALERTA
# ---------------------------------------------------------
def insert_alert(conn, alert: dict, rule_id_map: dict):
    rule_name = alert.get("rule_name")

    if not rule_name:
        log.warning("Alerta sin rule_name. Descartada.")
        return

    # Obtener una copia actualizada del mapa si la regla no aparece
    if rule_name not in rule_id_map:
        log.warning("Regla '%s' no está en el mapa. Recargando BD...", rule_name)
        refresh_rule_id_map()
        with _rule_id_map_lock:
            rule_id_map = dict(app.config["rule_id_map"])

    if rule_name not in rule_id_map:
        log.warning("Regla '%s' no existe en BD tras recarga. Alerta descartada.", rule_name)
        return

    rule_id = rule_id_map[rule_name]

    # source_system: preferir el del evento; fallback al del alert; último recurso "LogSentinel"
    source_system = (
        alert.get("metadata", {}).get("source_system")
        or alert.get("source_system")
        or "LogSentinel"
    )

    try:
        metadata_json = json.dumps(alert.get("metadata", {}), default=_json_default)
    except (TypeError, ValueError) as e:
        log.error("Error serializando metadata de alerta '%s': %s. Usando {}.", rule_name, e)
        metadata_json = "{}"

    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO alerts (
                rule_id, severity_id, source_ip, username,
                source_system, title, message, metadata,
                event_timestamp, status
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s);
        """, (
            rule_id,
            alert.get("severity_id", 1),
            alert.get("source_ip"),
            alert.get("username"),
            source_system,
            alert.get("title"),
            alert.get("message"),
            metadata_json,
            alert.get("event_timestamp", datetime.now(timezone.utc)),
            "open",
        ))

    conn.commit()
    log.info("Alerta insertada: %s", alert.get("title"))


# ---------------------------------------------------------
# EVALUAR REGLAS
# ---------------------------------------------------------
def evaluate_rules(event: dict, rules: list) -> list:
    alerts = []
    for rule in rules:
        rule_label = f"{getattr(rule, '__name__', '?')} ({getattr(rule, '__file__', '?')})"
        try:
            try:
                result = rule.run(event, state)
            except TypeError:
                result = rule.run(event)
            if result:
                alerts.append(result)
        except Exception as e:
            log.error("Error evaluando regla %s: %s", rule_label, e)
    return alerts


# ---------------------------------------------------------
# ENDPOINT PRINCIPAL — recibir eventos
# ---------------------------------------------------------
@app.post("/event")
def receive_event():
    event = request.get_json(silent=True)

    log.info("Evento recibido: %s", event)

    if not isinstance(event, dict):
        return jsonify({"error": "JSON inválido o Content-Type incorrecto"}), 400

    alerts = evaluate_rules(event, app.config["rules"])

    if not alerts:
        return jsonify({"status": "processed", "alerts_generated": 0}), 200

    db_pool = app.config["db_pool"]
    conn    = db_pool.getconn()

    try:
        with _rule_id_map_lock:
            rule_id_map = dict(app.config["rule_id_map"])
        for alert in alerts:
            insert_alert(conn, alert, rule_id_map)
    finally:
        db_pool.putconn(conn)

    return jsonify({
        "status":           "processed",
        "alerts_generated": len(alerts),
    }), 200


# ---------------------------------------------------------
# API REGLAS — listar
# ---------------------------------------------------------
@app.get("/api/rules")
def api_list_rules():
    conn = app.config["db_pool"].getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, rule_name, enabled FROM correlation_rules ORDER BY rule_name"
            )
            rows = cur.fetchall()
    finally:
        app.config["db_pool"].putconn(conn)

    return jsonify([
        {"id": r[0], "rule_name": r[1], "enabled": r[2]}
        for r in rows
    ])


# ---------------------------------------------------------
# API REGLAS — generar con IA y activar
# ---------------------------------------------------------
@app.post("/api/rules/generate")
def api_generate_rule():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON inválido o Content-Type incorrecto"}), 400

    rule_name   = (data.get("rule_name")   or "").strip().replace(" ", "_")
    description = (data.get("description") or "").strip()

    if not rule_name or not description:
        return jsonify({"error": "Se requieren rule_name y description"}), 400

    if not ANTHROPIC_API_KEY:
        return jsonify({"error": "ANTHROPIC_API_KEY no configurada en el servidor"}), 500

    try:
        code = generate_rule_code(rule_name, description)
    except Exception as e:
        log.error("Error generando código para regla '%s': %s", rule_name, e)
        return jsonify({"error": f"Error generando código: {e}"}), 500

    filepath = os.path.join(RULES_DIR, f"{rule_name}.py")
    try:
        os.makedirs(RULES_DIR, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(code)
    except OSError as e:
        log.error("Error escribiendo fichero de regla '%s': %s", filepath, e)
        return jsonify({"error": f"Error escribiendo fichero: {e}"}), 500

    conn = app.config["db_pool"].getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO correlation_rules (rule_name, enabled)
                VALUES (%s, true)
                ON CONFLICT (rule_name) DO NOTHING
                """,
                (rule_name,)
            )
        conn.commit()
    finally:
        app.config["db_pool"].putconn(conn)

    app.config["rules"] = load_rules()
    refresh_rule_id_map()

    return jsonify({
        "status":    "created",
        "rule_name": rule_name,
        "code":      code,
    }), 201


# ---------------------------------------------------------
# API REGLAS — activar / desactivar
# ---------------------------------------------------------
@app.post("/api/rules/toggle")
def api_toggle_rule():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON inválido o Content-Type incorrecto"}), 400

    rule_name = data.get("rule_name")
    enabled   = data.get("enabled")

    if rule_name is None or enabled is None:
        return jsonify({"error": "Se requieren rule_name y enabled"}), 400

    conn = app.config["db_pool"].getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE correlation_rules SET enabled=%s WHERE rule_name=%s",
                (bool(enabled), rule_name)
            )
        conn.commit()
    finally:
        app.config["db_pool"].putconn(conn)

    refresh_rule_id_map()
    return jsonify({
        "status":    "updated",
        "rule_name": rule_name,
        "enabled":   bool(enabled),
    })


# ---------------------------------------------------------
# API REGLAS — obtener código fuente de una regla
# ---------------------------------------------------------
@app.get("/api/rules/<rule_name>/code")
def api_get_rule_code(rule_name: str):
    if not all(c.isalnum() or c == "_" for c in rule_name):
        return jsonify({"error": "Nombre de regla inválido"}), 400

    filepath = os.path.join(RULES_DIR, f"{rule_name}.py")
    if not os.path.isfile(filepath):
        return jsonify({"error": "Fichero de regla no encontrado"}), 404

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            code = f.read()
    except OSError as e:
        return jsonify({"error": f"Error leyendo fichero: {e}"}), 500

    return jsonify({"rule_name": rule_name, "code": code})


# ---------------------------------------------------------
# API REGLAS — hot-reload manual
# ---------------------------------------------------------
@app.post("/api/rules/reload")
def api_reload_rules():
    app.config["rules"] = load_rules()
    refresh_rule_id_map()
    return jsonify({
        "status":       "reloaded",
        "rules_loaded": len(app.config["rules"]),
    })


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------
if __name__ == "__main__":
    log.info("Correlation engine starting on port 7000...")

    try:
        connection_pool = create_pool()
    except Exception as e:
        log.critical("No se pudo crear el pool de conexiones a BD: %s", e)
        sys.exit(1)

    try:
        conn = connection_pool.getconn()
        rule_id_map = load_rule_ids(conn)
        connection_pool.putconn(conn)
    except Exception as e:
        log.critical("No se pudo cargar el mapa de reglas desde BD: %s", e)
        connection_pool.closeall()
        sys.exit(1)

    app.config["db_pool"]     = connection_pool
    app.config["rules"]       = load_rules()
    app.config["rule_id_map"] = rule_id_map

    log.info("Correlation engine running on port 7000.")
    app.run(host="0.0.0.0", port=7000)
