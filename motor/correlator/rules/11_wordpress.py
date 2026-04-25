from datetime import datetime, timezone
from collections import defaultdict

# --- Umbrales configurables ---
WP_BF_THRESHOLD  = 5    # intentos fallidos en wp-login.php
WP_BF_WINDOW     = 180  # segundos

XMLRPC_THRESHOLD = 10   # peticiones a xmlrpc.php
XMLRPC_WINDOW    = 60

ENUM_THRESHOLD   = 8    # peticiones de enumeración de usuarios
ENUM_WINDOW      = 120

# --- Estado en memoria ---
_wp_failed  = defaultdict(list)
_xmlrpc     = defaultdict(list)
_user_enum  = defaultdict(list)

WP_SENSITIVE_PATHS = [
    "wp-config.php", "wp-config.bak", "wp-config-sample.php",
    ".env", "/wp-content/debug.log", ".git/config",
    "backup", "database.sql",
]

WP_ENUM_PATHS = [
    "/?author=", "/wp-json/wp/v2/users", "/?rest_route=/wp/v2/users",
]


def _purge(lst, now, window):
    return [t for t in lst if (now - t).total_seconds() <= window]


def run(event):
    now        = datetime.now(timezone.utc)
    ip         = event.get("source_ip")
    user       = event.get("username")
    event_type = event.get("event_type") or ""
    path       = event.get("resource") or ""

    # ------------------------------------------------------------------ #
    # 1. Brute force en wp-login.php                                       #
    # ------------------------------------------------------------------ #
    if event_type == "login_failed" and "wp-login" in path:
        _wp_failed[ip].append(now)
        _wp_failed[ip] = _purge(_wp_failed[ip], now, WP_BF_WINDOW)
        if len(_wp_failed[ip]) >= WP_BF_THRESHOLD:
            count = len(_wp_failed[ip])
            _wp_failed[ip] = []
            return {
                "rule_name":       "wp_bruteforce_login",
                "severity_id":     3,
                "source_ip":       ip,
                "username":        user,
                "title":           "WordPress: Brute Force en wp-login.php",
                "message":         f"{count} intentos fallidos en {WP_BF_WINDOW}s desde {ip}",
                "metadata":        event,
                "event_timestamp": now,
            }

    # ------------------------------------------------------------------ #
    # 2. Abuso de XML-RPC                                                  #
    # ------------------------------------------------------------------ #
    if "xmlrpc.php" in path:
        _xmlrpc[ip].append(now)
        _xmlrpc[ip] = _purge(_xmlrpc[ip], now, XMLRPC_WINDOW)
        if len(_xmlrpc[ip]) >= XMLRPC_THRESHOLD:
            count = len(_xmlrpc[ip])
            _xmlrpc[ip] = []
            return {
                "rule_name":       "wp_xmlrpc_abuse",
                "severity_id":     3,
                "source_ip":       ip,
                "username":        user,
                "title":           "WordPress: Abuso de XML-RPC",
                "message":         (
                    f"{count} peticiones a xmlrpc.php en "
                    f"{XMLRPC_WINDOW}s — posible brute force o DDoS amplificado"
                ),
                "metadata":        event,
                "event_timestamp": now,
            }

    # ------------------------------------------------------------------ #
    # 3. Enumeración de usuarios                                           #
    # ------------------------------------------------------------------ #
    if any(p in path for p in WP_ENUM_PATHS):
        _user_enum[ip].append(now)
        _user_enum[ip] = _purge(_user_enum[ip], now, ENUM_WINDOW)
        if len(_user_enum[ip]) >= ENUM_THRESHOLD:
            count = len(_user_enum[ip])
            _user_enum[ip] = []
            return {
                "rule_name":       "wp_user_enumeration",
                "severity_id":     2,
                "source_ip":       ip,
                "username":        user,
                "title":           "WordPress: Enumeración de usuarios",
                "message":         (
                    f"{count} peticiones de enumeración en "
                    f"{ENUM_WINDOW}s desde {ip} — ruta: {path}"
                ),
                "metadata":        event,
                "event_timestamp": now,
            }

    # ------------------------------------------------------------------ #
    # 4. Acceso a archivos sensibles                                       #
    # ------------------------------------------------------------------ #
    if any(p in path for p in WP_SENSITIVE_PATHS):
        return {
            "rule_name":       "wp_sensitive_file_access",
            "severity_id":     4,
            "source_ip":       ip,
            "username":        user,
            "title":           "WordPress: Acceso a archivo sensible",
            "message":         f"Intento de acceso a '{path}' desde {ip}",
            "metadata":        event,
            "event_timestamp": now,
        }

    return None
