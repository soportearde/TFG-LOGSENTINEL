from datetime import datetime, timezone

_WP_USER_PATHS = [
    "wp-admin/user-new.php",
    "wp-admin/users.php",
    "/wp-json/wp/v2/users",
    "wp-admin/user-new",
]

_ADMIN_ROLE_INDICATORS = [
    "role=administrator",
    'role":"administrator',
    'role": "administrator',
    '"role":"administrator"',
    "new_admin",
    "add_admin",
    "role%3dadministrator",
    "set_role.*administrator",
]

_WP_ACTION_KEYWORDS = [
    "user_register", "user_new", "createuser", "adduser",
    "wpmu_new_user", "wp_insert_user", "added_user",
    "created_user", "new user", "nuevo usuario", "new_user",
]


def run(event):
    path       = event.get("resource") or ""
    event_type = event.get("event_type") or ""
    message    = event.get("message")   or ""
    raw_line   = event.get("raw_line")  or ""

    event_str  = f"{path} {event_type} {message} {raw_line}".lower()
    path_lower = path.lower()

    path_matches  = any(wp in path_lower for wp in _WP_USER_PATHS)
    has_admin     = any(ind in event_str for ind in _ADMIN_ROLE_INDICATORS)
    has_wp_action = any(kw in event_str for kw in _WP_ACTION_KEYWORDS)

    if path_matches and has_admin:
        detail = f"New WordPress admin user created via {path}"
    elif "wp-json" in path_lower and "users" in path_lower and has_admin:
        detail = f"WordPress REST API admin user creation detected: {path}"
    elif has_admin and has_wp_action:
        detail = "WordPress admin user creation detected in application logs"
    else:
        return None

    source_ip = event.get("source_ip") or "unknown"
    user      = event.get("username")  or "unknown"

    return {
        "rule_name":       "wp-admin",
        "severity_id":     4,
        "source_ip":       source_ip,
        "username":        user,
        "title":           "WordPress Admin User Created",
        "message":         (
            f"A new user with administrator role was created in WordPress. "
            f"{detail}. Source IP: {source_ip}, User: {user}"
        ),
        "metadata":        event,
        "event_timestamp": datetime.now(timezone.utc),
    }
