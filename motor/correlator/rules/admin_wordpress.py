from datetime import datetime, timezone


def run(event):
    event_type = event.get("event_type", "")
    message = event.get("message", "")
    raw_line = event.get("raw_line", "")
    source_system = event.get("source_system", "")
    service = event.get("service", "")

    username = event.get("username", "")
    if username:
        username = username.rstrip(",").strip()

    # Detectar creación de usuario administrador en WordPress
    # Esto puede venir como evento de creación de usuario con indicios de WordPress/admin
    # o como un log de WordPress que registre la creación de un rol administrador

    combined_text = (message + " " + raw_line).lower()

    # Estrategia 1: evento user_created con contexto WordPress
    is_user_created = event_type == "user_created"

    # Estrategia 2: detectar en el mensaje/raw_line indicios de WordPress admin user creation
    wp_indicators = [
        "wordpress",
        "wp-admin",
        "wp-login",
        "wp_capabilities",
        "wp_user_level",
        "wpdb",
        "wp-json",
        "woocommerce",
        "/wp/",
    ]

    admin_indicators = [
        "administrator",
        "role=administrator",
        "role=\"administrator\"",
        "role='administrator'",
        "wp_capabilities.*administrator",
        "set_role.*administrator",
        "add_role.*administrator",
        "user_role.*administrator",
        "admin role",
        "role: administrator",
        "new user.*admin",
        "created.*administrator",
        "useradd.*wordpress",
        "wp user create",
        "wp_usermeta.*administrator",
    ]

    has_wp_context = any(indicator in combined_text for indicator in wp_indicators)
    has_admin_role = any(indicator in combined_text for indicator in admin_indicators)

    # Caso 1: Mensaje contiene evidencia directa de creación de admin en WordPress
    if has_wp_context and has_admin_role:
        return {
            "rule_name": "admin_wordpress",
            "severity_id": 4,
            "source_ip": event.get("source_ip"),
            "username": username,
            "title": "Creación de usuario administrador en WordPress",
            "message": (
                f"Se ha detectado la creación de un usuario con rol administrador "
                f"en WordPress. Usuario: '{username}'. "
                f"Servidor: {event.get('hostname', 'desconocido')}. "
                f"Esto puede indicar compromiso del sitio o acceso no autorizado al panel de administración."
            ),
            "metadata": event,
            "event_timestamp": datetime.now(timezone.utc),
        }

    # Caso 2: Evento de creación de usuario con contexto WordPress en el mensaje
    if is_user_created and has_wp_context:
        return {
            "rule_name": "admin_wordpress",
            "severity_id": 3,
            "source_ip": event.get("source_ip"),
            "username": username,
            "title": "Nuevo usuario creado con contexto WordPress",
            "message": (
                f"Se ha creado un nuevo usuario '{username}' en un entorno WordPress. "
                f"Servidor: {event.get('hostname', 'desconocido')}. "
                f"Verifique si el usuario tiene privilegios de administrador."
            ),
            "metadata": event,
            "event_timestamp": datetime.now(timezone.utc),
        }

    # Caso 3: Evento de creación de usuario con nombre sospechoso típico de atacantes en WP
    if is_user_created and has_admin_role:
        return {
            "rule_name": "admin_wordpress",
            "severity_id": 4,
            "source_ip": event.get("source_ip"),
            "username": username,
            "title": "Creación de usuario administrador detectada (posible WordPress)",
            "message": (
                f"Se ha detectado la creación de un usuario '{username}' con rol de administrador. "
                f"Servidor: {event.get('hostname', 'desconocido')}. "
                f"Revisar si es una acción legítima o un posible compromiso de WordPress."
            ),
            "metadata": event,
            "event_timestamp": datetime.now(timezone.utc),
        }

    return None