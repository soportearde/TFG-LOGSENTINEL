<?php
/**
 * Plugin Name: LogSentinel WordPress Agent
 * Description: Monitorización de seguridad para LogSentinel SIEM
 * Version: 2.1
 * Author: LogSentinel
 *
 * INSTALACIÓN:
 * 1. Copia este archivo en: wp-content/mu-plugins/logsentinel-agent.php
 * 2. Si la carpeta mu-plugins no existe, créala
 * 3. No hay que activar nada, se carga solo
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// Estos valores se inyectan automáticamente desde el panel de LogSentinel
define( 'LOGSENTINEL_API_KEY',  '__API_KEY__' );
define( 'LOGSENTINEL_ENDPOINT', '__ENDPOINT__' );

// ════════════════════════════════════════════════════════════
// FUNCIÓN DE ENVÍO — cURL directo con API Key
// ════════════════════════════════════════════════════════════

function logsentinel_send( array $payload ): void {
    $payload['source_system'] = 'wordpress';
    $payload['hostname']      = parse_url( get_site_url(), PHP_URL_HOST );
    $payload['source_ip']     = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $payload['user_agent']    = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    $payload['timestamp']     = gmdate('Y-m-d\TH:i:s\Z');

    $ch = curl_init( LOGSENTINEL_ENDPOINT );
    curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
    curl_setopt( $ch, CURLOPT_POST, true );
    curl_setopt( $ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'X-API-Key: ' . LOGSENTINEL_API_KEY,
    ]);
    curl_setopt( $ch, CURLOPT_POSTFIELDS, json_encode( $payload ) );
    curl_setopt( $ch, CURLOPT_TIMEOUT, 2 );
    curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 2 );
    curl_exec( $ch );
    curl_close( $ch );
}

// ════════════════════════════════════════════════════════════
// HEARTBEAT — avisa al SIEM de que WordPress está vivo
// ════════════════════════════════════════════════════════════

add_filter( 'cron_schedules', function( $schedules ) {
    $schedules['every_5_minutes'] = [
        'interval' => 300,
        'display'  => 'Cada 5 minutos',
    ];
    return $schedules;
});

add_action( 'init', function() {
    if ( ! wp_next_scheduled( 'logsentinel_heartbeat_event' ) ) {
        wp_schedule_event( time(), 'every_5_minutes', 'logsentinel_heartbeat_event' );
    }
});

add_action( 'logsentinel_heartbeat_event', function() {
    $heartbeat_url = str_replace( '/api/log', '/api/heartbeat', LOGSENTINEL_ENDPOINT );

    $ch = curl_init( $heartbeat_url );
    curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
    curl_setopt( $ch, CURLOPT_POST, true );
    curl_setopt( $ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'X-API-Key: ' . LOGSENTINEL_API_KEY,
    ]);
    curl_setopt( $ch, CURLOPT_POSTFIELDS, json_encode([
        'source_system' => 'wordpress',
        'hostname'      => parse_url( get_site_url(), PHP_URL_HOST ),
    ]) );
    curl_setopt( $ch, CURLOPT_TIMEOUT, 5 );
    curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 5 );
    curl_exec( $ch );
    curl_close( $ch );
});

// ════════════════════════════════════════════════════════════
// CALLBACKS DE EVENTOS DE SEGURIDAD
// ════════════════════════════════════════════════════════════

// 1. LOGIN FALLIDO
add_action( 'wp_login_failed', function( $username ) {
    static $done = false;
    if ( $done ) return;
    $done = true;

    logsentinel_send([
        'event_type'  => 'login_failed',
        'username'    => $username,
        'method'      => 'POST',
        'path'        => '/wp-login.php',
        'resource'    => '/wp-login.php',
        'status'      => 'failure',
        'status_code' => 403,
        'message'     => "Login fallido para usuario '{$username}' desde " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown')
    ]);
}, 10, 1 );

// 2. LOGIN EXITOSO
add_action( 'wp_login', function( $user_login, $user ) {
    static $done = false;
    if ( $done ) return;
    $done = true;

    logsentinel_send([
        'event_type'  => 'login_success',
        'username'    => $user->user_login,
        'method'      => 'POST',
        'path'        => '/wp-login.php',
        'resource'    => '/wp-login.php',
        'status'      => 'success',
        'status_code' => 200,
        'message'     => "Login exitoso para usuario '{$user->user_login}' desde " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown')
    ]);
}, 10, 2 );

// 3. LOGOUT
add_action( 'wp_logout', function( $user_id ) {
    static $done = false;
    if ( $done ) return;
    $done = true;

    $user_data = $user_id ? get_userdata( $user_id ) : false;
    $username  = $user_data ? $user_data->user_login : 'unknown';

    logsentinel_send([
        'event_type' => 'logout',
        'username'   => $username,
        'method'     => 'GET',
        'path'       => '/wp-login.php',
        'resource'   => '/wp-login.php',
        'status'     => 'success',
        'message'    => "Logout del usuario '{$username}'"
    ]);
}, 10, 1 );

// 4. CREACIÓN DE USUARIO
add_action( 'user_register', function( $user_id ) {
    static $done = false;
    if ( $done ) return;
    $done = true;

    $userdata = get_userdata( $user_id );
    if ( ! $userdata ) return;

    $login = $userdata->user_login;
    $roles = (array) $userdata->roles;
    $role  = ! empty( $roles ) ? $roles[0] : 'none';

    $msg = in_array( 'administrator', $roles )
        ? "new_admin_created: {$login} con rol administrator"
        : "Nuevo usuario '{$login}' creado con rol {$role}";

    logsentinel_send([
        'event_type' => 'user_created',
        'username'   => $login,
        'role'       => $role,
        'action'     => 'account_created',
        'status'     => 'success',
        'message'    => $msg,
        'raw_line'   => $msg
    ]);
}, 10, 1 );

// 5. CAMBIO DE ROL
add_action( 'set_user_role', function( $user_id, $new_role, $old_roles ) {
    static $done = false;
    if ( $done ) return;
    if ( empty( $old_roles ) ) return;

    $old_role = $old_roles[0];
    if ( $new_role === $old_role ) return;

    $done = true;

    $userdata = get_userdata( $user_id );
    if ( ! $userdata ) return;
    $login = $userdata->user_login;

    $msg = ( $new_role === 'administrator' )
        ? "new_admin_created: {$login} rol cambiado a administrator"
        : "Rol de '{$login}' cambiado de {$old_role} a {$new_role}";

    logsentinel_send([
        'event_type' => 'role_change',
        'username'   => $login,
        'role'       => $new_role,
        'old_role'   => $old_role,
        'action'     => 'role_changed',
        'status'     => 'success',
        'message'    => $msg,
        'raw_line'   => $msg
    ]);
}, 10, 3 );

// 6. ELIMINACIÓN DE USUARIO
add_action( 'delete_user', function( $user_id ) {
    static $done = false;
    if ( $done ) return;
    $done = true;

    $userdata = get_userdata( $user_id );
    if ( ! $userdata ) return;
    $login = $userdata->user_login;

    logsentinel_send([
        'event_type' => 'user_deleted',
        'username'   => $login,
        'action'     => 'account_deleted',
        'status'     => 'success',
        'message'    => "Usuario '{$login}' eliminado de WordPress"
    ]);
}, 10, 1 );

// 7. CAMBIO DE CONTRASEÑA
add_action( 'profile_update', function( $user_id, $old_data, $new_data ) {
    static $done = false;
    if ( $done ) return;
    $done = true;

    $userdata = get_userdata( $user_id );
    if ( ! $userdata ) return;

    if ( $old_data->user_pass !== $userdata->user_pass ) {
        logsentinel_send([
            'event_type' => 'password_change',
            'username'   => $userdata->user_login,
            'action'     => 'password_change',
            'status'     => 'success',
            'message'    => "Contraseña cambiada para el usuario '{$userdata->user_login}'"
        ]);
    }
}, 10, 3 );

// 8. PETICIÓN A xmlrpc.php
add_action( 'xmlrpc_call', function( $method_name ) {
    static $done = false;
    if ( $done ) return;
    $done = true;

    logsentinel_send([
        'event_type' => 'request',
        'method'     => 'POST',
        'path'       => '/xmlrpc.php',
        'resource'   => '/xmlrpc.php',
        'action'     => $method_name,
        'status'     => 'success',
        'message'    => "Llamada XML-RPC: {$method_name} desde " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown')
    ]);
}, 10, 1 );

// 9. INSTALACIÓN DE PLUGIN/TEMA
add_action( 'upgrader_process_complete', function( $upgrader, $hook_extra ) {
    static $done = false;
    if ( $done ) return;
    $done = true;

    if ( ! isset( $hook_extra['action'] ) || $hook_extra['action'] !== 'install' ) return;

    $name = 'unknown';
    if ( isset( $hook_extra['type'], $hook_extra['plugin'] ) && $hook_extra['type'] === 'plugin' ) {
        $name = $hook_extra['plugin'];
    } elseif ( isset( $hook_extra['type'], $hook_extra['theme'] ) && $hook_extra['type'] === 'theme' ) {
        $name = $hook_extra['theme'];
    }

    $current_user = wp_get_current_user();
    $admin = ( $current_user && $current_user->exists() ) ? $current_user->user_login : 'unknown';

    logsentinel_send([
        'event_type' => 'plugin_installed',
        'username'   => $admin,
        'action'     => 'plugin_installed',
        'resource'   => $name,
        'status'     => 'success',
        'message'    => "Plugin/tema '{$name}' instalado por '{$admin}'"
    ]);
}, 10, 2 );

// 10. ENUMERACIÓN USUARIOS REST API
add_filter( 'rest_pre_dispatch', function( $result, $server, $request ) {
    static $done = false;
    if ( $done ) return $result;

    $route = $request->get_route();
    if ( strpos( $route, '/wp/v2/users' ) !== false ) {
        $done = true;
        logsentinel_send([
            'event_type' => 'request',
            'method'     => $request->get_method(),
            'path'       => $route,
            'resource'   => $route,
            'status'     => 'success',
            'message'    => "Enumeración de usuarios vía REST API desde " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown')
        ]);
    }
    return $result;
}, 10, 3 );

// 11. ENUMERACIÓN POR ?author=
add_action( 'template_redirect', function() {
    static $done = false;
    if ( $done ) return;

    if ( is_author() && isset( $_SERVER['QUERY_STRING'] ) && strpos( $_SERVER['QUERY_STRING'], 'author=' ) !== false ) {
        $author_id = get_query_var( 'author' );
        if ( is_numeric( $author_id ) && $_SERVER['REQUEST_METHOD'] === 'GET' ) {
            $done = true;
            $path = '/?author=' . absint( $author_id );
            logsentinel_send([
                'event_type' => 'request',
                'method'     => 'GET',
                'path'       => $path,
                'resource'   => $path,
                'status'     => 'success',
                'message'    => "Enumeración de usuarios por ?author= desde " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown')
            ]);
        }
    }
});

// 12. ACCESO A ARCHIVOS SENSIBLES (404)
add_action( 'template_redirect', function() {
    static $done = false;
    if ( $done ) return;

    if ( ! is_404() ) return;

    $uri = $_SERVER['REQUEST_URI'] ?? '';
    $patterns = [ 'wp-config.php', '.env', 'debug.log', '.git/config', 'backup', 'database.sql', 'wp-config.bak' ];

    foreach ( $patterns as $p ) {
        if ( strpos( $uri, $p ) !== false ) {
            $done = true;
            logsentinel_send([
                'event_type'  => 'access',
                'method'      => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
                'path'        => $uri,
                'resource'    => $uri,
                'status'      => 'failure',
                'status_code' => 404,
                'message'     => "Intento de acceso a archivo sensible '{$uri}' desde " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown')
            ]);
            break;
        }
    }
});
