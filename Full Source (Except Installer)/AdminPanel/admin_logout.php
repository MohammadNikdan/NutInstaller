<?php

declare(strict_types=1);

require_once __DIR__ . '/admin_common.php';

try {
    $config = nutricula_admin_load_config();
    nutricula_admin_start_session($config);
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
    nutricula_admin_send_json(['ok' => true]);
} catch (Throwable $e) {
    error_log('[Nutricula admin logout] ' . $e->getMessage());
    nutricula_admin_send_json(['ok' => true]); // logging out never fails from the user's perspective
}
