<?php

declare(strict_types=1);

require_once __DIR__ . '/admin_common.php';

/* admin_session.php - GET, called once when the PWA page (re)loads, to find
   out whether the browser already has a valid session (so the dashboard can
   be shown directly instead of the login screen) and to hand the frontend
   the CSRF token for this session (a page reload loses whatever copy
   JavaScript had in memory, but the token itself is unchanged server-side -
   returning the existing one here, rather than rotating it, means a second
   open tab doesn't get silently logged out of mutating actions). */

try {
    $config = nutricula_admin_load_config();
    nutricula_admin_start_session($config);

    if (empty($_SESSION['nutricula_admin_authenticated'])) {
        nutricula_admin_send_json(['authenticated' => false]);
    }

    $lastActivity = (int)($_SESSION['nutricula_admin_last_activity'] ?? 0);
    if ($lastActivity > 0 && (time() - $lastActivity) > 12 * 3600) {
        $_SESSION = [];
        session_destroy();
        nutricula_admin_send_json(['authenticated' => false]);
    }
    $_SESSION['nutricula_admin_last_activity'] = time();

    nutricula_admin_send_json(['authenticated' => true, 'csrf' => (string)($_SESSION['nutricula_admin_csrf'] ?? '')]);
} catch (Throwable $e) {
    error_log('[Nutricula admin session] ' . $e->getMessage());
    nutricula_admin_send_json(['authenticated' => false]);
}
