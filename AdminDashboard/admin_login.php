<?php

declare(strict_types=1);

require_once __DIR__ . '/admin_common.php';

/* admin_login.php - POST { "password": "..." }
   On success: starts an authenticated session and returns a fresh CSRF
   token the frontend must send back (as X-Admin-CSRF) on every mutating
   request for the rest of this session. */

try {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        http_response_code(405);
        exit('Method not allowed.');
    }

    $config = nutricula_admin_load_config();
    $conn = nutricula_admin_db($config);

    if (!nutricula_admin_login_rate_ok($conn)) {
        $conn->close();
        http_response_code(429);
        nutricula_admin_send_json(['error' => 'Too many attempts. Try again later.']);
    }

    $body = nutricula_admin_json_body();
    $password = (string)($body['password'] ?? '');

    nutricula_admin_start_session($config);

    if ($password === '' || !password_verify($password, (string)$config['admin_password_hash'])) {
        nutricula_admin_audit($conn, 'login_failed', 'session', 'wrong password');
        $conn->close();
        http_response_code(401);
        nutricula_admin_send_json(['error' => 'Incorrect password.']);
    }

    // Prevent session fixation - a fresh session ID on every successful
    // login, never reusing whatever (unauthenticated) session ID the
    // browser happened to show up with.
    session_regenerate_id(true);
    $_SESSION['nutricula_admin_authenticated'] = true;
    $_SESSION['nutricula_admin_last_activity'] = time();
    $_SESSION['nutricula_admin_csrf'] = bin2hex(random_bytes(32));

    nutricula_admin_audit($conn, 'login_success', 'session', '');
    $conn->close();

    nutricula_admin_send_json(['ok' => true, 'csrf' => $_SESSION['nutricula_admin_csrf']]);

} catch (Throwable $e) {
    error_log('[Nutricula admin login] ' . $e->getMessage());
    http_response_code(500);
    nutricula_admin_send_json(['error' => 'Internal error.']);
}
