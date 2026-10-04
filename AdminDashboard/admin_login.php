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
        nutricula_admin_send_json(['error' => 'Too many attempts. Try again later.', 'code' => 'rate_limited']);
    }

    $body = nutricula_admin_json_body();
    $password = (string)($body['password'] ?? '');
    $captchaInput = trim((string)($body['captcha'] ?? ''));

    nutricula_admin_start_session($config);

    // CAPTCHA is required on the password path (never on fingerprint login,
    // which never calls this endpoint). One-time use: consumed from the
    // session the instant we read it, whether it turns out right or wrong,
    // so a captured request body can never be replayed against the same
    // code twice.
    $expectedCaptcha = (string)($_SESSION['nutricula_admin_captcha_code'] ?? '');
    unset($_SESSION['nutricula_admin_captcha_code']);
    if ($expectedCaptcha === '' || $captchaInput === '' || strcasecmp($captchaInput, $expectedCaptcha) !== 0) {
        nutricula_admin_audit($conn, 'login_failed', 'session', 'bad captcha');
        $conn->close();
        http_response_code(401);
        nutricula_admin_send_json(['error' => 'Security code is incorrect.', 'captcha_failed' => true, 'code' => 'bad_captcha']);
    }

    if ($password === '' || !password_verify($password, (string)$config['admin_password_hash'])) {
        nutricula_admin_audit($conn, 'login_failed', 'session', 'wrong password');
        $conn->close();
        http_response_code(401);
        nutricula_admin_send_json(['error' => 'Incorrect password.', 'code' => 'wrong_password']);
    }

    // Prevent session fixation - a fresh session ID on every successful
    // login, never reusing whatever (unauthenticated) session ID the
    // browser happened to show up with.
    session_regenerate_id(true);
    $_SESSION['nutricula_admin_authenticated'] = true;
    $_SESSION['nutricula_admin_last_activity'] = time();
    $_SESSION['nutricula_admin_csrf'] = bin2hex(random_bytes(32));
    $csrf = $_SESSION['nutricula_admin_csrf'];
    // Flush the session to disk NOW, before sending the response. The
    // dashboard fires several requests the instant it sees this response,
    // and on some shared hosts the session write otherwise only happens at
    // script shutdown - a hair's-width race that showed up only on mobile
    // (faster to fire the follow-up requests) as "login works for an
    // instant, then bounces back to the password screen".
    session_write_close();

    nutricula_admin_audit($conn, 'login_success', 'session', '');
    $conn->close();

    nutricula_admin_send_json(['ok' => true, 'csrf' => $csrf]);

} catch (Throwable $e) {
    error_log('[Nutricula admin login] ' . $e->getMessage());
    http_response_code(500);
    nutricula_admin_send_json(['error' => 'Internal error.', 'code' => 'internal_error']);
}
