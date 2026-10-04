<?php

declare(strict_types=1);

require_once __DIR__ . '/admin_common.php';
require_once __DIR__ . '/admin_webauthn_common.php';

/* admin_passkey_login_options.php - POST, UNAUTHENTICATED (this is the whole
   point - it lets a registered device sign in without the password). Shares
   the same login attempt throttle as admin_login.php (same rate_key prefix),
   so a passkey try and a password try both draw from the one 8-per-15-min
   budget. Returns an empty list (not an error) when nothing is registered
   yet, so the frontend can just hide the "sign in with fingerprint" button. */

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

    // If the passkeys table hasn't been created yet, that's the same as
    // "nothing registered" from this unauthenticated endpoint's point of
    // view - report unavailable rather than a 500 (and never hint at a
    // missing table to an unauthenticated caller either way).
    $tableCheck = $conn->query("SHOW TABLES LIKE 'nutricula_admin_passkeys'");
    if (!$tableCheck || $tableCheck->num_rows === 0) {
        $conn->close();
        nutricula_admin_send_json(['available' => false]);
    }

    $allow = [];
    $res = $conn->query('SELECT credential_id FROM nutricula_admin_passkeys');
    while ($row = $res->fetch_assoc()) {
        $allow[] = ['id' => nutricula_b64url_encode((string)$row['credential_id']), 'type' => 'public-key', 'transports' => ['internal']];
    }
    $conn->close();

    if (!$allow) {
        nutricula_admin_send_json(['available' => false]);
    }

    nutricula_admin_start_session($config);
    $challenge = random_bytes(32);
    $_SESSION['nutricula_admin_passkey_challenge'] = nutricula_b64url_encode($challenge);
    $_SESSION['nutricula_admin_passkey_challenge_at'] = time();
    $_SESSION['nutricula_admin_passkey_challenge_purpose'] = 'login';

    nutricula_admin_send_json([
        'available' => true,
        'challenge' => nutricula_b64url_encode($challenge),
        'rpId' => nutricula_webauthn_rp_id(),
        'allowCredentials' => $allow,
        'userVerification' => 'required',
        'timeout' => 60000,
    ]);

} catch (Throwable $e) {
    error_log('[Nutricula admin passkey login-options] ' . $e->getMessage());
    http_response_code(500);
    nutricula_admin_send_json(['error' => 'Internal error.']);
}
