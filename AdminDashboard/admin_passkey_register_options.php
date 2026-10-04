<?php

declare(strict_types=1);

require_once __DIR__ . '/admin_common.php';
require_once __DIR__ . '/admin_webauthn_common.php';

/* admin_passkey_register_options.php - GET, authenticated (you must already
   be logged in with the password to register a new passkey - this is what
   stops anyone who doesn't know the password from just adding their own
   fingerprint to your panel). Returns a WebAuthn CredentialCreationOptions
   object for navigator.credentials.create(), and stashes the challenge (and
   its issue time) in the session for admin_passkey_register_verify.php to
   check against. */

try {
    $config = nutricula_admin_load_config();
    nutricula_admin_start_session($config);
    nutricula_admin_require_auth();
    $conn = nutricula_admin_db($config);
    nutricula_webauthn_require_table($conn);

    $existing = [];
    $res = $conn->query('SELECT credential_id FROM nutricula_admin_passkeys');
    while ($row = $res->fetch_assoc()) {
        $existing[] = ['id' => nutricula_b64url_encode((string)$row['credential_id']), 'type' => 'public-key'];
    }
    $conn->close();

    $challenge = random_bytes(32);
    $_SESSION['nutricula_admin_passkey_challenge'] = nutricula_b64url_encode($challenge);
    $_SESSION['nutricula_admin_passkey_challenge_at'] = time();
    $_SESSION['nutricula_admin_passkey_challenge_purpose'] = 'register';

    nutricula_admin_send_json([
        'challenge' => nutricula_b64url_encode($challenge),
        'rp' => ['id' => nutricula_webauthn_rp_id(), 'name' => 'Nutricula Admin Panel'],
        'user' => [
            'id' => nutricula_b64url_encode(random_bytes(16)),
            'name' => 'admin',
            'displayName' => 'Nutricula Admin',
        ],
        'pubKeyCredParams' => [['type' => 'public-key', 'alg' => -7]], // ES256 only - see admin_webauthn_common.php
        'authenticatorSelection' => [
            'authenticatorAttachment' => 'platform',
            'userVerification' => 'required',
            'residentKey' => 'discouraged',
        ],
        'attestation' => 'none',
        'timeout' => 60000,
        'excludeCredentials' => $existing,
    ]);

} catch (Throwable $e) {
    error_log('[Nutricula admin passkey register-options] ' . $e->getMessage());
    http_response_code(500);
    nutricula_admin_send_json(['error' => $e instanceof WebAuthnError ? $e->getMessage() : 'Internal error.']);
}
