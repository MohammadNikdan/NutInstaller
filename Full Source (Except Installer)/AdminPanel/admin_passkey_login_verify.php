<?php

declare(strict_types=1);

require_once __DIR__ . '/admin_common.php';
require_once __DIR__ . '/admin_webauthn_common.php';

/* admin_passkey_login_verify.php - POST, UNAUTHENTICATED. Body:
     { "rawId": "<b64url>",
       "response": { "clientDataJSON": "<b64url>", "authenticatorData": "<b64url>", "signature": "<b64url>" } }
   Verifies the assertion against the credential's stored public key and, on
   success, establishes exactly the same authenticated session
   admin_login.php does.

   This is an UNAUTHENTICATED endpoint, so unlike the registration side we
   deliberately do NOT echo precise WebAuthnError reasons back to the caller
   (that would hand an attacker a oracle for probing why their forged
   assertion failed) - every failure here logs the real reason server-side
   via error_log() and returns one generic message to the client. */

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

    nutricula_admin_start_session($config);

    $fail = function (string $reason) use ($conn): never {
        error_log('[Nutricula admin passkey login-verify] ' . $reason);
        try { nutricula_admin_audit($conn, 'passkey_login_failed', 'session', $reason); } catch (Throwable $e) { /* best effort */ }
        $conn->close();
        http_response_code(401);
        nutricula_admin_send_json(['error' => 'Passkey sign-in failed.']);
    };

    $challengeB64 = (string)($_SESSION['nutricula_admin_passkey_challenge'] ?? '');
    $challengeAt = (int)($_SESSION['nutricula_admin_passkey_challenge_at'] ?? 0);
    $purpose = (string)($_SESSION['nutricula_admin_passkey_challenge_purpose'] ?? '');
    if ($challengeB64 === '' || $purpose !== 'login' || (time() - $challengeAt) > 120) {
        $fail('no pending/expired login challenge');
    }

    $body = nutricula_admin_json_body();

    try {
        $rawId = nutricula_b64url_decode((string)($body['rawId'] ?? ''));
        $clientDataJSON = nutricula_b64url_decode((string)($body['response']['clientDataJSON'] ?? ''));
        $authenticatorData = nutricula_b64url_decode((string)($body['response']['authenticatorData'] ?? ''));
        $signature = nutricula_b64url_decode((string)($body['response']['signature'] ?? ''));

        nutricula_webauthn_check_client_data($clientDataJSON, 'webauthn.get', $challengeB64, nutricula_webauthn_origin());

        $stmt = $conn->prepare('SELECT id, pub_x, pub_y, sign_count FROM nutricula_admin_passkeys WHERE credential_id = ?');
        if (!$stmt) throw new \RuntimeException('prepare failed: ' . $conn->error);
        $stmt->bind_param('s', $rawId);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        if (!$row) throw new WebAuthnError('unknown credential_id');

        $parsed = nutricula_webauthn_parse_auth_data($authenticatorData);
        $expectedRpIdHash = hash('sha256', nutricula_webauthn_rp_id(), true);
        if (!hash_equals($expectedRpIdHash, $parsed['rpIdHash'])) throw new WebAuthnError('rpIdHash mismatch');
        if (!$parsed['userPresent'] || !$parsed['userVerified']) throw new WebAuthnError('authenticator did not report user verification');

        $storedCount = (int)$row['sign_count'];
        $newCount = $parsed['signCount'];
        if ($storedCount > 0 && $newCount <= $storedCount) {
            throw new WebAuthnError('sign count did not increase (possible cloned credential): stored=' . $storedCount . ' new=' . $newCount);
        }

        $pem = nutricula_webauthn_xy_to_pem((string)$row['pub_x'], (string)$row['pub_y']);
        $verifiedData = $authenticatorData . hash('sha256', $clientDataJSON, true);
        $ok = openssl_verify($verifiedData, $signature, $pem, OPENSSL_ALGO_SHA256);
        if ($ok !== 1) throw new WebAuthnError('signature verification failed (openssl_verify=' . var_export($ok, true) . ')');

        $upd = $conn->prepare('UPDATE nutricula_admin_passkeys SET sign_count = ?, last_used_at = NOW() WHERE id = ?');
        $upd->bind_param('ii', $newCount, $row['id']);
        $upd->execute();
        $upd->close();

    } catch (WebAuthnError $e) {
        $fail($e->getMessage());
    }

    // Success - same session bootstrap as a password login.
    session_regenerate_id(true);
    $_SESSION['nutricula_admin_authenticated'] = true;
    $_SESSION['nutricula_admin_last_activity'] = time();
    $_SESSION['nutricula_admin_csrf'] = bin2hex(random_bytes(32));
    unset($_SESSION['nutricula_admin_passkey_challenge'], $_SESSION['nutricula_admin_passkey_challenge_at'], $_SESSION['nutricula_admin_passkey_challenge_purpose']);
    $csrf = $_SESSION['nutricula_admin_csrf'];
    // Flush to disk now - see the matching comment in admin_login.php.
    session_write_close();

    nutricula_admin_audit($conn, 'passkey_login_success', 'session', '');
    $conn->close();

    nutricula_admin_send_json(['ok' => true, 'csrf' => $csrf]);

} catch (Throwable $e) {
    error_log('[Nutricula admin passkey login-verify] ' . $e->getMessage());
    http_response_code(500);
    nutricula_admin_send_json(['error' => 'Internal error.']);
}
