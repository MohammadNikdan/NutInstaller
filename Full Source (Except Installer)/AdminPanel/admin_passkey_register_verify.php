<?php

declare(strict_types=1);

require_once __DIR__ . '/admin_common.php';
require_once __DIR__ . '/admin_webauthn_common.php';

/* admin_passkey_register_verify.php - POST, authenticated + CSRF. Body:
     { "rawId": "<b64url>", "label": "...",
       "response": { "clientDataJSON": "<b64url>", "attestationObject": "<b64url>" } }
   This is the authenticated counterpart to register_options.php: verifies
   the browser's attestation response against the challenge we just issued,
   pulls the ES256 public key out of it, and stores the new credential. */

try {
    $config = nutricula_admin_load_config();
    nutricula_admin_start_session($config);
    nutricula_admin_require_auth();
    nutricula_admin_require_csrf();
    $conn = nutricula_admin_db($config);

    $challengeB64 = (string)($_SESSION['nutricula_admin_passkey_challenge'] ?? '');
    $challengeAt = (int)($_SESSION['nutricula_admin_passkey_challenge_at'] ?? 0);
    $purpose = (string)($_SESSION['nutricula_admin_passkey_challenge_purpose'] ?? '');
    if ($challengeB64 === '' || $purpose !== 'register' || (time() - $challengeAt) > 300) {
        throw new WebAuthnError('No pending registration, or it expired - start over.');
    }

    $body = nutricula_admin_json_body();
    $label = trim((string)($body['label'] ?? ''));
    if ($label === '') $label = 'دستگاه بدون نام';
    if (mb_strlen($label) > 100) $label = mb_substr($label, 0, 100);

    $clientDataJSON = nutricula_b64url_decode((string)($body['response']['clientDataJSON'] ?? ''));
    $attestationObject = nutricula_b64url_decode((string)($body['response']['attestationObject'] ?? ''));

    nutricula_webauthn_check_client_data($clientDataJSON, 'webauthn.create', $challengeB64, nutricula_webauthn_origin());

    $pos = 0;
    $attMap = MiniCbor::decode($attestationObject, $pos);
    if (!is_array($attMap) || !isset($attMap['authData'])) {
        throw new WebAuthnError('attestationObject missing authData.');
    }
    $parsed = nutricula_webauthn_parse_auth_data((string)$attMap['authData']);

    $expectedRpIdHash = hash('sha256', nutricula_webauthn_rp_id(), true);
    if (!hash_equals($expectedRpIdHash, $parsed['rpIdHash'])) {
        throw new WebAuthnError('rpIdHash mismatch - this credential was not created for this exact site.');
    }
    if (!$parsed['userPresent'] || !$parsed['userVerified']) {
        throw new WebAuthnError('The authenticator did not report user verification (fingerprint) for this registration.');
    }
    if ($parsed['credentialId'] === null || $parsed['cosePublicKey'] === null) {
        throw new WebAuthnError('No attested credential data in authenticatorData.');
    }

    [$x, $y] = nutricula_webauthn_cose_to_xy($parsed['cosePublicKey']);
    // Validates the key is actually usable before we store it.
    nutricula_webauthn_xy_to_pem($x, $y);

    $credentialId = $parsed['credentialId'];

    $stmt = $conn->prepare(
        'INSERT INTO nutricula_admin_passkeys (credential_id, pub_x, pub_y, sign_count, label, created_at)
         VALUES (?, ?, ?, ?, ?, NOW())'
    );
    if (!$stmt) throw new \RuntimeException('Failed to prepare insert: ' . $conn->error);
    $signCount = $parsed['signCount'];
    $stmt->bind_param('sssis', $credentialId, $x, $y, $signCount, $label);
    if (!$stmt->execute()) {
        $stmt->close();
        if ($conn->errno === 1062) throw new WebAuthnError('This device is already registered.');
        throw new \RuntimeException('Failed to store credential: ' . $conn->error);
    }
    $newId = $stmt->insert_id;
    $stmt->close();

    nutricula_admin_audit($conn, 'passkey_registered', 'passkey', $label);
    $conn->close();

    unset($_SESSION['nutricula_admin_passkey_challenge'], $_SESSION['nutricula_admin_passkey_challenge_at'], $_SESSION['nutricula_admin_passkey_challenge_purpose']);

    nutricula_admin_send_json(['ok' => true, 'id' => $newId, 'label' => $label]);

} catch (WebAuthnError $e) {
    // Authenticated endpoint - safe to return the precise reason so you can
    // actually debug a failed registration on your own device.
    http_response_code(400);
    nutricula_admin_send_json(['error' => $e->getMessage()]);
} catch (Throwable $e) {
    error_log('[Nutricula admin passkey register-verify] ' . $e->getMessage());
    http_response_code(500);
    nutricula_admin_send_json(['error' => 'Internal error.', 'debug' => $e->getMessage()]);
}
