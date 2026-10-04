<?php

declare(strict_types=1);

require_once __DIR__ . '/admin_common.php';
require_once __DIR__ . '/admin_webauthn_common.php';

/* admin_passkey_delete.php - POST, authenticated + CSRF. Body: { "id": 1 }
   Removing every registered passkey never locks you out - the password
   login always keeps working regardless. */

try {
    $config = nutricula_admin_load_config();
    nutricula_admin_start_session($config);
    nutricula_admin_require_auth();
    nutricula_admin_require_csrf();
    $conn = nutricula_admin_db($config);
    nutricula_webauthn_require_table($conn);

    $body = nutricula_admin_json_body();
    $id = (int)($body['id'] ?? 0);
    if ($id <= 0) {
        $conn->close();
        http_response_code(400);
        nutricula_admin_send_json(['error' => 'Invalid id.']);
    }

    $stmt = $conn->prepare('SELECT label FROM nutricula_admin_passkeys WHERE id = ?');
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    $stmt = $conn->prepare('DELETE FROM nutricula_admin_passkeys WHERE id = ?');
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $deleted = $stmt->affected_rows > 0;
    $stmt->close();

    if ($deleted) {
        nutricula_admin_audit($conn, 'passkey_deleted', 'passkey', $row['label'] ?? ('id=' . $id));
    }
    $conn->close();

    nutricula_admin_send_json(['ok' => true, 'deleted' => $deleted]);

} catch (Throwable $e) {
    error_log('[Nutricula admin passkey delete] ' . $e->getMessage());
    http_response_code(500);
    nutricula_admin_send_json(['error' => $e instanceof WebAuthnError ? $e->getMessage() : 'Internal error.']);
}
