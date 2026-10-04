<?php

declare(strict_types=1);

require_once __DIR__ . '/admin_common.php';
require_once __DIR__ . '/admin_webauthn_common.php';

/* admin_passkey_list.php - GET, authenticated. Lists registered passkeys
   (never the key material itself) so the dashboard can show what's
   registered and let you remove a lost/old device. */

try {
    $config = nutricula_admin_load_config();
    nutricula_admin_start_session($config);
    nutricula_admin_require_auth();
    $conn = nutricula_admin_db($config);
    nutricula_webauthn_require_table($conn);

    $rows = [];
    $res = $conn->query('SELECT id, label, created_at, last_used_at FROM nutricula_admin_passkeys ORDER BY created_at DESC');
    while ($row = $res->fetch_assoc()) {
        $rows[] = [
            'id' => (int)$row['id'],
            'label' => (string)$row['label'],
            'created_at' => $row['created_at'],
            'last_used_at' => $row['last_used_at'],
        ];
    }
    $conn->close();

    nutricula_admin_send_json(['passkeys' => $rows]);

} catch (Throwable $e) {
    error_log('[Nutricula admin passkey list] ' . $e->getMessage());
    http_response_code(500);
    // Authenticated-only endpoint - safe to show the real reason (e.g. the
    // passkeys table not existing yet) instead of a generic message.
    nutricula_admin_send_json(['error' => $e instanceof WebAuthnError ? $e->getMessage() : 'Internal error.']);
}
