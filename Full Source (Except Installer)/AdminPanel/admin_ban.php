<?php

declare(strict_types=1);

require_once __DIR__ . '/admin_common.php';

/* admin_ban.php - POST, authenticated + CSRF-protected.
   Body: { "action": "ban"|"unban", "scope": "license"|"free_device",
           "license_id": <int, scope=license>,
           "machine_id": "<64 hex>", "device_key_hash": "<64 hex>" (scope=free_device, either or both),
           "reason": "<free text, scope=license ban only>" }
   Enforcement itself (license_check.php's nutricula_is_banned() calls) is
   completely independent of this file - this just maintains the table that
   function reads. */

try {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        http_response_code(405);
        exit('Method not allowed.');
    }

    $config = nutricula_admin_load_config();
    nutricula_admin_start_session($config);
    nutricula_admin_require_auth();
    nutricula_admin_require_csrf();
    $conn = nutricula_admin_db($config);

    $body = nutricula_admin_json_body();
    $action = (string)($body['action'] ?? '');
    $scope = (string)($body['scope'] ?? '');
    if (!in_array($action, ['ban', 'unban'], true)) throw new RuntimeException('Invalid action.');
    if (!in_array($scope, ['license', 'free_device'], true)) throw new RuntimeException('Invalid scope.');

    if ($scope === 'license') {
        $licenseId = (int)($body['license_id'] ?? 0);
        if ($licenseId <= 0) throw new RuntimeException('license_id is required.');

        if ($action === 'unban') {
            $stmt = $conn->prepare('DELETE FROM nutricula_banned_devices WHERE license_id = ?');
            $stmt->bind_param('i', $licenseId);
            $stmt->execute();
            $stmt->close();
            nutricula_admin_audit($conn, 'unban', 'license', 'license_id=' . $licenseId);
            $conn->close();
            nutricula_admin_send_json(['ok' => true]);
        }

        $stmt = $conn->prepare('SELECT user_email FROM nutricula_licenses WHERE id = ? LIMIT 1');
        $stmt->bind_param('i', $licenseId);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        if (!$row) throw new RuntimeException('License not found.');
        $email = (string)$row['user_email'];
        $reason = trim((string)($body['reason'] ?? ''));
        if (strlen($reason) > 255) $reason = substr($reason, 0, 255);
        $reason = $reason !== '' ? $reason : null;
        $bannedBy = 'admin';

        $stmt = $conn->prepare(
            'INSERT INTO nutricula_banned_devices (scope, license_id, user_email, reason, banned_at, banned_by)
             VALUES (\'license\', ?, ?, ?, NOW(), ?)
             ON DUPLICATE KEY UPDATE reason = VALUES(reason), banned_at = NOW(), banned_by = VALUES(banned_by)'
        );
        $stmt->bind_param('isss', $licenseId, $email, $reason, $bannedBy);
        $stmt->execute();
        $stmt->close();
        nutricula_admin_audit($conn, 'ban', 'license', 'license_id=' . $licenseId . ' email=' . $email);
        $conn->close();
        nutricula_admin_send_json(['ok' => true]);
    }

    // scope === 'free_device'
    $machineId = strtoupper(trim((string)($body['machine_id'] ?? '')));
    $deviceKeyHash = strtoupper(trim((string)($body['device_key_hash'] ?? '')));
    $machineId = ($machineId !== '' && preg_match('/\A[0-9A-F]{64}\z/', $machineId)) ? $machineId : null;
    $deviceKeyHash = ($deviceKeyHash !== '' && preg_match('/\A[0-9A-F]{64}\z/', $deviceKeyHash)) ? $deviceKeyHash : null;
    if ($machineId === null && $deviceKeyHash === null) {
        throw new RuntimeException('machine_id or device_key_hash (64 hex chars) is required.');
    }
    // NOTE: nutricula_banned_devices has a separate UNIQUE key on each of
    // machine_id and device_public_key_hash. In the rare case where this
    // request's machine_id collides with one existing row while its
    // device_key_hash independently collides with a DIFFERENT existing row,
    // ON DUPLICATE KEY UPDATE below only resolves one of the two conflicts -
    // acceptable for a single-admin internal tool; a failed insert here
    // simply surfaces as a 400 the admin can retry with one identifier at a
    // time.

    if ($action === 'unban') {
        $stmt = $conn->prepare('DELETE FROM nutricula_banned_devices WHERE machine_id = ? OR device_public_key_hash = ?');
        $mid = $machineId ?? '';
        $dkh = $deviceKeyHash ?? '';
        $stmt->bind_param('ss', $mid, $dkh);
        $stmt->execute();
        $stmt->close();
        nutricula_admin_audit($conn, 'unban', 'free_device', 'machine_id=' . ($machineId ?? '') . ' device_key_hash=' . ($deviceKeyHash ?? ''));
        $conn->close();
        nutricula_admin_send_json(['ok' => true]);
    }

    $reason = trim((string)($body['reason'] ?? ''));
    if (strlen($reason) > 255) $reason = substr($reason, 0, 255);
    $reason = $reason !== '' ? $reason : null;
    $bannedBy = 'admin';

    $stmt = $conn->prepare(
        'INSERT INTO nutricula_banned_devices (scope, machine_id, device_public_key_hash, reason, banned_at, banned_by)
         VALUES (\'free_device\', ?, ?, ?, NOW(), ?)
         ON DUPLICATE KEY UPDATE reason = VALUES(reason), banned_at = NOW(), banned_by = VALUES(banned_by)'
    );
    $stmt->bind_param('ssss', $machineId, $deviceKeyHash, $reason, $bannedBy);
    $stmt->execute();
    $stmt->close();
    nutricula_admin_audit($conn, 'ban', 'free_device', 'machine_id=' . ($machineId ?? '') . ' device_key_hash=' . ($deviceKeyHash ?? ''));
    $conn->close();
    nutricula_admin_send_json(['ok' => true]);

} catch (Throwable $e) {
    error_log('[Nutricula admin ban] ' . $e->getMessage());
    http_response_code(400);
    nutricula_admin_send_json(['error' => $e->getMessage()]);
}
