<?php

declare(strict_types=1);

require_once __DIR__ . '/admin_common.php';

/* admin_search.php - GET ?q=<term>&scope=license|free|banned
   Free-text search: if $q looks like a UUID -> license_uuid; otherwise
   tried against user_email (LIKE), machine_id (exact, uppercased), and
   device_public_key_hash (exact, uppercased) across both premium licenses
   and free check-ins. scope narrows which of those are searched (default:
   both). scope=banned ignores $q and just lists everything currently
   banned, for the "manage bans" view. */

try {
    $config = nutricula_admin_load_config();
    nutricula_admin_start_session($config);
    nutricula_admin_require_auth();
    $conn = nutricula_admin_db($config);

    $scope = (string)($_GET['scope'] ?? 'all');
    if (!in_array($scope, ['all', 'license', 'free', 'banned'], true)) $scope = 'all';

    if ($scope === 'banned') {
        $rows = [];
        $res = $conn->query(
            'SELECT id, scope, license_id, machine_id, device_public_key_hash, user_email, reason, banned_at, banned_by
             FROM nutricula_banned_devices ORDER BY banned_at DESC LIMIT 500'
        );
        while ($row = $res->fetch_assoc()) { $rows[] = $row; }
        $conn->close();
        nutricula_admin_send_json(['banned' => $rows]);
    }

    $q = trim((string)($_GET['q'] ?? ''));
    if ($q === '') {
        $conn->close();
        nutricula_admin_send_json(['licenses' => [], 'free_devices' => []]);
    }
    if (strlen($q) > 320) $q = substr($q, 0, 320);

    $licenses = [];
    if ($scope === 'all' || $scope === 'license') {
        if (nutricula_is_valid_uuid($q)) {
            $stmt = $conn->prepare(
                'SELECT id, license_uuid, user_email, product_name, device_type, status,
                        machine_id, device_public_key_hash, last_seen_at, created_at, license_expires_at
                 FROM nutricula_licenses WHERE license_uuid = ? LIMIT 50'
            );
            $stmt->bind_param('s', $q);
        } elseif (preg_match('/\A[0-9A-Fa-f]{64}\z/', $q)) {
            $upper = strtoupper($q);
            $stmt = $conn->prepare(
                'SELECT id, license_uuid, user_email, product_name, device_type, status,
                        machine_id, device_public_key_hash, last_seen_at, created_at, license_expires_at
                 FROM nutricula_licenses WHERE machine_id = ? OR device_public_key_hash = ? LIMIT 50'
            );
            $stmt->bind_param('ss', $upper, $upper);
        } else {
            $like = '%' . $conn->real_escape_string($q) . '%';
            $stmt = $conn->prepare(
                'SELECT id, license_uuid, user_email, product_name, device_type, status,
                        machine_id, device_public_key_hash, last_seen_at, created_at, license_expires_at
                 FROM nutricula_licenses WHERE user_email LIKE ? LIMIT 50'
            );
            $stmt->bind_param('s', $like);
        }
        $stmt->execute();
        $res = $stmt->get_result();
        while ($row = $res->fetch_assoc()) { $licenses[] = $row; }
        $stmt->close();
    }

    $freeDevices = [];
    if (($scope === 'all' || $scope === 'free') && preg_match('/\A[0-9A-Fa-f]{64}\z/', $q)) {
        $upper = strtoupper($q);
        $stmt = $conn->prepare(
            'SELECT id, machine_id, device_public_key_hash, platform_profile, first_seen_at, last_seen_at
             FROM nutricula_unlicensed_checkins WHERE machine_id = ? OR device_public_key_hash = ? LIMIT 50'
        );
        $stmt->bind_param('ss', $upper, $upper);
        $stmt->execute();
        $res = $stmt->get_result();
        while ($row = $res->fetch_assoc()) { $freeDevices[] = $row; }
        $stmt->close();
    }

    // Attach current ban status to each result so the frontend can show a
    // single ban/unban toggle without a second round trip.
    $banLookup = function (array $rows, string $keyCol, bool $byLicense) use ($conn): array {
        foreach ($rows as &$row) {
            if ($byLicense) {
                $stmt = $conn->prepare('SELECT id FROM nutricula_banned_devices WHERE license_id = ? LIMIT 1');
                $stmt->bind_param('i', $row['id']);
            } else {
                $stmt = $conn->prepare('SELECT id FROM nutricula_banned_devices WHERE machine_id = ? OR device_public_key_hash = ? LIMIT 1');
                $mid = (string)$row['machine_id'];
                $dkh = (string)$row['device_public_key_hash'];
                $stmt->bind_param('ss', $mid, $dkh);
            }
            $stmt->execute();
            $row['banned'] = $stmt->get_result()->fetch_assoc() !== null;
            $stmt->close();
        }
        return $rows;
    };
    $licenses = $banLookup($licenses, 'id', true);
    $freeDevices = $banLookup($freeDevices, 'machine_id', false);

    $conn->close();
    nutricula_admin_send_json(['licenses' => $licenses, 'free_devices' => $freeDevices]);

} catch (Throwable $e) {
    error_log('[Nutricula admin search] ' . $e->getMessage());
    http_response_code(500);
    nutricula_admin_send_json(['error' => 'Internal error.']);
}
