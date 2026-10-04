<?php

declare(strict_types=1);

require_once __DIR__ . '/admin_common.php';

/* admin_search.php - GET ?q=<term>&scope=license|free|banned
   Free-text search: if $q looks like a UUID -> license_uuid; otherwise
   tried against user_email (LIKE), machine_id (exact, uppercased), and
   device_public_key_hash (exact, uppercased) across both premium licenses
   and free check-ins. scope narrows which of those are searched (default:
   both). scope=banned ignores $q and just lists everything currently
   banned, for the "manage bans" view.

   Pagination: page (1-based, default 1), page_size (default 50, max 200) -
   same pattern as admin_minus2.php. Applies to the licenses list, the
   free_devices list, and the banned list independently (each returns its
   own total/page/page_size alongside its rows), since a broad email-LIKE
   search can realistically return far more than fits on one screen. */

try {
    $config = nutricula_admin_load_config();
    nutricula_admin_start_session($config);
    nutricula_admin_require_auth();
    $conn = nutricula_admin_db($config);

    $scope = (string)($_GET['scope'] ?? 'all');
    if (!in_array($scope, ['all', 'license', 'free', 'banned'], true)) $scope = 'all';

    $page = max(1, (int)($_GET['page'] ?? 1));
    $pageSize = (int)($_GET['page_size'] ?? 50);
    if ($pageSize < 1) $pageSize = 50;
    if ($pageSize > 200) $pageSize = 200;
    $offset = ($page - 1) * $pageSize;

    if ($scope === 'banned') {
        $total = (int)($conn->query('SELECT COUNT(*) c FROM nutricula_banned_devices')->fetch_assoc()['c'] ?? 0);
        $stmt = $conn->prepare(
            'SELECT id, scope, license_id, machine_id, device_public_key_hash, user_email, reason, banned_at, banned_by
             FROM nutricula_banned_devices ORDER BY banned_at DESC LIMIT ?, ?'
        );
        $stmt->bind_param('ii', $offset, $pageSize);
        $stmt->execute();
        $res = $stmt->get_result();
        $rows = [];
        while ($row = $res->fetch_assoc()) { $rows[] = $row; }
        $stmt->close();
        $conn->close();
        nutricula_admin_send_json(['banned' => $rows, 'total' => $total, 'page' => $page, 'page_size' => $pageSize]);
    }

    $q = trim((string)($_GET['q'] ?? ''));
    if ($q === '') {
        $conn->close();
        nutricula_admin_send_json([
            'licenses' => [], 'licenses_total' => 0,
            'free_devices' => [], 'free_devices_total' => 0,
            'page' => $page, 'page_size' => $pageSize,
        ]);
    }
    if (strlen($q) > 320) $q = substr($q, 0, 320);

    $licenses = [];
    $licensesTotal = 0;
    if ($scope === 'all' || $scope === 'license') {
        if (nutricula_is_valid_uuid($q)) {
            $whereSql = 'license_uuid = ?';
            $types = 's';
            $params = [$q];
        } elseif (preg_match('/\A[0-9A-Fa-f]{64}\z/', $q)) {
            $upper = strtoupper($q);
            $whereSql = '(machine_id = ? OR device_public_key_hash = ?)';
            $types = 'ss';
            $params = [$upper, $upper];
        } else {
            $whereSql = 'user_email LIKE ?';
            $types = 's';
            $params = ['%' . $conn->real_escape_string($q) . '%'];
        }

        $countStmt = $conn->prepare("SELECT COUNT(*) c FROM nutricula_licenses WHERE $whereSql");
        $countStmt->bind_param($types, ...$params);
        $countStmt->execute();
        $licensesTotal = (int)($countStmt->get_result()->fetch_assoc()['c'] ?? 0);
        $countStmt->close();

        $listParams = $params;
        $listParams[] = $offset;
        $listParams[] = $pageSize;
        $stmt = $conn->prepare(
            "SELECT id, license_uuid, user_email, product_name, device_type, status,
                    machine_id, device_public_key_hash, last_seen_at, created_at, license_expires_at
             FROM nutricula_licenses WHERE $whereSql
             ORDER BY created_at DESC LIMIT ?, ?"
        );
        $stmt->bind_param($types . 'ii', ...$listParams);
        $stmt->execute();
        $res = $stmt->get_result();
        while ($row = $res->fetch_assoc()) { $licenses[] = $row; }
        $stmt->close();
    }

    $freeDevices = [];
    $freeDevicesTotal = 0;
    if (($scope === 'all' || $scope === 'free') && preg_match('/\A[0-9A-Fa-f]{64}\z/', $q)) {
        $upper = strtoupper($q);
        $countStmt = $conn->prepare(
            'SELECT COUNT(*) c FROM nutricula_unlicensed_checkins WHERE machine_id = ? OR device_public_key_hash = ?'
        );
        $countStmt->bind_param('ss', $upper, $upper);
        $countStmt->execute();
        $freeDevicesTotal = (int)($countStmt->get_result()->fetch_assoc()['c'] ?? 0);
        $countStmt->close();

        $stmt = $conn->prepare(
            'SELECT id, machine_id, device_public_key_hash, platform_profile, first_seen_at, last_seen_at
             FROM nutricula_unlicensed_checkins WHERE machine_id = ? OR device_public_key_hash = ?
             ORDER BY last_seen_at DESC LIMIT ?, ?'
        );
        $stmt->bind_param('ssii', $upper, $upper, $offset, $pageSize);
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
    nutricula_admin_send_json([
        'licenses' => $licenses, 'licenses_total' => $licensesTotal,
        'free_devices' => $freeDevices, 'free_devices_total' => $freeDevicesTotal,
        'page' => $page, 'page_size' => $pageSize,
    ]);

} catch (Throwable $e) {
    error_log('[Nutricula admin search] ' . $e->getMessage());
    http_response_code(500);
    nutricula_admin_send_json(['error' => 'Internal error.']);
}
