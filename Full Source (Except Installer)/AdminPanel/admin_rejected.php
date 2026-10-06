<?php

declare(strict_types=1);

require_once __DIR__ . '/admin_common.php';

/* admin_rejected.php - GET, authenticated.
   Devices whose free_checkin FAILED full validation (banned, outdated or
   tampered install) - nutricula_rejected_checkins, written by
   nutricula_track_rejected_checkin() in license_common.php. They are NOT in
   nutricula_unlicensed_checkins (that table holds only fully verified free
   installs), so this is where "who is still on an old version / who keeps
   coming back with modified files / who is banned and still trying" is read.

   Query params (all optional): q (64-hex machine_id or device_key_hash,
   exact), reason (banned|update_required|artifact_mismatch - matches the
   MOST RECENT reason), days (activity window by last_seen_at, default 30,
   max 365 - rows are pruned server-side after 90 days of silence anyway),
   page (1-based), page_size (default 50, max 200).
   Response: total, page, page_size, rows, and `summary` = number of devices
   per most-recent reason within the window (ignores the reason filter, so the
   counts stay visible while filtering), with each row's ban status attached
   like admin_search.php does so the panel can show a ban/unban toggle. */

try {
    $config = nutricula_admin_load_config();
    nutricula_admin_start_session($config);
    nutricula_admin_require_auth();
    $conn = nutricula_admin_db($config);

    $q = trim((string)($_GET['q'] ?? ''));
    $reason = trim((string)($_GET['reason'] ?? ''));
    if (!in_array($reason, ['banned', 'update_required', 'artifact_mismatch'], true)) $reason = '';
    $days = (int)($_GET['days'] ?? 30);
    if ($days < 1) $days = 1;
    if ($days > 365) $days = 365;
    $page = max(1, (int)($_GET['page'] ?? 1));
    $pageSize = (int)($_GET['page_size'] ?? 50);
    if ($pageSize < 1) $pageSize = 50;
    if ($pageSize > 200) $pageSize = 200;
    $offset = ($page - 1) * $pageSize;

    $baseWhere = ['last_seen_at >= (NOW() - INTERVAL ? DAY)'];
    $baseTypes = 'i';
    $baseParams = [$days];
    if ($q !== '') {
        if (!preg_match('/\A[0-9A-Fa-f]{64}\z/', $q)) {
            $conn->close();
            nutricula_admin_send_json(['total' => 0, 'page' => $page, 'page_size' => $pageSize, 'rows' => [], 'summary' => new stdClass()]);
        }
        $upper = strtoupper($q);
        $baseWhere[] = '(machine_id = ? OR device_public_key_hash = ?)';
        $baseTypes .= 'ss';
        $baseParams[] = $upper; $baseParams[] = $upper;
    }

    // Per-reason summary (reason filter deliberately NOT applied).
    $summary = ['banned' => 0, 'update_required' => 0, 'artifact_mismatch' => 0];
    $stmt = $conn->prepare('SELECT last_reason, COUNT(*) c FROM nutricula_rejected_checkins WHERE ' . implode(' AND ', $baseWhere) . ' GROUP BY last_reason');
    $stmt->bind_param($baseTypes, ...$baseParams);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($r = $res->fetch_assoc()) {
        if (array_key_exists($r['last_reason'], $summary)) $summary[$r['last_reason']] = (int)$r['c'];
    }
    $stmt->close();

    $where = $baseWhere; $types = $baseTypes; $params = $baseParams;
    if ($reason !== '') {
        $where[] = 'last_reason = ?';
        $types .= 's';
        $params[] = $reason;
    }
    $whereSql = implode(' AND ', $where);

    $countStmt = $conn->prepare("SELECT COUNT(*) c FROM nutricula_rejected_checkins WHERE $whereSql");
    $countStmt->bind_param($types, ...$params);
    $countStmt->execute();
    $total = (int)($countStmt->get_result()->fetch_assoc()['c'] ?? 0);
    $countStmt->close();

    $listParams = $params; $listParams[] = $offset; $listParams[] = $pageSize;
    $stmt = $conn->prepare(
        "SELECT id, machine_id, device_public_key_hash, first_seen_at, last_seen_at, last_reason,
                banned_count, update_required_count, artifact_mismatch_count,
                platform_profile, last_build_id, last_observed_ip
         FROM nutricula_rejected_checkins WHERE $whereSql
         ORDER BY last_seen_at DESC
         LIMIT ?, ?"
    );
    $stmt->bind_param($types . 'ii', ...$listParams);
    $stmt->execute();
    $res = $stmt->get_result();
    $rows = [];
    while ($row = $res->fetch_assoc()) { $rows[] = $row; }
    $stmt->close();

    // Current ban status per row - same lookup admin_search.php uses for free devices.
    foreach ($rows as &$row) {
        $stmt = $conn->prepare('SELECT id FROM nutricula_banned_devices WHERE machine_id = ? OR device_public_key_hash = ? LIMIT 1');
        $mid = (string)$row['machine_id'];
        $dkh = (string)$row['device_public_key_hash'];
        $stmt->bind_param('ss', $mid, $dkh);
        $stmt->execute();
        $row['banned'] = $stmt->get_result()->fetch_assoc() !== null;
        $stmt->close();
    }
    unset($row);

    $conn->close();
    nutricula_admin_send_json([
        'total' => $total,
        'page' => $page,
        'page_size' => $pageSize,
        'rows' => $rows,
        'summary' => $summary,
    ]);

} catch (Throwable $e) {
    error_log('[Nutricula admin rejected] ' . $e->getMessage());
    http_response_code(500);
    nutricula_admin_send_json(['error' => 'Internal error.']);
}
