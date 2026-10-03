<?php

declare(strict_types=1);

require_once __DIR__ . '/admin_common.php';

/* admin_minus2.php - GET, authenticated.
   Query params (all optional): q (email/machine_id/device_key_hash,
   substring on email / exact on the 64-hex fields), reason_code,
   install_kind (free|licensed), days (how far back, default 30 - the log
   itself is pruned to MINUS2_LOG_RETENTION_DAYS=30 server-side anyway, so
   anything older simply won't be there), page (1-based), page_size (default
   50, max 200). */

try {
    $config = nutricula_admin_load_config();
    nutricula_admin_start_session($config);
    nutricula_admin_require_auth();
    $conn = nutricula_admin_db($config);

    $q = trim((string)($_GET['q'] ?? ''));
    $reasonCode = trim((string)($_GET['reason_code'] ?? ''));
    $installKind = trim((string)($_GET['install_kind'] ?? ''));
    if ($installKind !== 'free' && $installKind !== 'licensed') $installKind = '';
    $days = (int)($_GET['days'] ?? 30);
    if ($days < 1) $days = 1;
    if ($days > 365) $days = 365;
    $page = max(1, (int)($_GET['page'] ?? 1));
    $pageSize = (int)($_GET['page_size'] ?? 50);
    if ($pageSize < 1) $pageSize = 50;
    if ($pageSize > 200) $pageSize = 200;
    $offset = ($page - 1) * $pageSize;

    $where = ['occurred_at >= (NOW() - INTERVAL ? DAY)'];
    $types = 'i';
    $params = [$days];

    if ($reasonCode !== '') {
        $where[] = 'reason_code = ?';
        $types .= 's';
        $params[] = $reasonCode;
    }
    if ($installKind !== '') {
        $where[] = 'install_kind = ?';
        $types .= 's';
        $params[] = $installKind;
    }
    if ($q !== '') {
        if (preg_match('/\A[0-9A-Fa-f]{64}\z/', $q)) {
            $upper = strtoupper($q);
            $where[] = '(machine_id = ? OR machine_id_alt = ? OR device_public_key_hash = ?)';
            $types .= 'sss';
            $params[] = $upper; $params[] = $upper; $params[] = $upper;
        } else {
            $where[] = 'user_email LIKE ?';
            $types .= 's';
            $params[] = '%' . $q . '%';
        }
    }

    $whereSql = implode(' AND ', $where);

    $countStmt = $conn->prepare("SELECT COUNT(*) c FROM nutricula_minus2_log WHERE $whereSql");
    $countStmt->bind_param($types, ...$params);
    $countStmt->execute();
    $total = (int)($countStmt->get_result()->fetch_assoc()['c'] ?? 0);
    $countStmt->close();

    $listTypes = $types . 'ii';
    $listParams = $params;
    $listParams[] = $offset;
    $listParams[] = $pageSize;

    $stmt = $conn->prepare(
        "SELECT id, occurred_at, install_kind, reason_code, reason_detail, license_id, user_email,
                machine_id, machine_id_alt, device_public_key_hash, build_id, observed_ip, platform_profile
         FROM nutricula_minus2_log WHERE $whereSql
         ORDER BY occurred_at DESC
         LIMIT ?, ?"
    );
    $stmt->bind_param($listTypes, ...$listParams);
    $stmt->execute();
    $res = $stmt->get_result();
    $rows = [];
    while ($row = $res->fetch_assoc()) { $rows[] = $row; }
    $stmt->close();

    $conn->close();
    nutricula_admin_send_json([
        'total' => $total,
        'page' => $page,
        'page_size' => $pageSize,
        'rows' => $rows,
    ]);

} catch (Throwable $e) {
    error_log('[Nutricula admin minus2] ' . $e->getMessage());
    http_response_code(500);
    nutricula_admin_send_json(['error' => 'Internal error.']);
}
