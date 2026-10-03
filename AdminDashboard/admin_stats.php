<?php

declare(strict_types=1);

require_once __DIR__ . '/admin_common.php';

/* admin_stats.php - GET, authenticated. Query params:
     days        = activity window in days, for "active in the last N days"
                   and for the "inactive" complement (default 30).
     growth_days = how far back the growth chart goes (default 90).
   Returns one big JSON blob with everything the dashboard's summary cards,
   percentage view, OS breakdown, growth chart and server-load chart need -
   one request, one round trip, so the "update" button and the 60-second
   auto-refresh are each a single fetch. */

try {
    $config = nutricula_admin_load_config();
    nutricula_admin_start_session($config);
    nutricula_admin_require_auth();
    $conn = nutricula_admin_db($config);

    $days = (int)($_GET['days'] ?? 30);
    if ($days < 1) $days = 1;
    if ($days > 3650) $days = 3650;

    $growthDays = (int)($_GET['growth_days'] ?? 90);
    if ($growthDays < 7) $growthDays = 7;
    if ($growthDays > 1095) $growthDays = 1095;

    $result = [
        'generated_at' => gmdate('c'),
        'window_days' => $days,
    ];

    // ------------------------------------------------------------------
    // Summary counts
    // ------------------------------------------------------------------
    $scalar = function (string $sql, array $types = [], array $params = []) use ($conn): int {
        $stmt = $conn->prepare($sql);
        if (!$stmt) return 0;
        if ($types) $stmt->bind_param(implode('', $types), ...$params);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_row();
        $stmt->close();
        return $row ? (int)$row[0] : 0;
    };

    $freeActive = $scalar(
        'SELECT COUNT(*) FROM nutricula_unlicensed_checkins WHERE last_seen_at >= (NOW() - INTERVAL ? DAY)',
        ['i'], [$days]
    );
    $premiumActive = $scalar(
        "SELECT COUNT(*) FROM nutricula_licenses WHERE status='active' AND last_seen_at IS NOT NULL AND last_seen_at >= (NOW() - INTERVAL ? DAY)",
        ['i'], [$days]
    );
    $freeNew24h = $scalar('SELECT COUNT(*) FROM nutricula_unlicensed_checkins WHERE first_seen_at >= (NOW() - INTERVAL 1 DAY)');
    $premiumNew24h = $scalar('SELECT COUNT(*) FROM nutricula_licenses WHERE created_at >= (NOW() - INTERVAL 1 DAY)');
    $freeNew7d = $scalar('SELECT COUNT(*) FROM nutricula_unlicensed_checkins WHERE first_seen_at >= (NOW() - INTERVAL 7 DAY)');
    $premiumNew7d = $scalar('SELECT COUNT(*) FROM nutricula_licenses WHERE created_at >= (NOW() - INTERVAL 7 DAY)');

    $freeEverTotal = $scalar('SELECT COUNT(*) FROM nutricula_unlicensed_checkins');
    $premiumEverTotal = $scalar('SELECT COUNT(*) FROM nutricula_licenses');
    $everTotal = $freeEverTotal + $premiumEverTotal;
    $activeTotal = $freeActive + $premiumActive;
    $inactiveTotal = max(0, $everTotal - $activeTotal);

    $pct = function (int $part, int $whole): float {
        return $whole > 0 ? round(($part / $whole) * 100, 1) : 0.0;
    };

    $result['summary'] = [
        'free_active_window' => $freeActive,
        'premium_active_window' => $premiumActive,
        'total_active_window' => $activeTotal,
        'free_new_24h' => $freeNew24h,
        'premium_new_24h' => $premiumNew24h,
        'total_new_24h' => $freeNew24h + $premiumNew24h,
        'free_new_7d' => $freeNew7d,
        'premium_new_7d' => $premiumNew7d,
        'total_new_7d' => $freeNew7d + $premiumNew7d,
        'free_ever_total' => $freeEverTotal,
        'premium_ever_total' => $premiumEverTotal,
        'ever_total' => $everTotal,
        'inactive_ever_total' => $inactiveTotal,
        'percentages' => [
            'free_of_active' => $pct($freeActive, $activeTotal),
            'premium_of_active' => $pct($premiumActive, $activeTotal),
            'free_of_ever' => $pct($freeEverTotal, $everTotal),
            'premium_of_ever' => $pct($premiumEverTotal, $everTotal),
            'active_of_ever' => $pct($activeTotal, $everTotal),
            'inactive_of_ever' => $pct($inactiveTotal, $everTotal),
        ],
    ];

    // ------------------------------------------------------------------
    // Active users by OS/platform, within the same window, broken down by
    // free vs premium so the frontend can show either or a combined total.
    // ------------------------------------------------------------------
    $osLabels = ['windows', 'windows_vm', 'macos_wine', 'linux_wine'];
    $byOs = [];
    foreach ($osLabels as $os) {
        $freeCount = $scalar(
            'SELECT COUNT(*) FROM nutricula_unlicensed_checkins WHERE platform_profile = ? AND last_seen_at >= (NOW() - INTERVAL ? DAY)',
            ['s', 'i'], [$os, $days]
        );
        $premiumCount = $scalar(
            "SELECT COUNT(*) FROM nutricula_licenses WHERE device_type = ? AND status='active' AND last_seen_at IS NOT NULL AND last_seen_at >= (NOW() - INTERVAL ? DAY)",
            ['s', 'i'], [$os, $days]
        );
        $byOs[] = [
            'platform' => $os,
            'free' => $freeCount,
            'premium' => $premiumCount,
            'total' => $freeCount + $premiumCount,
        ];
    }
    // Free rows with no platform_profile at all yet (older Coordinator, or
    // the export genuinely unavailable) - shown separately rather than
    // silently dropped, so the OS breakdown's total still reconciles with
    // free_active_window above.
    $freeUnknownOs = $scalar(
        'SELECT COUNT(*) FROM nutricula_unlicensed_checkins WHERE platform_profile IS NULL AND last_seen_at >= (NOW() - INTERVAL ? DAY)',
        ['i'], [$days]
    );
    $premiumUnknownOs = $scalar(
        "SELECT COUNT(*) FROM nutricula_licenses WHERE device_type='unknown' AND status='active' AND last_seen_at IS NOT NULL AND last_seen_at >= (NOW() - INTERVAL ? DAY)",
        ['i'], [$days]
    );
    $byOs[] = [
        'platform' => 'unknown',
        'free' => $freeUnknownOs,
        'premium' => $premiumUnknownOs,
        'total' => $freeUnknownOs + $premiumUnknownOs,
    ];
    $result['by_os'] = $byOs;

    // ------------------------------------------------------------------
    // Growth chart - new free/premium signups per day over the selected
    // window, plus a running cumulative total for each. The frontend
    // derives weekly/monthly buckets from this same daily series client-
    // side (simpler than three near-identical SQL grouping queries, and
    // lets the user flip granularity instantly with no extra request).
    // ------------------------------------------------------------------
    $freeDaily = [];
    $stmt = $conn->prepare(
        'SELECT DATE(first_seen_at) d, COUNT(*) c FROM nutricula_unlicensed_checkins
         WHERE first_seen_at >= (NOW() - INTERVAL ? DAY)
         GROUP BY DATE(first_seen_at)'
    );
    $stmt->bind_param('i', $growthDays);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($row = $res->fetch_assoc()) { $freeDaily[(string)$row['d']] = (int)$row['c']; }
    $stmt->close();

    $premiumDaily = [];
    $stmt = $conn->prepare(
        'SELECT DATE(created_at) d, COUNT(*) c FROM nutricula_licenses
         WHERE created_at >= (NOW() - INTERVAL ? DAY)
         GROUP BY DATE(created_at)'
    );
    $stmt->bind_param('i', $growthDays);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($row = $res->fetch_assoc()) { $premiumDaily[(string)$row['d']] = (int)$row['c']; }
    $stmt->close();

    // Cumulative baseline: how many of each already existed BEFORE the
    // growth window started, so the cumulative line's first point isn't
    // misleadingly reset to zero.
    $freeBaseline = $scalar('SELECT COUNT(*) FROM nutricula_unlicensed_checkins WHERE first_seen_at < (NOW() - INTERVAL ? DAY)', ['i'], [$growthDays]);
    $premiumBaseline = $scalar('SELECT COUNT(*) FROM nutricula_licenses WHERE created_at < (NOW() - INTERVAL ? DAY)', ['i'], [$growthDays]);

    $series = [];
    $freeCum = $freeBaseline;
    $premiumCum = $premiumBaseline;
    $start = new DateTime("-{$growthDays} days", new DateTimeZone('UTC'));
    $today = new DateTime('now', new DateTimeZone('UTC'));
    for ($d = clone $start; $d <= $today; $d->modify('+1 day')) {
        $key = $d->format('Y-m-d');
        $freeN = $freeDaily[$key] ?? 0;
        $premiumN = $premiumDaily[$key] ?? 0;
        $freeCum += $freeN;
        $premiumCum += $premiumN;
        $series[] = [
            'date' => $key,
            'free_new' => $freeN,
            'premium_new' => $premiumN,
            'free_cumulative' => $freeCum,
            'premium_cumulative' => $premiumCum,
        ];
    }
    $result['growth_daily'] = $series;

    // ------------------------------------------------------------------
    // Server load proxy - total requests/minute across ALL endpoints, for
    // the last 60 minutes, straight from the rate-limiting table every
    // public endpoint already writes to. No shell/SSH access to the box
    // needed for this.
    // ------------------------------------------------------------------
    $loadSeries = [];
    $stmt = $conn->prepare(
        'SELECT window_start, SUM(request_count) c FROM nutricula_rate_limits
         WHERE window_start >= ?
         GROUP BY window_start ORDER BY window_start ASC'
    );
    $since = time() - 3600;
    $stmt->bind_param('i', $since);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($row = $res->fetch_assoc()) {
        $loadSeries[] = ['minute' => gmdate('H:i', (int)$row['window_start']), 'requests' => (int)$row['c']];
    }
    $stmt->close();
    $result['server_load_last_hour'] = $loadSeries;

    // ------------------------------------------------------------------
    // Free -> Premium conversion. A "conversion" is detected when a
    // premium license's machine_id matches a row that was ALREADY in
    // nutricula_unlicensed_checkins (first_seen_at before the license's
    // created_at) - both tables already store machine_id for their own
    // reasons, so this needs no new column, just a join. Necessarily an
    // approximation (a customer who reinstalls on a fresh machine ID
    // between trying the free version and buying won't match), but it's a
    // real, directly-derived signal, not a guess.
    // ------------------------------------------------------------------
    $convertedAllTime = $scalar(
        'SELECT COUNT(*) FROM nutricula_licenses lic
         WHERE EXISTS (
             SELECT 1 FROM nutricula_unlicensed_checkins u
             WHERE u.machine_id = lic.machine_id AND u.first_seen_at < lic.created_at
         )'
    );
    $convertedInWindow = $scalar(
        'SELECT COUNT(*) FROM nutricula_licenses lic
         WHERE lic.created_at >= (NOW() - INTERVAL ? DAY)
           AND EXISTS (
             SELECT 1 FROM nutricula_unlicensed_checkins u
             WHERE u.machine_id = lic.machine_id AND u.first_seen_at < lic.created_at
         )',
        ['i'], [$days]
    );
    $avgDaysRow = $conn->query(
        'SELECT AVG(DATEDIFF(lic.created_at, u.first_seen_at)) a
         FROM nutricula_licenses lic
         JOIN nutricula_unlicensed_checkins u
           ON u.machine_id = lic.machine_id AND u.first_seen_at < lic.created_at'
    )->fetch_assoc();
    $result['conversion'] = [
        'converted_all_time' => $convertedAllTime,
        'converted_in_window' => $convertedInWindow,
        'free_ever_total' => $freeEverTotal,
        'conversion_rate_all_time_pct' => $pct($convertedAllTime, $freeEverTotal),
        'avg_days_free_to_premium' => $avgDaysRow && $avgDaysRow['a'] !== null ? round((float)$avgDaysRow['a'], 1) : null,
    ];

    // ------------------------------------------------------------------
    // Build/version adoption among CURRENTLY ACTIVE installs (within the
    // selected window), free + premium combined, grouped by version via
    // nutricula_build_manifests. "Latest" = the manifest with the most
    // recent created_at (i.e. the most recently published build row) -
    // this panel doesn't read the public license_config.php, so it derives
    // "latest" from the manifests table itself rather than duplicating
    // that config's latest_version value.
    // ------------------------------------------------------------------
    $latestRow = $conn->query('SELECT build_id, version FROM nutricula_build_manifests ORDER BY created_at DESC LIMIT 1')->fetch_assoc();
    $latestVersion = $latestRow ? (string)$latestRow['version'] : null;

    $adoptionRows = [];
    $res = $conn->query(
        "SELECT COALESCE(m.version, 'unknown') version,
                SUM(CASE WHEN src = 'free' THEN 1 ELSE 0 END) free_count,
                SUM(CASE WHEN src = 'premium' THEN 1 ELSE 0 END) premium_count
         FROM (
             SELECT last_build_id, 'free' src FROM nutricula_unlicensed_checkins
             WHERE last_seen_at >= (NOW() - INTERVAL $days DAY) AND last_build_id IS NOT NULL
             UNION ALL
             SELECT last_build_id, 'premium' src FROM nutricula_licenses
             WHERE status='active' AND last_seen_at IS NOT NULL
               AND last_seen_at >= (NOW() - INTERVAL $days DAY) AND last_build_id IS NOT NULL
         ) t
         LEFT JOIN nutricula_build_manifests m ON m.build_id = t.last_build_id
         GROUP BY COALESCE(m.version, 'unknown')
         ORDER BY free_count + premium_count DESC"
    );
    $totalWithBuildInfo = 0;
    $onLatestCount = 0;
    while ($row = $res->fetch_assoc()) {
        $rowTotal = (int)$row['free_count'] + (int)$row['premium_count'];
        $totalWithBuildInfo += $rowTotal;
        if ($latestVersion !== null && $row['version'] === $latestVersion) $onLatestCount += $rowTotal;
        $adoptionRows[] = [
            'version' => (string)$row['version'],
            'free' => (int)$row['free_count'],
            'premium' => (int)$row['premium_count'],
            'total' => $rowTotal,
            'is_latest' => $latestVersion !== null && $row['version'] === $latestVersion,
        ];
    }
    $result['build_adoption'] = [
        'latest_version' => $latestVersion,
        'rows' => $adoptionRows,
        'active_with_known_build' => $totalWithBuildInfo,
        'pct_on_latest' => $pct($onLatestCount, $totalWithBuildInfo),
    ];

    // ------------------------------------------------------------------
    // Suspicious IPs - two independent signals:
    //  - raw request VOLUME per IP across all endpoints in the last 24h,
    //    straight from nutricula_rate_limits (catches a flood/scripted
    //    hammering regardless of whether individual requests succeed).
    //  - FAILED/rejected premium activity per IP in the selected window,
    //    from nutricula_license_activity (catches someone trying many
    //    license_ids/machine_ids against one IP - credential stuffing-
    //    style probing - even if their request rate alone looks modest).
    // ------------------------------------------------------------------
    $topByVolume = [];
    $res = $conn->query(
        "SELECT SUBSTRING_INDEX(rate_key, '|', -1) ip, SUM(request_count) c
         FROM nutricula_rate_limits
         WHERE window_start >= " . (time() - 86400) . "
         GROUP BY ip ORDER BY c DESC LIMIT 15"
    );
    while ($row = $res->fetch_assoc()) { $topByVolume[] = ['ip' => (string)$row['ip'], 'requests_24h' => (int)$row['c']]; }

    $topByFailures = [];
    $stmt = $conn->prepare(
        "SELECT observed_ip, COUNT(*) c FROM nutricula_license_activity
         WHERE reason IS NOT NULL AND occurred_at >= (NOW() - INTERVAL ? DAY)
         GROUP BY observed_ip ORDER BY c DESC LIMIT 15"
    );
    $stmt->bind_param('i', $days);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($row = $res->fetch_assoc()) { $topByFailures[] = ['ip' => (string)$row['observed_ip'], 'failed_attempts' => (int)$row['c']]; }
    $stmt->close();

    $result['suspicious_ips'] = [
        'top_by_request_volume_24h' => $topByVolume,
        'top_by_failed_attempts_window' => $topByFailures,
    ];

    // ------------------------------------------------------------------
    // A handful of extra signals that come essentially free from columns
    // that already exist, worth having on one screen:
    //  - licenses expiring soon (renewal/business planning)
    //  - currently clone-blocked licenses (blocked_until in the future)
    //  - licenses with an open "one stale token seen" flag (precedes an
    //    actual clone-block - an early warning, not yet an incident)
    //  - verify/challenge success rate in the selected window (general
    //    protocol health, independent of the -2 log's own narrower scope)
    // ------------------------------------------------------------------
    $expiring7d = $scalar(
        'SELECT COUNT(*) FROM nutricula_licenses WHERE status=\'active\' AND license_expires_at BETWEEN ? AND ?',
        ['i', 'i'], [time(), time() + 7 * 86400]
    );
    $expiring30d = $scalar(
        'SELECT COUNT(*) FROM nutricula_licenses WHERE status=\'active\' AND license_expires_at BETWEEN ? AND ?',
        ['i', 'i'], [time(), time() + 30 * 86400]
    );
    $cloneBlockedNow = $scalar('SELECT COUNT(*) FROM nutricula_licenses WHERE blocked_until IS NOT NULL AND blocked_until > ?', ['i'], [time()]);
    $tokenSuspiciousNow = $scalar('SELECT COUNT(*) FROM nutricula_licenses WHERE token_suspicious = 1');

    $verifyTotal = $scalar(
        "SELECT COUNT(*) FROM nutricula_license_activity WHERE request_type='verify' AND occurred_at >= (NOW() - INTERVAL ? DAY)",
        ['i'], [$days]
    );
    $verifyOk = $scalar(
        "SELECT COUNT(*) FROM nutricula_license_activity WHERE request_type='verify' AND reason IS NULL AND occurred_at >= (NOW() - INTERVAL ? DAY)",
        ['i'], [$days]
    );

    $result['health'] = [
        'licenses_expiring_7d' => $expiring7d,
        'licenses_expiring_30d' => $expiring30d,
        'clone_blocked_now' => $cloneBlockedNow,
        'token_suspicious_now' => $tokenSuspiciousNow,
        'verify_success_rate_pct_window' => $pct($verifyOk, $verifyTotal),
        'verify_attempts_window' => $verifyTotal,
    ];

    $conn->close();
    nutricula_admin_send_json($result);

} catch (Throwable $e) {
    error_log('[Nutricula admin stats] ' . $e->getMessage());
    http_response_code(500);
    nutricula_admin_send_json(['error' => 'Internal error.']);
}
