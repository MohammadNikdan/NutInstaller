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

    $conn->close();
    nutricula_admin_send_json($result);

} catch (Throwable $e) {
    error_log('[Nutricula admin stats] ' . $e->getMessage());
    http_response_code(500);
    nutricula_admin_send_json(['error' => 'Internal error.']);
}
