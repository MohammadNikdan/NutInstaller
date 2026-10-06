<?php

declare(strict_types=1);

require_once __DIR__ . '/admin_common.php';

/* admin_stats.php - GET, authenticated. Query params:
     range       = 'today' | 'all' | omitted (plain day-count mode)
     days        = activity window in days when range is omitted, for
                   "active in the last N days" and the "inactive" complement
                   (default 30). Also accepts 365 for "last year".
     tz          = IANA zone name, detected client-side from the device
                   (never user-editable) and used for the 'today' boundary
                   and for the "active today" cards below.
     growth_days = how far back the growth chart goes (default 90) -
                   independent of the window above, its own selector.
   Returns one big JSON blob with everything the dashboard's summary cards,
   percentage view, OS breakdown, growth chart and server-load chart need -
   one request, one round trip, so the "update" button and the 60-second
   auto-refresh are each a single fetch. */

try {
    $config = nutricula_admin_load_config();
    nutricula_admin_start_session($config);
    nutricula_admin_require_auth();
    $conn = nutricula_admin_db($config);

    $growthDays = (int)($_GET['growth_days'] ?? 90);
    if ($growthDays < 7) $growthDays = 7;
    if ($growthDays > 1095) $growthDays = 1095;

    // ------------------------------------------------------------------
    // Timezone for the "today" boundary and the active-today
    // cards below - all share the SAME local midnight, so every "today"-
    // flavored feature in this response stays consistent with the others.
    // The browser now sends its own device timezone (not a user-editable
    // dropdown), so it can be any valid IANA zone name - not a fixed list
    // anymore. DateTimeZone itself throws on an invalid name, which is all
    // the validation an unchecked query param needs; fall back to UTC
    // rather than letting a bad/spoofed value 500 the endpoint.
    // ------------------------------------------------------------------
    $tzName = (string)($_GET['tz'] ?? 'UTC');
    try {
        $tz = new DateTimeZone($tzName);
    } catch (Exception $e) {
        $tzName = 'UTC';
        $tz = new DateTimeZone($tzName);
    }
    $nowInTz = new DateTime('now', $tz);
    $todayMidnightInTz = (clone $nowInTz)->setTime(0, 0, 0);
    $todayMidnightTs = $todayMidnightInTz->getTimestamp();
    $nowTs = $nowInTz->getTimestamp();
    $elapsedSecondsToday = max(0, $nowTs - $todayMidnightTs);

    // ------------------------------------------------------------------
    // The "active/new window" - every summary/OS/build/conversion/health
    // query below that used to say "in the last N days" now filters
    // between two absolute timestamps ($sinceTs, $untilTs) instead, so
    // 'today' (local-midnight based, not a round number of days), 'all'
    // (no lower bound at all) all flow through the exact same queries as
    // the plain day-count modes (24h/7d/30d/90d/365d) - no special-casing
    // needed anywhere past this point.
    // ------------------------------------------------------------------
    $range = (string)($_GET['range'] ?? '');
    $days = (int)($_GET['days'] ?? 30); // kept for the response + legacy callers
    if ($days < 1) $days = 1;
    if ($days > 3650) $days = 3650;
    $untilTs = $nowTs;

    if ($range === 'today') {
        $sinceTs = $todayMidnightTs;
        $windowLabel = 'today';
    } elseif ($range === 'all') {
        $sinceTs = 0; // 1970 - effectively "no lower bound"
        $windowLabel = 'all';
    } else {
        $sinceTs = $nowTs - $days * 86400;
        $windowLabel = (string)$days;
    }

    $result = [
        'generated_at' => gmdate('c'),
        'window_days' => $days,
        'window_label' => $windowLabel,
        'window_since' => gmdate('c', $sinceTs),
        'window_until' => gmdate('c', $untilTs),
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
        'SELECT COUNT(*) FROM nutricula_unlicensed_checkins WHERE last_seen_at >= FROM_UNIXTIME(?) AND last_seen_at <= FROM_UNIXTIME(?)',
        ['i', 'i'], [$sinceTs, $untilTs]
    );
    $premiumActive = $scalar(
        "SELECT COUNT(*) FROM nutricula_licenses WHERE status='active' AND last_seen_at IS NOT NULL AND last_seen_at >= FROM_UNIXTIME(?) AND last_seen_at <= FROM_UNIXTIME(?)",
        ['i', 'i'], [$sinceTs, $untilTs]
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
    // "Today" acquisition cards - deliberately NOT "active today" (merely
    // having used the app today says nothing about whether someone is a
    // NEW signal worth noticing). All five are since LOCAL midnight in the
    // selected timezone ($todayMidnightTs), resetting to zero every day -
    // the server's own current time in that zone is echoed back so the
    // admin can verify the midnight boundary is actually landing where
    // they expect. Independent of the window selector above (always
    // "today", whatever the dashboard's main window is set to).
    // ------------------------------------------------------------------

    // 1) Brand-new free users - no record of this machine at all before
    // today, neither free nor premium.
    $freeBrandNewToday = $scalar(
        'SELECT COUNT(*) FROM nutricula_unlicensed_checkins u
         WHERE u.first_seen_at >= FROM_UNIXTIME(?)
           AND NOT EXISTS (
             SELECT 1 FROM nutricula_licenses lic
             WHERE u.machine_id IS NOT NULL AND lic.machine_id = u.machine_id
               AND lic.created_at < FROM_UNIXTIME(?)
           )',
        ['i', 'i'], [$todayMidnightTs, $todayMidnightTs]
    );

    // 2) Free users returning TODAY after >=30 days with no free activity -
    // needs previous_last_seen_at (see nutricula_track_unlicensed_checkin()
    // in license_common.php). Degrade gracefully on an un-migrated DB
    // instead of a fatal "unknown column" error.
    $hasPreviousLastSeenColumn = (bool)$conn->query(
        "SHOW COLUMNS FROM nutricula_unlicensed_checkins LIKE 'previous_last_seen_at'"
    )->num_rows;
    $freeReturningToday = $hasPreviousLastSeenColumn ? $scalar(
        'SELECT COUNT(*) FROM nutricula_unlicensed_checkins u
         WHERE u.last_seen_at >= FROM_UNIXTIME(?)
           AND u.first_seen_at < FROM_UNIXTIME(?)
           AND u.previous_last_seen_at IS NOT NULL
           AND u.previous_last_seen_at < FROM_UNIXTIME(?)',
        ['i', 'i', 'i'], [$todayMidnightTs, $todayMidnightTs, $nowTs - 30 * 86400]
    ) : 0;

    // 3) First-ever premium activation today - may have used the free
    // version before, but never held a license before today.
    $premiumFirstTimeToday = $scalar(
        'SELECT COUNT(*) FROM nutricula_licenses lic
         WHERE lic.activated_at >= FROM_UNIXTIME(?)
           AND NOT EXISTS (
             SELECT 1 FROM nutricula_licenses other
             WHERE other.machine_id = lic.machine_id AND other.id <> lic.id
               AND other.activated_at < FROM_UNIXTIME(?)
           )',
        ['i', 'i'], [$todayMidnightTs, $todayMidnightTs]
    );

    // 4) Renewal/reactivation today - activated today, but this machine
    // held a premium license before (the complement of #3 among today's
    // activations: #3 + #4 = every license activated today).
    $premiumRenewalToday = $scalar(
        'SELECT COUNT(*) FROM nutricula_licenses lic
         WHERE lic.activated_at >= FROM_UNIXTIME(?)
           AND EXISTS (
             SELECT 1 FROM nutricula_licenses other
             WHERE other.machine_id = lic.machine_id AND other.id <> lic.id
               AND other.activated_at < FROM_UNIXTIME(?)
           )',
        ['i', 'i'], [$todayMidnightTs, $todayMidnightTs]
    );

    // 5) Transfers completed today.
    $transfersToday = $scalar(
        'SELECT COUNT(*) FROM nutricula_transfer_keys_used WHERE transferred_at >= FROM_UNIXTIME(?)',
        ['i'], [$todayMidnightTs]
    );

    $result['today'] = [
        'timezone' => $tzName,
        'server_time_in_tz' => $nowInTz->format('Y-m-d H:i:s'),
        'midnight_in_tz' => $todayMidnightInTz->format('Y-m-d H:i:s'),
        'free_brand_new' => $freeBrandNewToday,
        'free_returning_30d' => $freeReturningToday,
        'free_returning_available' => $hasPreviousLastSeenColumn,
        'premium_first_time' => $premiumFirstTimeToday,
        'premium_renewal' => $premiumRenewalToday,
        'transfers' => $transfersToday,
    ];

    // ------------------------------------------------------------------
    // Active users by OS/platform, within the same window, broken down by
    // free vs premium so the frontend can show either or a combined total.
    // windows_vm (Windows running inside a VM) gets its OWN bucket here -
    // shown as "VPS"/"سرور مجازی" - rather than being folded into "windows",
    // since that's meaningfully different infrastructure for support
    // purposes. macos_wine/linux_wine still drop their _wine suffix (no
    // ambiguity there - there is no "native-vs-VM" distinction to preserve
    // for those). The frontend maps each key through os_windows/os_vm/
    // os_mac/os_linux/os_unknown for the actual label text.
    // ------------------------------------------------------------------
    $osGroups = [
        'windows' => ['windows'],
        'vm' => ['windows_vm'],
        'mac' => ['macos_wine'],
        'linux' => ['linux_wine'],
    ];
    $byOs = [];
    foreach ($osGroups as $label => $rawValues) {
        $placeholders = implode(',', array_fill(0, count($rawValues), '?'));
        $types = str_repeat('s', count($rawValues)) . 'ii';
        $params = array_merge($rawValues, [$sinceTs, $untilTs]);
        $freeCount = $scalar(
            "SELECT COUNT(*) FROM nutricula_unlicensed_checkins WHERE platform_profile IN ($placeholders) AND last_seen_at >= FROM_UNIXTIME(?) AND last_seen_at <= FROM_UNIXTIME(?)",
            str_split($types), $params
        );
        $premiumCount = $scalar(
            "SELECT COUNT(*) FROM nutricula_licenses WHERE device_type IN ($placeholders) AND status='active' AND last_seen_at IS NOT NULL AND last_seen_at >= FROM_UNIXTIME(?) AND last_seen_at <= FROM_UNIXTIME(?)",
            str_split($types), $params
        );
        $byOs[] = [
            'platform' => $label,
            'free' => $freeCount,
            'premium' => $premiumCount,
            'total' => $freeCount + $premiumCount,
        ];
    }
    // Free rows with no platform_profile at all yet (older Coordinator, or
    // the export genuinely unavailable), plus anything NOT in one of the
    // known buckets above (device_type='unknown', or any future/unmapped
    // value) - shown together rather than silently dropped, so the OS
    // breakdown's total still reconciles with free_active_window above.
    $knownRaw = array_merge(...array_values($osGroups));
    $freePlaceholders = implode(',', array_fill(0, count($knownRaw), '?'));
    $freeUnknownOs = $scalar(
        "SELECT COUNT(*) FROM nutricula_unlicensed_checkins
         WHERE (platform_profile IS NULL OR platform_profile NOT IN ($freePlaceholders))
           AND last_seen_at >= FROM_UNIXTIME(?) AND last_seen_at <= FROM_UNIXTIME(?)",
        array_merge(str_split(str_repeat('s', count($knownRaw))), ['i', 'i']), array_merge($knownRaw, [$sinceTs, $untilTs])
    );
    $premiumUnknownOs = $scalar(
        "SELECT COUNT(*) FROM nutricula_licenses
         WHERE device_type NOT IN ($freePlaceholders) AND status='active' AND last_seen_at IS NOT NULL
           AND last_seen_at >= FROM_UNIXTIME(?) AND last_seen_at <= FROM_UNIXTIME(?)",
        array_merge(str_split(str_repeat('s', count($knownRaw))), ['i', 'i']), array_merge($knownRaw, [$sinceTs, $untilTs])
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
    // Server health - what "is the server busy" actually means here is
    // RESPONSE SPEED, not raw request count (a traffic spike the server is
    // handling fine is not "busy" in any way that matters; a slowdown at
    // normal traffic IS). The real signal comes from nutricula_request_timing
    // - one row per minute, written by license_check.php's own request
    // timer (see nutricula_record_request_timing() in the public PHP
    // codebase's license_common.php) via a shutdown-function hook that adds
    // ZERO latency to the actual response. That table may not exist yet on
    // an install that hasn't picked up this change - degrade to the old
    // volume-only view (from nutricula_rate_limits, which every endpoint
    // already writes to) rather than erroring the whole panel.
    // ------------------------------------------------------------------
    $timingTableExists = (bool)$conn->query("SHOW TABLES LIKE 'nutricula_request_timing'")->num_rows;

    $periodStats = function (int $fromTs, int $toTs) use ($conn): array {
        $stmt = $conn->prepare(
            'SELECT COALESCE(SUM(request_count),0) c, COALESCE(SUM(total_duration_ms),0) t
             FROM nutricula_request_timing WHERE window_start >= ? AND window_start < ?'
        );
        $stmt->bind_param('ii', $fromTs, $toTs);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        $count = (int)$row['c'];
        $totalMs = (int)$row['t'];
        return ['requests' => $count, 'avg_ms' => $count > 0 ? round($totalMs / $count, 1) : null];
    };

    if (!$timingTableExists) {
        // Fallback: the old proxy metric (volume only, last hour only) so
        // there's still SOMETHING on screen while the new table is missing.
        $loadSeries = [];
        $stmt = $conn->prepare(
            'SELECT window_start, SUM(request_count) c FROM nutricula_rate_limits
             WHERE window_start >= ? GROUP BY window_start ORDER BY window_start ASC'
        );
        $since = time() - 3600;
        $stmt->bind_param('i', $since);
        $stmt->execute();
        $res = $stmt->get_result();
        while ($row = $res->fetch_assoc()) {
            $loadSeries[] = ['minute' => gmdate('H:i', (int)$row['window_start']), 'requests' => (int)$row['c'], 'avg_ms' => null];
        }
        $stmt->close();
        $result['server_health'] = [
            'available' => false,
            'reason' => 'timing_table_missing',
            'last_hour' => $loadSeries,
            'verdict' => 'insufficient_data',
        ];
    } else {
        // Minute-by-minute series for the last hour (volume + avg/max
        // latency per minute) - the detailed chart.
        $loadSeries = [];
        $stmt = $conn->prepare(
            'SELECT window_start, request_count, total_duration_ms, max_duration_ms
             FROM nutricula_request_timing WHERE window_start >= ? ORDER BY window_start ASC'
        );
        $since = time() - 3600;
        $stmt->bind_param('i', $since);
        $stmt->execute();
        $res = $stmt->get_result();
        while ($row = $res->fetch_assoc()) {
            $c = (int)$row['request_count'];
            $loadSeries[] = [
                'minute' => gmdate('H:i', (int)$row['window_start']),
                'requests' => $c,
                'avg_ms' => $c > 0 ? round(((int)$row['total_duration_ms']) / $c, 1) : null,
                'max_ms' => (int)$row['max_duration_ms'],
            ];
        }
        $stmt->close();

        // The verdict itself: a SELF-RELATIVE comparison (this server
        // against its own normal self over the last day), not a hardcoded
        // millisecond threshold - shared hosting speed varies wildly
        // install to install, so "280ms is slow" means nothing without a
        // baseline, but "3x slower than this exact server's last 24h
        // average" means something everywhere.
        $recent = $periodStats($nowTs - 900, $nowTs);               // last 15 min
        $baseline = $periodStats($nowTs - 86400, $nowTs - 900);     // prior ~23h45m

        $latencyRatio = ($recent['avg_ms'] !== null && $baseline['avg_ms'] !== null && $baseline['avg_ms'] > 0)
            ? $recent['avg_ms'] / $baseline['avg_ms'] : null;
        $recentPerMin = $recent['requests'] / 15;
        $baselinePerMin = $baseline['requests'] / ((86400 - 900) / 60);
        $volumeRatio = $baselinePerMin > 0 ? $recentPerMin / $baselinePerMin : null;

        if ($recent['requests'] < 5 || $baseline['requests'] < 20) {
            // Too little traffic yet to say anything meaningful - a single
            // slow request among 3 total would look like a 300% spike.
            $verdict = 'insufficient_data';
        } elseif ($latencyRatio !== null && ($latencyRatio >= 2.5 || ($latencyRatio >= 1.8 && $volumeRatio !== null && $volumeRatio >= 1.5))) {
            $verdict = 'critical';
        } elseif ($latencyRatio !== null && ($latencyRatio >= 1.4 || ($volumeRatio !== null && $volumeRatio >= 1.8))) {
            $verdict = 'elevated';
        } else {
            $verdict = 'normal';
        }

        // Period-over-period comparison - PURE rolling durations, nothing
        // anchored to local midnight or clock time at all (deliberately NOT
        // "today vs yesterday" by calendar day - "last 24h" here always
        // means the 24 hours ending THIS SECOND, compared against the 24
        // hours immediately before that, and likewise for 7d/30d). This is
        // the one spot in the whole report where the selected timezone is
        // irrelevant by design.
        $last24h = $periodStats($nowTs - 86400, $nowTs);
        $prior24h = $periodStats($nowTs - 2 * 86400, $nowTs - 86400);
        $last7d = $periodStats($nowTs - 7 * 86400, $nowTs);
        $prior7d = $periodStats($nowTs - 14 * 86400, $nowTs - 7 * 86400);
        $last30d = $periodStats($nowTs - 30 * 86400, $nowTs);
        $prior30d = $periodStats($nowTs - 60 * 86400, $nowTs - 30 * 86400);

        $deltaPct = function (?float $now, ?float $then): ?float {
            if ($now === null || $then === null || $then == 0.0) return null;
            return round((($now - $then) / $then) * 100, 1);
        };

        // Best-effort CPU/RAM pressure - most shared hosts (including this
        // one's admin subdomain, per its own open_basedir restriction)
        // block /proc entirely, so every field here can legitimately come
        // back null. Reported when available rather than assumed.
        $systemLoad = null;
        if (function_exists('sys_getloadavg')) {
            $la = @sys_getloadavg();
            if (is_array($la) && count($la) === 3) {
                $systemLoad = ['load_1m' => round($la[0], 2), 'load_5m' => round($la[1], 2), 'load_15m' => round($la[2], 2)];
            }
        }
        $cpuCores = null;
        if (@is_readable('/proc/cpuinfo')) {
            $cpuinfoRaw = @file_get_contents('/proc/cpuinfo');
            if ($cpuinfoRaw !== false) {
                $cpuCores = substr_count($cpuinfoRaw, "\nprocessor\t:") ?: null;
            }
        }
        $memInfo = null;
        if (@is_readable('/proc/meminfo')) {
            $memRaw = @file_get_contents('/proc/meminfo');
            if ($memRaw) {
                preg_match('/MemTotal:\s+(\d+)/', $memRaw, $mt);
                preg_match('/MemAvailable:\s+(\d+)/', $memRaw, $ma);
                if ($mt && $ma) {
                    $totalMb = (int)round(((int)$mt[1]) / 1024);
                    $availMb = (int)round(((int)$ma[1]) / 1024);
                    $memInfo = [
                        'total_mb' => $totalMb,
                        'available_mb' => $availMb,
                        'used_pct' => $totalMb > 0 ? round((($totalMb - $availMb) / $totalMb) * 100, 1) : null,
                    ];
                }
            }
        }

        $result['server_health'] = [
            'available' => true,
            'last_hour' => $loadSeries,
            'recent_15m' => $recent,
            'baseline_24h' => $baseline,
            'latency_ratio' => $latencyRatio !== null ? round($latencyRatio, 2) : null,
            'volume_ratio' => $volumeRatio !== null ? round($volumeRatio, 2) : null,
            'verdict' => $verdict,
            'comparison' => [
                'last_24h' => $last24h,
                'prior_24h' => $prior24h,
                'last_7d' => $last7d,
                'prior_7d' => $prior7d,
                'last_30d' => $last30d,
                'prior_30d' => $prior30d,
                'requests_24h_pct' => $deltaPct((float)$last24h['requests'], (float)$prior24h['requests']),
                'requests_7d_pct' => $deltaPct((float)$last7d['requests'], (float)$prior7d['requests']),
                'requests_30d_pct' => $deltaPct((float)$last30d['requests'], (float)$prior30d['requests']),
                'latency_24h_pct' => $deltaPct($last24h['avg_ms'], $prior24h['avg_ms']),
                'latency_7d_pct' => $deltaPct($last7d['avg_ms'], $prior7d['avg_ms']),
                'latency_30d_pct' => $deltaPct($last30d['avg_ms'], $prior30d['avg_ms']),
            ],
            'system' => [
                'load' => $systemLoad,
                'cpu_cores' => $cpuCores,
                'memory' => $memInfo,
            ],
        ];
    }

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
         WHERE lic.created_at >= FROM_UNIXTIME(?) AND lic.created_at <= FROM_UNIXTIME(?)
           AND EXISTS (
             SELECT 1 FROM nutricula_unlicensed_checkins u
             WHERE u.machine_id = lic.machine_id AND u.first_seen_at < lic.created_at
         )',
        ['i', 'i'], [$sinceTs, $untilTs]
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
    // selected window), free (verified + outdated-rejected) + premium combined, grouped by version via
    // nutricula_build_manifests. "Latest" = the manifest with the most
    // recent created_at (i.e. the most recently published build row) -
    // this panel doesn't read the public license_config.php, so it derives
    // "latest" from the manifests table itself rather than duplicating
    // that config's latest_version value.
    // ------------------------------------------------------------------
    $latestRow = $conn->query('SELECT build_id, version FROM nutricula_build_manifests ORDER BY created_at DESC LIMIT 1')->fetch_assoc();
    $latestVersion = $latestRow ? (string)$latestRow['version'] : null;

    $adoptionRows = [];
    $stmt = $conn->prepare(
        "SELECT COALESCE(m.version, 'unknown') version,
                SUM(CASE WHEN src = 'free' THEN 1 ELSE 0 END) free_count,
                SUM(CASE WHEN src = 'premium' THEN 1 ELSE 0 END) premium_count,
                SUM(CASE WHEN src = 'free' THEN 1 ELSE 0 END) + SUM(CASE WHEN src = 'premium' THEN 1 ELSE 0 END) total_count
         FROM (
             SELECT last_build_id, 'free' src FROM nutricula_unlicensed_checkins
             WHERE last_seen_at >= FROM_UNIXTIME(?) AND last_seen_at <= FROM_UNIXTIME(?) AND last_build_id IS NOT NULL
             UNION ALL
             SELECT last_build_id, 'premium' src FROM nutricula_licenses
             WHERE status='active' AND last_seen_at IS NOT NULL
               AND last_seen_at >= FROM_UNIXTIME(?) AND last_seen_at <= FROM_UNIXTIME(?) AND last_build_id IS NOT NULL
             UNION ALL
             /* Free installs that are OUTDATED are no longer in
                nutricula_unlicensed_checkins (only fully verified devices are) -
                they live in nutricula_rejected_checkins with last_reason
                'update_required'. Counted here as free, once per computer: a
                device that ALSO has a row in the unlicensed table inside this
                same window (it checked in fine just before the version became
                mandatory) is already counted above and is skipped. */
             SELECT r.last_build_id, 'free' src FROM nutricula_rejected_checkins r
             WHERE r.last_reason = 'update_required'
               AND r.last_seen_at >= FROM_UNIXTIME(?) AND r.last_seen_at <= FROM_UNIXTIME(?) AND r.last_build_id IS NOT NULL
               AND NOT EXISTS (
                   SELECT 1 FROM nutricula_unlicensed_checkins u
                   WHERE u.last_seen_at >= FROM_UNIXTIME(?) AND u.last_seen_at <= FROM_UNIXTIME(?)
                     AND ((u.machine_id IS NOT NULL AND u.machine_id = r.machine_id)
                          OR (u.device_public_key_hash IS NOT NULL AND u.device_public_key_hash = r.device_public_key_hash))
               )
         ) t
         LEFT JOIN nutricula_build_manifests m ON m.build_id = t.last_build_id
         GROUP BY COALESCE(m.version, 'unknown')
         ORDER BY total_count DESC"
    );
    $stmt->bind_param('iiiiiiii', $sinceTs, $untilTs, $sinceTs, $untilTs, $sinceTs, $untilTs, $sinceTs, $untilTs);
    $stmt->execute();
    $res = $stmt->get_result();
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
    $stmt->close();
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
         WHERE reason IS NOT NULL AND occurred_at >= FROM_UNIXTIME(?) AND occurred_at <= FROM_UNIXTIME(?)
         GROUP BY observed_ip ORDER BY c DESC LIMIT 15"
    );
    $stmt->bind_param('ii', $sinceTs, $untilTs);
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
        "SELECT COUNT(*) FROM nutricula_license_activity WHERE request_type='verify' AND occurred_at >= FROM_UNIXTIME(?) AND occurred_at <= FROM_UNIXTIME(?)",
        ['i', 'i'], [$sinceTs, $untilTs]
    );
    $verifyOk = $scalar(
        "SELECT COUNT(*) FROM nutricula_license_activity WHERE request_type='verify' AND reason IS NULL AND occurred_at >= FROM_UNIXTIME(?) AND occurred_at <= FROM_UNIXTIME(?)",
        ['i', 'i'], [$sinceTs, $untilTs]
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
