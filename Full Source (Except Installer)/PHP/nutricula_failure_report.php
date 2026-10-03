<?php

declare(strict_types=1);

date_default_timezone_set('UTC');

require_once __DIR__ . '/license_common.php';

/* nutricula_failure_report.php (2026) - best-effort diagnostic telemetry
   from the Coordinator for the two "-2" (TIER_FAILED) causes it decides
   ENTIRELY ON ITS OWN, without any server round-trip deciding the outcome
   for it (see nutricula_minus2_log's schema comment for the full picture
   of which -2 causes can and cannot ever reach this server):

     - 'transport_exhausted': the Coordinator made its full MAX_ATTEMPTS
       budget of challenge/verify requests to license_check.php without
       EVER getting a usable, signature-verified response (real network
       outage, DNS failure, the request never reaching this server for any
       reason). Sent as an independent, separate request specifically
       because the premium/transfer channel it describes just failed -
       this one may equally fail to arrive for the exact same underlying
       reason, and that is fine: its absence in that specific case is
       itself consistent with "the customer's network/firewall was the
       problem", which is useful information too.
     - 'machineid_generation_failed': local hardware-ID generation failed
       before any network attempt was even possible.

   Deliberately carries NO per-device signature and proves no license
   ownership - it is pure, unauthenticated telemetry about an already-
   locally-decided outcome, exactly like free_checkin's own design
   philosophy (see license_check.php's FREE_CHECKIN_STAGE_FIELDS comment).
   Forging a fake report here grants an attacker nothing (it is a log
   entry, not an authorization decision) - the only concern is spam, which
   the same per-IP rate limiting used everywhere else in this system
   already handles. */

const FAILURE_REPORT_ALLOWED_FIELDS = [
    'v', 'reason_code', 'reason_detail', 'install_kind',
    'license_id', 'machine_id', 'machine_id_alt', 'device_key_hash', 'build_id',
];

/* Fixed, short allowlist - NOT whatever string the client feels like
   sending. Keeps this log meaningful and immune to log-injection/spam of
   junk reason codes. Must be kept in sync with the reason codes
   CoordinatorCore.cpp actually sends (see its own ReportFailureBestEffort
   call sites) and with nutricula_minus2_log's schema comment. */
const FAILURE_REPORT_ALLOWED_REASONS = [
    'transport_exhausted',
    'machineid_generation_failed',
];

try {
    $config = nutricula_load_config();
    $conn = nutricula_db($config);
    // Same DDoS mitigation as every other endpoint here - see
    // nutricula_rate_limit_check()'s own doc comment.
    nutricula_rate_limit_check($conn, $config, 'failure_report');
    $conn->query("SET time_zone = '+00:00'");

    $outer = nutricula_require_post_data();
    $inner = nutricula_gcm_decrypt($outer, $config);
    $fields = nutricula_strict_parse_fields($inner, FAILURE_REPORT_ALLOWED_FIELDS);

    if ((string)($fields['v'] ?? '') !== '3') throw new RuntimeException('Invalid protocol version.');

    $reasonCode = trim(nutricula_required_field($fields, 'reason_code'));
    if (!in_array($reasonCode, FAILURE_REPORT_ALLOWED_REASONS, true)) {
        throw new RuntimeException('Unrecognized reason_code.');
    }

    // Free-text, but capped hard - this is support-readability only, never
    // parsed or trusted for any decision, so a generous but bounded length
    // is all the validation it needs.
    $reasonDetail = isset($fields['reason_detail']) ? (string)$fields['reason_detail'] : '';
    if (strlen($reasonDetail) > 500) $reasonDetail = substr($reasonDetail, 0, 500);
    $reasonDetail = ($reasonDetail !== '') ? $reasonDetail : null;

    $installKind = (string)($fields['install_kind'] ?? '');
    if ($installKind !== 'free' && $installKind !== 'licensed') {
        throw new RuntimeException('Invalid install_kind.');
    }

    $rawMachineId = isset($fields['machine_id']) ? strtoupper(trim($fields['machine_id'])) : '';
    $rawMachineIdAlt = isset($fields['machine_id_alt']) ? strtoupper(trim($fields['machine_id_alt'])) : '';
    $rawDeviceKeyHash = isset($fields['device_key_hash']) ? strtoupper(trim($fields['device_key_hash'])) : '';
    $machineId = ($rawMachineId !== '') ? $rawMachineId : null;
    $machineIdAlt = ($rawMachineIdAlt !== '') ? $rawMachineIdAlt : null;
    $deviceKeyHash = ($rawDeviceKeyHash !== '') ? $rawDeviceKeyHash : null;
    if ($machineId !== null && !preg_match('/\A[0-9A-F]{64}\z/', $machineId)) throw new RuntimeException('Invalid machine ID.');
    if ($machineIdAlt !== null && !preg_match('/\A[0-9A-F]{64}\z/', $machineIdAlt)) throw new RuntimeException('Invalid machine ID.');
    if ($deviceKeyHash !== null && !preg_match('/\A[0-9A-F]{64}\z/', $deviceKeyHash)) throw new RuntimeException('Invalid device key hash.');

    $buildId = isset($fields['build_id']) ? trim($fields['build_id']) : '';
    if (strlen($buildId) > 64) $buildId = substr($buildId, 0, 64);
    $buildId = ($buildId !== '') ? $buildId : null;

    // license_id is purely for looking up the email to attach to this log
    // row for support convenience - it is NEVER verified against any
    // signature here (this endpoint has none to check), so it must never
    // be used for anything beyond that one lookup. A bogus/unknown
    // license_id simply means no email gets attached - never an error.
    $licenseDbId = null;
    $userEmail = null;
    $rawLicenseId = isset($fields['license_id']) ? trim($fields['license_id']) : '';
    if ($rawLicenseId !== '' && nutricula_is_valid_uuid($rawLicenseId)) {
        $stmt = $conn->prepare('SELECT id, user_email FROM nutricula_licenses WHERE license_uuid=? LIMIT 1');
        if ($stmt) {
            $stmt->bind_param('s', $rawLicenseId);
            $stmt->execute();
            $row = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            if ($row) {
                $licenseDbId = (int)$row['id'];
                $userEmail = (string)$row['user_email'];
            }
        }
    }

    nutricula_log_minus2(
        $conn, $installKind, $reasonCode, $reasonDetail,
        $licenseDbId, $userEmail, $machineId, $machineIdAlt, $deviceKeyHash,
        $buildId, nutricula_client_ip($config)
    );
    $conn->close();

    // The Coordinator never inspects this response (true fire-and-forget,
    // unlike the hardened free_checkin stage - there is nothing for it to
    // act on here, this call exists purely to get a row into the log) -
    // its exact content doesn't matter, but it still goes out through the
    // same GCM envelope as everything else for consistency.
    http_response_code(200);
    header('Content-Type: text/plain; charset=UTF-8');
    try {
        echo nutricula_gcm_encrypt('ok', $config);
    } catch (Throwable $e) {
        echo 'no';
    }
    exit;

} catch (Throwable $e) {
    if (isset($conn) && $conn instanceof mysqli) {
        try { $conn->close(); } catch (Throwable $ignored) {}
    }
    error_log('[Nutricula failure report] ' . $e->getMessage());
    $fallback = $config ?? null;
    if (is_array($fallback)) nutricula_no($fallback);
    http_response_code(500);
    exit('no');
}
