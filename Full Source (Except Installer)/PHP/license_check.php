<?php

declare(strict_types=1);

date_default_timezone_set('UTC');

require_once __DIR__ . '/license_common.php';

/* Combined whitelist across both stages - the per-stage subset is enforced
   separately right after 'stage' is known, so a verify-only field (e.g.
   signature) appearing in a challenge request is still rejected. */
const CHECK_ALLOWED_FIELDS = [
    'v', 'stage', 'license_id', 'machine_id', 'machine_id_alt', 'device_key_hash', 'local_ip',
    'challenge_id', 'signature', 'build_id', 'ex5_hash', 'ex4_hash', 'dll32_hash', 'dll64_hash',
    'machineid32_hash', 'machineid64_hash', 'broker_hash',
    'refresh_token', 'platform_profile',
];
const CHALLENGE_STAGE_FIELDS = ['v', 'stage', 'license_id', 'machine_id', 'machine_id_alt', 'device_key_hash', 'local_ip'];
/* Free-tier telemetry (2026): a check-in the Coordinator sends periodically
   whenever it has NO usable local lease at all (missing file, corrupt file,
   or a lease that failed Layer 1's machine/device match) - i.e. whenever it
   is about to present TIER_FREE locally with nothing else to report. Still
   deliberately minimal on the AUTHORIZATION side: no license_id (there may
   genuinely be none), no challenge/signature (there is no license private
   key relationship to prove possession of anything against - this is not an
   authorization request, just "a free-tier install exists and is still
   running"). Still travels inside the same mandatory GCM transport envelope
   as every other request (Transport Key), so it is not readable in transit,
   but carries no cryptographic proof of device ownership beyond that - by
   design, since nothing is being authorized. See
   nutricula_track_unlicensed_checkin() for what gets recorded, and the
   "reject reasons that map to TIER_FREE" handling below for how a
   MISMATCHED-but-real lease (Layer 1 catches it locally, but the Coordinator
   still owns a real license_id) is tracked through the existing
   challenge/verify path instead of this one.
   2026 hardening (owner's explicit request - "security mechanisms shouldn't
   depend on license type, free or pro"): build_id and the 7 artifact hashes
   below are now ALSO REQUIRED here, exactly as mandatory as they are on the
   verify stage (no backward-compat allowance - Nutricula has not shipped
   publicly yet, so there is no older Coordinator build in the field to stay
   compatible with). This endpoint validates them against
   nutricula_build_manifests - the exact same server-authoritative table the
   Premium/Transfer verify stage checks - and against latest_version, and
   responds with a genuine signed Reject (update_required / artifact_mismatch)
   instead of the plain OK when either check fails, so a free install gets
   the same mandatory-update and tamper-detection enforcement a Premium
   install does. This still proves nothing about LICENSE ownership (there is
   no license here to own) - it only proves "this build's artifacts are/
   aren't what the vendor shipped", which needs no per-device signature,
   only the server's own signing key (the same one that signs every
   Reject/Lease). */
const FREE_CHECKIN_STAGE_FIELDS = [
    'v', 'stage', 'machine_id', 'device_key_hash',
    'build_id', 'ex5_hash', 'ex4_hash', 'dll32_hash', 'dll64_hash',
    'machineid32_hash', 'machineid64_hash', 'broker_hash',
    // 2026 hardening: optional (not required like the hashes above) - purely
    // diagnostic, attached to the -2 log row when this check-in turns out to
    // be an artifact_mismatch. See nutricula_normalize_platform_profile().
    'platform_profile',
];
/* build_id/ex5_hash/dll32_hash/dll64_hash/machineid32_hash/machineid64_hash/
   broker_hash: Artifact Evidence (architecture points 47-49/88) - the
   Coordinator's own measured hashes of the currently-installed EX5/DLL32/
   DLL64/MachineId32/MachineId64/Broker, bound into the SAME device
   signature that proves possession of the license's private key.
   machineid32_hash/machineid64_hash were added alongside dll32_hash/
   dll64_hash (not alongside broker_hash) because MachineId32/64.dll are
   unconditional, always-both-present artifacts just like the License Check
   DLLs - never trusted as bare client-reported values (point 46/122) - see
   the comparison against nutricula_build_manifests below, which is the only
   source of "expected" hashes this endpoint ever consults. (The Windows
   Service host was removed in 2026 - the Broker is the sole Coordinator -
   so there is no longer a service_hash field.) */
const VERIFY_STAGE_FIELDS = [
    'v', 'stage', 'license_id', 'machine_id', 'machine_id_alt', 'device_key_hash', 'local_ip', 'challenge_id', 'signature',
    'build_id', 'ex5_hash', 'ex4_hash', 'dll32_hash', 'dll64_hash',
    'machineid32_hash', 'machineid64_hash', 'broker_hash',
    'refresh_token', 'platform_profile',
];

/* Cheap, opportunistic housekeeping - runs as a side effect of normal
   traffic so no separate cron job is required. Bounded with LIMIT so any
   single request's added cost stays small; it simply catches up over
   subsequent requests. */
function nutricula_cleanup_old_challenges(mysqli $conn): void
{
    $conn->query(
        "DELETE FROM nutricula_license_challenges
         WHERE expires_at < (NOW() - INTERVAL 1 DAY)
         LIMIT 100"
    );
}

/* Lightweight defense against unauthenticated challenge spam now that
   issuing a challenge itself carries no time lock (see the note at the
   'challenge' stage below for why that moved to verify-after-signature).
   This does not gate on WHO is asking, only on HOW OFTEN for this specific
   license - legitimate traffic is at most one challenge roughly every 55
   minutes, so this threshold is nowhere near legitimate usage. */
function nutricula_challenge_rate_ok(mysqli $conn, int $licenseDbId, int $now): bool
{
    $cutoff = date('Y-m-d H:i:s', $now - 60);
    $stmt = $conn->prepare(
        "SELECT COUNT(*) c FROM nutricula_license_activity
         WHERE license_id=? AND request_type='challenge' AND occurred_at>=?"
    );
    if (!$stmt) return true; // fail open on a logging-path error, not security-critical
    $stmt->bind_param('is', $licenseDbId, $cutoff);
    $stmt->execute();
    $count = (int)($stmt->get_result()->fetch_assoc()['c'] ?? 0);
    $stmt->close();
    return $count < 5;
}

try {
    $config = nutricula_load_config();
    $conn = nutricula_db($config);
    // DDoS mitigation: rejects cheaply (before any decrypt/DB-heavy work)
    // if this IP has exceeded the request rate for this endpoint - see
    // nutricula_rate_limit_check()'s own doc comment for the exact limit
    // and why a reverse proxy/WAF layer in front of this is still recommended.
    nutricula_rate_limit_check($conn, $config, 'license_check');
    $conn->query("SET time_zone = '+00:00'");

    $minGapSeconds = (int)$config['min_request_gap_seconds']; // guaranteed present - see nutricula_validate_config()

    $outer = nutricula_require_post_data();
    $inner = nutricula_gcm_decrypt($outer, $config);
    $fields = nutricula_strict_parse_fields($inner, CHECK_ALLOWED_FIELDS);

    if ((string)($fields['v'] ?? '') !== '3') throw new RuntimeException('Invalid protocol version.');

    $stage = trim(nutricula_required_field($fields, 'stage'));
    if ($stage !== 'challenge' && $stage !== 'verify' && $stage !== 'free_checkin') {
        throw new RuntimeException('Invalid stage.');
    }

    if ($stage === 'free_checkin') {
        foreach (array_keys($fields) as $key) {
            if (!in_array($key, FREE_CHECKIN_STAGE_FIELDS, true)) {
                throw new RuntimeException('Field not valid for this stage: ' . $key);
            }
        }
        // Both optional here (unlike verify) - a free install's machine_id
        // can genuinely fail to generate on some systems (see
        // NutriculaMachineId's own acceptance logic); the device key alone
        // is then sufficient to recognize this computer across check-ins.
        // At least one of the two must be present and validly formatted.
        $rawMachineId = isset($fields['machine_id']) ? strtoupper(trim($fields['machine_id'])) : '';
        $rawDeviceKeyHash = isset($fields['device_key_hash']) ? strtoupper(trim($fields['device_key_hash'])) : '';
        $checkinMachineId = ($rawMachineId !== '') ? $rawMachineId : null;
        $checkinDeviceKeyHash = ($rawDeviceKeyHash !== '') ? $rawDeviceKeyHash : null;
        if ($checkinMachineId === null && $checkinDeviceKeyHash === null) {
            throw new RuntimeException('At least one of machine_id or device_key_hash is required.');
        }
        if ($checkinMachineId !== null && !preg_match('/\A[0-9A-F]{64}\z/', $checkinMachineId)) {
            throw new RuntimeException('Invalid machine ID.');
        }
        if ($checkinDeviceKeyHash !== null && !preg_match('/\A[0-9A-F]{64}\z/', $checkinDeviceKeyHash)) {
            throw new RuntimeException('Invalid device key hash.');
        }

        /* Same per-IP rate limit machinery already used elsewhere in this
           file (e.g. the challenge stage below) - a single install pinging
           roughly every 30 minutes is completely normal and unaffected,
           while someone scripting rapid-fire fake check-ins to inflate the
           free-tier count gets throttled the same way any other endpoint
           here already throttles abuse.
           Reuse the connection opened above (which already ran
           SET time_zone='+00:00' at line 99) - a previous version reopened a
           SECOND connection here, which leaked the first and, more
           importantly, ran without the UTC session tz, so the NOW() writes in
           nutricula_track_unlicensed_checkin below landed in the server's
           default timezone instead of UTC. */
        nutricula_rate_limit_check($conn, $config, 'free_checkin');

        nutricula_track_unlicensed_checkin($conn, $checkinMachineId, $checkinDeviceKeyHash);

        /* 2026 hardening (owner's explicit request - "security mechanisms
           shouldn't depend on license type, free or pro"): a free-tier
           install now gets the SAME authenticated mandatory-update and
           server-authoritative artifact-hash validation Premium/Transfer
           already receive via the challenge/verify flow, instead of an
           unconditional, unauthenticated "OK". build_id/the 7 hashes are
           REQUIRED here, exactly like the verify stage - no backward-compat
           allowance, since there is no older Coordinator build in the field
           to accommodate (Nutricula has not shipped publicly yet). */
        $buildId = trim(nutricula_required_field($fields, 'build_id'));
        $ex5Hash = strtolower(trim(nutricula_required_field($fields, 'ex5_hash')));
        $ex4Hash = strtolower(trim(nutricula_required_field($fields, 'ex4_hash')));
        $dll32Hash = strtolower(trim(nutricula_required_field($fields, 'dll32_hash')));
        $dll64Hash = strtolower(trim(nutricula_required_field($fields, 'dll64_hash')));
        $machineid32Hash = strtolower(trim(nutricula_required_field($fields, 'machineid32_hash')));
        $machineid64Hash = strtolower(trim(nutricula_required_field($fields, 'machineid64_hash')));
        $brokerHash = strtolower(trim(nutricula_required_field($fields, 'broker_hash')));

        $wellFormed = ($buildId !== '' && strlen($buildId) <= 64);
        foreach ([$ex5Hash, $ex4Hash, $dll32Hash, $dll64Hash, $machineid32Hash, $machineid64Hash, $brokerHash] as $h) {
            if (!preg_match('/\A[0-9a-f]{64}\z/', $h)) $wellFormed = false;
        }

        // Malformed Artifact Evidence is treated identically to
        // well-formed-but-wrong below (artifact_mismatch) rather than a
        // hard error - there is no per-device signature on this stage to
        // tell "tampered" apart from "simply dropped/truncated in transit",
        // and either way the Coordinator now treats the outcome identically
        // (TIER_FAILED / "-2", not just a demotion to TIER_FREE - see the
        // client-side mapping in CoordinatorCore.cpp).
        $manifestRow = null;
        if ($wellFormed) {
            $manifestStmt = $conn->prepare(
                'SELECT version, ex5_sha256, ex4_sha256, dll32_sha256, dll64_sha256,
                        machineid32_sha256, machineid64_sha256,
                        broker32_sha256, broker64_sha256
                 FROM nutricula_build_manifests WHERE build_id=? LIMIT 1'
            );
            if ($manifestStmt) {
                $manifestStmt->bind_param('s', $buildId);
                $manifestStmt->execute();
                $manifestRow = $manifestStmt->get_result()->fetch_assoc();
                $manifestStmt->close();
            }
        }

        // Accepts EITHER the 32-bit or 64-bit expected Broker hash - see
        // the identical reasoning at the verify stage's $brokerMatches.
        $brokerMatches = $manifestRow && (
            hash_equals((string)$manifestRow['broker32_sha256'], $brokerHash) ||
            hash_equals((string)$manifestRow['broker64_sha256'], $brokerHash)
        );
        $artifactsOk = $wellFormed && $manifestRow &&
            hash_equals((string)$manifestRow['ex5_sha256'], $ex5Hash) &&
            hash_equals((string)$manifestRow['ex4_sha256'], $ex4Hash) &&
            hash_equals((string)$manifestRow['dll32_sha256'], $dll32Hash) &&
            hash_equals((string)$manifestRow['dll64_sha256'], $dll64Hash) &&
            hash_equals((string)$manifestRow['machineid32_sha256'], $machineid32Hash) &&
            hash_equals((string)$manifestRow['machineid64_sha256'], $machineid64Hash) &&
            $brokerMatches;

        $reason = null;
        if (!$artifactsOk) {
            $reason = 'artifact_mismatch';
            // 2026 hardening: same -2/support logging as the verify stage's
            // artifact_mismatch - see that site's comment for the full
            // reasoning. Builds as precise a detail string as this request
            // lets us determine (malformed fields, no manifest row at all,
            // or exactly which hash field(s) genuinely mismatched).
            if (!$wellFormed) {
                $mismatchDetail = 'malformed build_id/hash field(s)';
            } elseif (!$manifestRow) {
                $mismatchDetail = 'no manifest row found for build_id=' . $buildId;
            } else {
                $mismatchedFields = [];
                if (!hash_equals((string)$manifestRow['ex5_sha256'], $ex5Hash)) $mismatchedFields[] = 'ex5_hash';
                if (!hash_equals((string)$manifestRow['ex4_sha256'], $ex4Hash)) $mismatchedFields[] = 'ex4_hash';
                if (!hash_equals((string)$manifestRow['dll32_sha256'], $dll32Hash)) $mismatchedFields[] = 'dll32_hash';
                if (!hash_equals((string)$manifestRow['dll64_sha256'], $dll64Hash)) $mismatchedFields[] = 'dll64_hash';
                if (!hash_equals((string)$manifestRow['machineid32_sha256'], $machineid32Hash)) $mismatchedFields[] = 'machineid32_hash';
                if (!hash_equals((string)$manifestRow['machineid64_sha256'], $machineid64Hash)) $mismatchedFields[] = 'machineid64_hash';
                if (!$brokerMatches) $mismatchedFields[] = 'broker_hash';
                $mismatchDetail = 'build_id=' . $buildId . '; mismatched field(s): ' . implode(', ', $mismatchedFields);
            }
            nutricula_log_minus2(
                $conn, 'free', 'artifact_mismatch', $mismatchDetail,
                null, null,
                $checkinMachineId, null, $checkinDeviceKeyHash, $buildId, nutricula_client_ip($config),
                nutricula_normalize_platform_profile($fields['platform_profile'] ?? null)
            );
        } else {
            $latestVersion = (string)($config['latest_version'] ?? '');
            $installedVersion = (string)($manifestRow['version'] ?? '');
            if ($latestVersion !== '' && $installedVersion !== '' &&
                version_compare($installedVersion, $latestVersion, '<')) {
                $reason = 'update_required';
            }
        }

        $responseBody = 'NL3-FREE-OK';
        if ($reason !== null) {
            // Same signed-Reject format and server signing key the
            // Premium/Transfer verify stage uses (nutricula_reject() /
            // nutricula_server_sign()) - the Coordinator's existing
            // LicenseProtocol::DecryptAndVerify already knows how to verify
            // this exact format, so nothing new is needed client-side to
            // trust it. No per-device signature is involved or required -
            // this endpoint is only vouching for "this build's artifacts",
            // not for license ownership.
            $now2 = time();
            $canonical = 'reason=' . $reason . '|requested_at=' . $now2 . '|retry_after_seconds=0';
            try {
                $sig = nutricula_server_sign($canonical, $config);
                $responseBody = 'NL3-REJECT|' . $canonical . '|server_signature=' . $sig;
            } catch (Throwable $e) {
                // Signing failed (e.g. key file unreadable) - fail open to
                // the harmless plain-OK default, same spirit as
                // nutricula_reject()'s own fallback.
                $responseBody = 'NL3-FREE-OK';
            }
        }

        $conn->close();

        http_response_code(200);
        header('Content-Type: text/plain; charset=UTF-8');
        try {
            echo nutricula_gcm_encrypt($responseBody, $config);
        } catch (Throwable $e) {
            echo 'no';
        }
        exit;
    }

    /* Reject any field that doesn't belong to THIS stage specifically, not
       just fields unknown to the endpoint as a whole - e.g. a 'signature'
       field has no business appearing on a challenge request. */
    $stageAllowed = $stage === 'challenge' ? CHALLENGE_STAGE_FIELDS : VERIFY_STAGE_FIELDS;
    foreach (array_keys($fields) as $key) {
        if (!in_array($key, $stageAllowed, true)) {
            throw new RuntimeException('Field not valid for this stage: ' . $key);
        }
    }

    $licenseId = trim(nutricula_required_field($fields, 'license_id'));
    $machineId = strtoupper(trim(nutricula_required_field($fields, 'machine_id')));
    /* Secondary machine_id variant (2026 hardening) - see the identical,
       more detailed comment in nutricula_computer_based_signup.php.
       Optional: defaults to $machineId when absent (every non-Windows-
       physical client, and any older client predating this feature). */
    $machineIdAltRaw = trim((string)($fields['machine_id_alt'] ?? ''));
    $machineIdAlt = ($machineIdAltRaw !== '') ? strtoupper($machineIdAltRaw) : $machineId;
    $deviceKeyHash = strtoupper(trim(nutricula_required_field($fields, 'device_key_hash')));
    $localIp = trim((string)($fields['local_ip'] ?? ''));
    $observedIp = nutricula_client_ip($config);

    if (!nutricula_is_valid_uuid($licenseId)) throw new RuntimeException('Invalid license id.');
    if (!preg_match('/\A[0-9A-F]{64}\z/', $machineId)) throw new RuntimeException('Invalid machine ID.');
    if (!preg_match('/\A[0-9A-F]{64}\z/', $machineIdAlt)) throw new RuntimeException('Invalid machine ID.');
    if (!preg_match('/\A[0-9A-F]{64}\z/', $deviceKeyHash)) throw new RuntimeException('Invalid device key hash.');
    if ($localIp !== '' && filter_var($localIp, FILTER_VALIDATE_IP) === false) throw new RuntimeException('Invalid local IP.');

    /* Wraps nutricula_reject() to also record a free-tier check-in first,
       for every reject reason EXCEPT the two that do NOT result in
       TIER_FREE client-side (update_required -> TIER_UPDATE_REQUIRED,
       blocked -> TIER_BLOCKED - see CoordinatorCore.cpp's tier mapping).
       Every other reason here - license_not_found, machine_mismatch,
       device_key_mismatch, license_inactive, license_expired,
       artifact_mismatch, signature_invalid, challenge_*, too_early, etc. -
       all leave the client at TIER_FREE, and per the "track every free-tier
       outcome, however it happens" requirement, all of them get tracked
       identically here rather than requiring a separate tracking call
       hand-added at each individual reject site (error-prone with this
       many call sites - centralizing it here means a future new reject
       reason is tracked correctly by default, not by remembering to add a
       line at the new call site). */
    $rejectTracked = function (string $reason, int $retryAfterSeconds = 0) use ($config, $conn, $machineId, $deviceKeyHash): never {
        if ($reason !== 'update_required' && $reason !== 'blocked') {
            nutricula_track_unlicensed_checkin($conn, $machineId, $deviceKeyHash);
        }
        nutricula_reject($config, $reason, $retryAfterSeconds);
    };

    $stmt = $conn->prepare(
        'SELECT * FROM nutricula_licenses WHERE license_uuid=? LIMIT 1'
    );
    if (!$stmt) throw new RuntimeException('DB prepare failed.');
    $stmt->bind_param('s', $licenseId);
    $stmt->execute();
    $license = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    /* --- First-pass checks, both stages, fixed order ---
       These are a cheap early gate on an UNLOCKED read. They are NOT the
       final authorization decision for verify - see the fresh, row-locked
       re-check right before a lease is actually issued, below, which closes
       the time-of-check-to-time-of-use gap between this read and the
       eventual commit (license state could otherwise change in between -
       e.g. an admin revoking the license mid-request). */
    if (!$license) {
        $rejectTracked('license_not_found');
    }

    $licenseDbId = (int)$license['id'];

    /* VPS IP-Binding - see nutricula_effective_machine_id()'s doc comment
       in license_common.php. $machineId stays the raw, client-reported
       value everywhere else below (including the signed lease canonical
       further down) - only this comparison uses the effective (possibly
       IP-augmented) form. For any non-VPS device_type, this function
       returns $machineId completely unchanged, so this check is byte-for-
       byte identical to the pre-existing behavior for every license that
       isn't device_type='windows_vm'. */
    $effectiveMachineId = nutricula_effective_machine_id((string)$license['device_type'], $machineId, $observedIp);
    $effectiveMachineIdAlt = nutricula_effective_machine_id((string)$license['device_type'], $machineIdAlt, $observedIp);
    $primaryMatches = ($effectiveMachineId !== '' && hash_equals((string)$license['machine_id'], $effectiveMachineId));
    $altMatches = ($effectiveMachineIdAlt !== '' && hash_equals((string)$license['machine_id'], $effectiveMachineIdAlt));
    if (!$primaryMatches && !$altMatches) {
        $rejectTracked('machine_mismatch');
    }
    /* Whichever raw (client-reported, non-effective) value actually
       matched what's on file - this is what must go into the signed
       Lease canonical below, NOT unconditionally $machineId, since a
       customer activated via the WithGuid fallback has $license['machine_id']
       equal to the effective form of $machineIdAlt, not $machineId. The
       client's own Layer 1 local check (CoordinatorCore.cpp) compares the
       Lease's machine_id against its own freshly recomputed value, so the
       Lease must carry whichever raw variant genuinely corresponds to
       what was stored. */
    $matchedRawMachineId = $primaryMatches ? $machineId : $machineIdAlt;
    if (!hash_equals((string)$license['device_public_key_hash'], $deviceKeyHash)) {
        $rejectTracked('device_key_mismatch');
    }
    if ($license['status'] !== 'active') {
        $rejectTracked('license_inactive');
    }
    $now = time();
    if ((int)$license['license_expires_at'] <= $now) {
        $rejectTracked('license_expired');
    }

    /* No longer scoring on local_ip vs observed_ip mismatch - that check
       relied entirely on a client-claimed value that changes routinely on
       VPS/VM hosts and never actually indicated anything about hardware
       uniqueness (see the accompanying research notes). local_ip is kept
       only for optional monitoring/reference via nutricula_log_activity
       below. The legitimate, server-observed abuse-pattern check further
       down (distinct observed_ip count per device key) is unaffected. */
    $riskScore = 0;

    if ($stage === 'challenge') {
        /* IMPORTANT DESIGN NOTE: the anti-abuse time lock (min_request_gap_seconds)
           is deliberately NOT checked here anymore. The fields required to reach
           this point - license_id, machine_id, device_key_hash - are not secret
           (machine_id is routinely sent by the client itself; device_key_hash is
           derived from a public key). Anyone who merely knows them, WITHOUT the
           device's private key, could otherwise trigger this branch and touch
           last_request_time, artificially time-locking out the real device even
           though nothing was actually proven. The time lock now only fires in the
           'verify' branch below, and only AFTER a valid ECDSA signature has been
           checked - i.e. only once genuine possession of the private key is
           established. A failure at THIS stage (not found / mismatched / inactive
           / expired) is a different problem entirely and never reaches lease
           issuance, so it has nothing to do with "was this device's identity
           copied" and correctly does not touch the time lock at all. */

        if (!nutricula_challenge_rate_ok($conn, $licenseDbId, $now)) {
            nutricula_log_activity($conn, $licenseDbId, $machineId, $deviceKeyHash, $localIp, $observedIp, 'challenge', 'challenge_rate_limited', $riskScore);
            // Do NOT close $conn here: $rejectTracked records a free-tier
            // check-in (nutricula_track_unlicensed_checkin) that needs the
            // connection open; nutricula_reject exits immediately afterward
            // and PHP closes the connection on exit anyway.
            $rejectTracked('challenge_rate_limited', 60);
        }

        /* Housekeeping: any earlier still-unused challenge for this license is
           now moot - only the challenge issued here should ever be verifiable.
           This isn't itself the fix for "an old and a new challenge both valid
           at once" (challenge_ttl_seconds is 60s, far shorter than the 53-minute
           gap, so that scenario doesn't actually arise the way it might for a
           much longer challenge TTL) - it's just good hygiene that also keeps
           the challenges table smaller. */
        $invalidateOld = $conn->prepare(
            'UPDATE nutricula_license_challenges SET used_at=NOW() WHERE license_id=? AND used_at IS NULL'
        );
        if ($invalidateOld) {
            $invalidateOld->bind_param('i', $licenseDbId);
            $invalidateOld->execute();
            $invalidateOld->close();
        }
        nutricula_cleanup_old_challenges($conn);

        $challengeId = nutricula_uuid();
        $nonce = random_bytes(32);
        $expires = $now + (int)$config['challenge_ttl_seconds'];

        $insert = $conn->prepare(
            'INSERT INTO nutricula_license_challenges
             (challenge_id,license_id,nonce,request_ip,created_at,expires_at)
             VALUES (?,?,?,?,FROM_UNIXTIME(?),FROM_UNIXTIME(?))'
        );
        if (!$insert) throw new RuntimeException('DB prepare failed.');
        $insert->bind_param('sissii', $challengeId, $licenseDbId, $nonce, $observedIp, $now, $expires);
        if (!$insert->execute()) throw new RuntimeException('Challenge insert failed.');
        $insert->close();

        nutricula_log_activity($conn, $licenseDbId, $machineId, $deviceKeyHash, $localIp, $observedIp, 'challenge', null, $riskScore);

        $conn->close();

        // CRITICAL FIX (found via full end-to-end testing): the C++ side
        // (LicenseProtocol.cpp) has always required a server signature on
        // Challenge responses ("Invalid - unsigned, no longer accepted" -
        // this was the whole point of the original Reject/Challenge
        // signing fix) - but this endpoint was never actually signing it,
        // meaning every single Challenge ever issued was silently rejected
        // by every client, and NO license could ever be activated or
        // renewed. Canonical is signed WITHOUT the "NL3-CHALLENGE" prefix,
        // exactly like the Lease canonical below - the client strips that
        // prefix before verifying for the same reason.
        $challengeCanonical =
            'challenge_id=' . $challengeId .
            '|nonce=' . base64_encode($nonce) .
            '|expires_at=' . $expires;
        $challengeSignature = nutricula_server_sign($challengeCanonical, $config);

        $response =
            'NL3-CHALLENGE' .
            '|' . $challengeCanonical .
            '|server_signature=' . $challengeSignature;

        nutricula_ok_gcm($response, $config);
    }

    if ($stage === 'verify') {
        $challengeId = trim(nutricula_required_field($fields, 'challenge_id'));
        $signatureB64 = trim(nutricula_required_field($fields, 'signature'));
        if (!nutricula_is_valid_uuid($challengeId) || $signatureB64 === '') {
            $rejectTracked('challenge_not_found');
        }

        /* Artifact Evidence (architecture points 47-49/88) - required on
           every verify request, not optional. A Coordinator that cannot
           produce these (e.g. because its own integrity check already
           failed locally) does not even reach this stage - see
           CoordinatorCore's own gate before ever sending a verify request. */
        $buildId = trim(nutricula_required_field($fields, 'build_id'));
        $ex5Hash = strtolower(trim(nutricula_required_field($fields, 'ex5_hash')));
        $ex4Hash = strtolower(trim(nutricula_required_field($fields, 'ex4_hash')));
        $dll32Hash = strtolower(trim(nutricula_required_field($fields, 'dll32_hash')));
        $dll64Hash = strtolower(trim(nutricula_required_field($fields, 'dll64_hash')));
        $machineid32Hash = strtolower(trim(nutricula_required_field($fields, 'machineid32_hash')));
        $machineid64Hash = strtolower(trim(nutricula_required_field($fields, 'machineid64_hash')));
        $brokerHash = strtolower(trim(nutricula_required_field($fields, 'broker_hash')));

        /* 2026 hardening: every "artifact_mismatch" reject here is a
           confirmed-tampering verdict the client maps to TIER_FAILED/"-2"
           (see CoordinatorCore.cpp) - log it, with as precise a reason as
           this request lets us determine, to nutricula_minus2_log so
           support can explain a customer's -2 report without guessing. */
        $verifyPlatformProfile = nutricula_normalize_platform_profile($fields['platform_profile'] ?? null);
        $logArtifactMismatch = function (string $detail) use ($conn, $licenseDbId, $license, $machineId, $machineIdAlt, $deviceKeyHash, $buildId, $observedIp, $verifyPlatformProfile): void {
            nutricula_log_minus2(
                $conn, 'licensed', 'artifact_mismatch', $detail,
                $licenseDbId, (string)$license['user_email'],
                $machineId, $machineIdAlt, $deviceKeyHash, $buildId, $observedIp,
                $verifyPlatformProfile
            );
        };

        if ($buildId === '' || strlen($buildId) > 64) {
            $logArtifactMismatch('malformed build_id');
            $rejectTracked('artifact_mismatch');
        }
        $hashFieldsByName = [
            'ex5_hash' => $ex5Hash, 'ex4_hash' => $ex4Hash,
            'dll32_hash' => $dll32Hash, 'dll64_hash' => $dll64Hash,
            'machineid32_hash' => $machineid32Hash, 'machineid64_hash' => $machineid64Hash,
            'broker_hash' => $brokerHash,
        ];
        foreach ($hashFieldsByName as $fieldName => $h) {
            if (!preg_match('/\A[0-9a-f]{64}\z/', $h)) {
                $logArtifactMismatch('malformed ' . $fieldName);
                $rejectTracked('artifact_mismatch');
            }
        }

        $stmt = $conn->prepare(
            'SELECT * FROM nutricula_license_challenges WHERE challenge_id=? LIMIT 1'
        );
        if (!$stmt) throw new RuntimeException('DB prepare failed.');
        $stmt->bind_param('s', $challengeId);
        $stmt->execute();
        $challenge = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$challenge) $rejectTracked('challenge_not_found');
        if ((int)$challenge['license_id'] !== $licenseDbId) $rejectTracked('challenge_wrong_license');
        if ($challenge['used_at'] !== null) $rejectTracked('challenge_already_used');

        $challengeExpires = strtotime((string)$challenge['expires_at'] . ' UTC');
        if ($challengeExpires === false || $challengeExpires <= $now) {
            $rejectTracked('challenge_expired');
        }

        $nonceB64 = base64_encode($challenge['nonce']);
        $message =
            'NUTRICULA-RUNTIME-V3' .
            '|challenge_id=' . $challengeId .
            '|nonce=' . $nonceB64 .
            '|license_id=' . $licenseId .
            '|machine_id=' . $matchedRawMachineId .
            '|build_id=' . $buildId .
            '|ex5_hash=' . $ex5Hash .
            '|ex4_hash=' . $ex4Hash .
            '|dll32_hash=' . $dll32Hash .
            '|dll64_hash=' . $dll64Hash .
            '|machineid32_hash=' . $machineid32Hash .
            '|machineid64_hash=' . $machineid64Hash .
            '|broker_hash=' . $brokerHash;

        $publicKeyPem = nutricula_build_p256_pem((string)$license['device_public_key_b64']);
        if (!nutricula_verify_device_signature($publicKeyPem, $message, $signatureB64)) {
            $rejectTracked('signature_invalid');
        }

        /* Signature is now proven valid, so the reported hashes genuinely
           came from this license's own device key - not a network
           attacker. That still does not make them trustworthy VALUES
           though (architecture point 46/122: "Client نباید بتواند Expected
           Hash را تعریف کند") - compare against this server's OWN registry
           of what each build_id's artifacts should hash to. Never accept a
           build_id the server has no record of, and never accept a partial
           match (all four must agree). */
        $manifestStmt = $conn->prepare(
            'SELECT version, ex5_sha256, ex4_sha256, dll32_sha256, dll64_sha256,
                    machineid32_sha256, machineid64_sha256,
                    broker32_sha256, broker64_sha256
             FROM nutricula_build_manifests WHERE build_id=? LIMIT 1'
        );
        if (!$manifestStmt) throw new RuntimeException('DB prepare failed.');
        $manifestStmt->bind_param('s', $buildId);
        $manifestStmt->execute();
        $expectedManifest = $manifestStmt->get_result()->fetch_assoc();
        $manifestStmt->close();

        /* Both architectures of the Broker genuinely ship to customers
           (32-bit Windows hosts are a real, supported case) - the reporting
           Coordinator only ever measures and reports its OWN binary's hash
           (it has no way to even know the other architecture's file, which
           isn't present on its machine), so this server-side check accepts
           a match against EITHER the 32-bit or the 64-bit expected value.
           This is still exact equality against a server-known-good value
           either way - never a looser check - just against one of two valid
           values instead of one. (The Windows Service host was removed in
           2026 - the Broker is the sole Coordinator - so there is no
           service_hash to check anymore.) */
        $brokerMatches = $expectedManifest && (
            hash_equals((string)$expectedManifest['broker32_sha256'], $brokerHash) ||
            hash_equals((string)$expectedManifest['broker64_sha256'], $brokerHash)
        );

        if (!$expectedManifest) {
            $logArtifactMismatch('no manifest row found for build_id=' . $buildId);
            $rejectTracked('artifact_mismatch');
        }
        $mismatchedFields = [];
        if (!hash_equals((string)$expectedManifest['ex5_sha256'], $ex5Hash)) $mismatchedFields[] = 'ex5_hash';
        if (!hash_equals((string)$expectedManifest['ex4_sha256'], $ex4Hash)) $mismatchedFields[] = 'ex4_hash';
        if (!hash_equals((string)$expectedManifest['dll32_sha256'], $dll32Hash)) $mismatchedFields[] = 'dll32_hash';
        if (!hash_equals((string)$expectedManifest['dll64_sha256'], $dll64Hash)) $mismatchedFields[] = 'dll64_hash';
        if (!hash_equals((string)$expectedManifest['machineid32_sha256'], $machineid32Hash)) $mismatchedFields[] = 'machineid32_hash';
        if (!hash_equals((string)$expectedManifest['machineid64_sha256'], $machineid64Hash)) $mismatchedFields[] = 'machineid64_hash';
        if (!$brokerMatches) $mismatchedFields[] = 'broker_hash';
        if (!empty($mismatchedFields)) {
            $logArtifactMismatch(
                'build_id=' . $buildId . '; mismatched field(s): ' . implode(', ', $mismatchedFields)
            );
            $rejectTracked('artifact_mismatch');
        }

        /* Mandatory-update gate: the artifact hashes above proved this
           build_id's files are genuinely unmodified, but that alone doesn't
           mean it's the CURRENT build - an old, still-intact, still validly-
           signed build can keep matching its own manifest forever. Comparing
           against 'latest_version' in license_config.php is what actually
           forces an upgrade path: if the installed build's version is older
           than the configured latest, refuse Tier 2 with a distinct reason
           (mapped by the Coordinator to TIER_UPDATE_REQUIRED, -50, rather
           than the ordinary TIER_FREE) so the EA can show a clear
           "please update" state instead of a generic unlicensed one. Uses
           PHP's own version_compare() (the same semantics as e.g. "3.0" <
           "3.1" < "3.10"), not a naive string comparison. */
        $latestVersion = (string)($config['latest_version'] ?? '');
        $installedVersion = (string)($expectedManifest['version'] ?? '');
        if ($latestVersion !== '' && $installedVersion !== '' &&
            version_compare($installedVersion, $latestVersion, '<')) {
            $rejectTracked('update_required');
        }

        /* Signature is now proven valid - genuine possession of the private
           key is established. Everything from here on happens against a
           freshly row-locked read of the license (closing the TOCTOU gap
           between the unlocked check above and this point), using a freshly
           captured $finalNow rather than the earlier $now - all the crypto
           and DB work above takes real, if small, time. THIS is also where
           the anti-abuse time lock is evaluated - see the design note in the
           challenge branch above for why it belongs here and not there. */
        $conn->begin_transaction();

        $lockStmt = $conn->prepare('SELECT id, product_id, status, license_expires_at, current_refresh_token_hash, token_suspicious, blocked_until FROM nutricula_licenses WHERE id=? FOR UPDATE');
        if (!$lockStmt) throw new RuntimeException('DB prepare failed.');
        $lockStmt->bind_param('i', $licenseDbId);
        $lockStmt->execute();
        $lockedLicense = $lockStmt->get_result()->fetch_assoc();
        $lockStmt->close();

        $finalNow = time();

        if (!$lockedLicense || $lockedLicense['status'] !== 'active') {
            $conn->rollback();
            nutricula_log_activity($conn, $licenseDbId, $machineId, $deviceKeyHash, $localIp, $observedIp, 'verify', 'license_inactive', $riskScore);
            // Keep $conn open for $rejectTracked's free-tier check-in record
            // (see the challenge_rate_limited site above); PHP closes it on exit.
            $rejectTracked('license_inactive');
        }
        if ((int)$lockedLicense['license_expires_at'] <= $finalNow) {
            $conn->rollback();
            nutricula_log_activity($conn, $licenseDbId, $machineId, $deviceKeyHash, $localIp, $observedIp, 'verify', 'license_expired', $riskScore);
            // Keep $conn open for $rejectTracked's free-tier check-in record.
            $rejectTracked('license_expired');
        }

        $stmt = $conn->prepare(
            'UPDATE nutricula_license_challenges SET used_at=NOW() WHERE id=? AND used_at IS NULL'
        );
        if (!$stmt) throw new RuntimeException('DB prepare failed.');
        $challengeDbId = (int)$challenge['id'];
        $stmt->bind_param('i', $challengeDbId);
        $stmt->execute();
        $affected = $stmt->affected_rows;
        $stmt->close();
        if ($affected !== 1) {
            $conn->rollback();
            $rejectTracked('challenge_already_used');
        }

        /* THE time lock - see the design note above. A signature has already
           been proven valid at this point, so a rejection here genuinely
           means "correct device credentials, but too soon" - exactly the
           "identity/device key was copied" signal this is meant to catch.
           Set to a low 9-minute floor (min_request_gap_seconds) since the
           actual anti-clone protection now lives in the rotating refresh
           token below, not in this timer - this floor only exists to stop
           pure request flooding, not to detect cloning by itself. */
        $lock = nutricula_check_and_touch_time_lock($conn, $licenseDbId, $minGapSeconds, $finalNow);
        if (!$lock['allowed']) {
            $conn->commit(); // the challenge-used and time-lock touches must still persist
            nutricula_log_activity($conn, $licenseDbId, $machineId, $deviceKeyHash, $localIp, $observedIp, 'verify', 'too_early', $riskScore);
            // Keep $conn open for $rejectTracked's free-tier check-in record
            // (the commit above already persisted the time-lock touch).
            $rejectTracked('too_early', $lock['retry_after_seconds']);
        }

        /* THE rotating refresh-token check - this is what actually detects
           a cloned machine_id + device key (see the design discussion).
           Must run on the freshly FOR-UPDATE-locked row ($lockedLicense),
           not the earlier $license snapshot. */
        $clientRefreshToken = (string)($fields['refresh_token'] ?? '');
        $tokenResult = nutricula_check_and_rotate_token($conn, $config, $lockedLicense, $clientRefreshToken);
        if ($tokenResult['action'] === 'blocked') {
            $conn->commit(); // persist the blocked_until write
            nutricula_log_activity($conn, $licenseDbId, $machineId, $deviceKeyHash, $localIp, $observedIp, 'verify', 'blocked', $riskScore);
            $conn->close();
            $rejectTracked('blocked', (int)$config['clone_block_hours'] * 3600);
        }
        $newRefreshToken = (string)$tokenResult['new_token'];

        /* Basic clone-monitoring signal: how many distinct IPs used this key recently? */
        $windowMinutes = 10;
        $cutoff = date('Y-m-d H:i:s', $finalNow - ($windowMinutes * 60));
        $stmt = $conn->prepare(
            'SELECT COUNT(DISTINCT observed_ip) AS c
             FROM nutricula_license_activity
             WHERE device_public_key_hash=? AND occurred_at>=?'
        );
        if (!$stmt) throw new RuntimeException('DB prepare failed.');
        $stmt->bind_param('ss', $deviceKeyHash, $cutoff);
        $stmt->execute();
        $ipCount = (int)($stmt->get_result()->fetch_assoc()['c'] ?? 0);
        $stmt->close();
        if ($ipCount >= 3) $riskScore += 50;

        $licenseExpires = (int)$lockedLicense['license_expires_at'];

        nutricula_touch_success($conn, $licenseDbId, $finalNow);

        $update = $conn->prepare(
            'UPDATE nutricula_licenses
             SET last_observed_ip=?, last_seen_at=NOW()
             WHERE id=?'
        );
        if (!$update) throw new RuntimeException('DB prepare failed.');
        $update->bind_param('si', $observedIp, $licenseDbId);
        if (!$update->execute()) throw new RuntimeException('DB update failed.');
        $update->close();

        nutricula_log_activity($conn, $licenseDbId, $machineId, $deviceKeyHash, $localIp, $observedIp, 'verify', null, $riskScore);

        $conn->commit();

        $canonical =
            'v=3' .
            '|license_id=' . $licenseId .
            '|product_id=' . (int)$lockedLicense['product_id'] .
            '|machine_id=' . $matchedRawMachineId .
            '|device_key_hash=' . $deviceKeyHash .
            '|license_expires_at=' . $licenseExpires .
            '|requested_at=' . $finalNow .
            '|refresh_token=' . $newRefreshToken;

        $serverSignature = nutricula_server_sign($canonical, $config);
        $lease = 'NL3|' . $canonical . '|server_signature=' . $serverSignature;

        $conn->close();
        nutricula_ok_gcm($lease, $config);
    }

    nutricula_reject($config, 'invalid_stage');

} catch (Throwable $e) {
    if (isset($conn) && $conn instanceof mysqli) {
        try { $conn->rollback(); } catch (Throwable $ignored) {}
        try { $conn->close(); } catch (Throwable $ignored) {}
    }
    error_log('[Nutricula license check] ' . $e->getMessage());
    $fallback = $config ?? null;
    if (is_array($fallback)) nutricula_no($fallback);
    http_response_code(500);
    exit('no');
}
