<?php

declare(strict_types=1);

date_default_timezone_set('UTC');

require_once __DIR__ . '/license_common.php';

/* Combined whitelist across both stages - the per-stage subset is enforced
   separately right after 'stage' is known, so a verify-only field (e.g.
   signature) appearing in a challenge request is still rejected. */
const CHECK_ALLOWED_FIELDS = [
    'v', 'stage', 'license_id', 'machine_id', 'device_key_hash', 'local_ip',
    'challenge_id', 'signature', 'build_id', 'ex5_hash', 'ex4_hash', 'dll32_hash', 'dll64_hash', 'service_hash', 'broker_hash',
];
const CHALLENGE_STAGE_FIELDS = ['v', 'stage', 'license_id', 'machine_id', 'device_key_hash', 'local_ip'];
/* build_id/ex5_hash/dll32_hash/dll64_hash/service_hash: Artifact Evidence
   (architecture points 47-49/88) - the Coordinator's own measured hashes of
   the currently-installed EX5/DLL32/DLL64/Service, bound into the SAME
   device signature that proves possession of the license's private key.
   Never trusted as bare client-reported values (point 46/122) - see the
   comparison against nutricula_build_manifests below, which is the only
   source of "expected" hashes this endpoint ever consults. */
const VERIFY_STAGE_FIELDS = [
    'v', 'stage', 'license_id', 'machine_id', 'device_key_hash', 'local_ip', 'challenge_id', 'signature',
    'build_id', 'ex5_hash', 'ex4_hash', 'dll32_hash', 'dll64_hash', 'service_hash', 'broker_hash',
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
    if ($stage !== 'challenge' && $stage !== 'verify') {
        throw new RuntimeException('Invalid stage.');
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
    $deviceKeyHash = strtoupper(trim(nutricula_required_field($fields, 'device_key_hash')));
    $localIp = trim((string)($fields['local_ip'] ?? ''));
    $observedIp = nutricula_client_ip($config);

    if (!nutricula_is_valid_uuid($licenseId)) throw new RuntimeException('Invalid license id.');
    if (!preg_match('/\A[0-9A-F]{64}\z/', $machineId)) throw new RuntimeException('Invalid machine ID.');
    if (!preg_match('/\A[0-9A-F]{64}\z/', $deviceKeyHash)) throw new RuntimeException('Invalid device key hash.');
    if ($localIp !== '' && filter_var($localIp, FILTER_VALIDATE_IP) === false) throw new RuntimeException('Invalid local IP.');

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
        nutricula_track_unlicensed_checkin($conn, $machineId, $deviceKeyHash);
        nutricula_reject($config, 'license_not_found');
    }

    $licenseDbId = (int)$license['id'];

    if (!hash_equals((string)$license['machine_id'], $machineId)) {
        nutricula_reject($config, 'machine_mismatch');
    }
    if (!hash_equals((string)$license['device_public_key_hash'], $deviceKeyHash)) {
        nutricula_reject($config, 'device_key_mismatch');
    }
    if ($license['status'] !== 'active') {
        nutricula_reject($config, 'license_inactive');
    }
    $now = time();
    if ((int)$license['license_expires_at'] <= $now) {
        nutricula_reject($config, 'license_expired');
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
            $conn->close();
            nutricula_reject($config, 'challenge_rate_limited', 60);
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

        $response =
            'NL3-CHALLENGE' .
            '|challenge_id=' . $challengeId .
            '|nonce=' . base64_encode($nonce) .
            '|expires_at=' . $expires;

        nutricula_ok_gcm($response, $config);
    }

    if ($stage === 'verify') {
        $challengeId = trim(nutricula_required_field($fields, 'challenge_id'));
        $signatureB64 = trim(nutricula_required_field($fields, 'signature'));
        if (!nutricula_is_valid_uuid($challengeId) || $signatureB64 === '') {
            nutricula_reject($config, 'challenge_not_found');
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
        $serviceHash = strtolower(trim(nutricula_required_field($fields, 'service_hash')));
        $brokerHash = strtolower(trim(nutricula_required_field($fields, 'broker_hash')));
        if ($buildId === '' || strlen($buildId) > 64) nutricula_reject($config, 'artifact_mismatch');
        foreach ([$ex5Hash, $ex4Hash, $dll32Hash, $dll64Hash, $serviceHash, $brokerHash] as $h) {
            if (!preg_match('/\A[0-9a-f]{64}\z/', $h)) nutricula_reject($config, 'artifact_mismatch');
        }

        $stmt = $conn->prepare(
            'SELECT * FROM nutricula_license_challenges WHERE challenge_id=? LIMIT 1'
        );
        if (!$stmt) throw new RuntimeException('DB prepare failed.');
        $stmt->bind_param('s', $challengeId);
        $stmt->execute();
        $challenge = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$challenge) nutricula_reject($config, 'challenge_not_found');
        if ((int)$challenge['license_id'] !== $licenseDbId) nutricula_reject($config, 'challenge_wrong_license');
        if ($challenge['used_at'] !== null) nutricula_reject($config, 'challenge_already_used');

        $challengeExpires = strtotime((string)$challenge['expires_at'] . ' UTC');
        if ($challengeExpires === false || $challengeExpires <= $now) {
            nutricula_reject($config, 'challenge_expired');
        }

        $nonceB64 = base64_encode($challenge['nonce']);
        $message =
            'NUTRICULA-RUNTIME-V3' .
            '|challenge_id=' . $challengeId .
            '|nonce=' . $nonceB64 .
            '|license_id=' . $licenseId .
            '|machine_id=' . $machineId .
            '|build_id=' . $buildId .
            '|ex5_hash=' . $ex5Hash .
            '|ex4_hash=' . $ex4Hash .
            '|dll32_hash=' . $dll32Hash .
            '|dll64_hash=' . $dll64Hash .
            '|service_hash=' . $serviceHash .
            '|broker_hash=' . $brokerHash;

        $publicKeyPem = nutricula_build_p256_pem((string)$license['device_public_key_b64']);
        if (!nutricula_verify_device_signature($publicKeyPem, $message, $signatureB64)) {
            nutricula_reject($config, 'signature_invalid');
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
                    service32_sha256, service64_sha256, broker32_sha256, broker64_sha256
             FROM nutricula_build_manifests WHERE build_id=? LIMIT 1'
        );
        if (!$manifestStmt) throw new RuntimeException('DB prepare failed.');
        $manifestStmt->bind_param('s', $buildId);
        $manifestStmt->execute();
        $expectedManifest = $manifestStmt->get_result()->fetch_assoc();
        $manifestStmt->close();

        /* Both architectures of Service/Broker genuinely ship to customers
           (32-bit Windows hosts are a real, supported case) - the reporting
           Coordinator only ever measures and reports its OWN binary's hash
           (it has no way to even know the other architecture's file, which
           isn't present on its machine), so this server-side check accepts
           a match against EITHER the 32-bit or the 64-bit expected value,
           for each of service/broker independently. This is still exact
           equality against a server-known-good value either way - never a
           looser check - just against one of two valid values instead of
           one. */
        $serviceMatches = $expectedManifest && (
            hash_equals((string)$expectedManifest['service32_sha256'], $serviceHash) ||
            hash_equals((string)$expectedManifest['service64_sha256'], $serviceHash)
        );
        $brokerMatches = $expectedManifest && (
            hash_equals((string)$expectedManifest['broker32_sha256'], $brokerHash) ||
            hash_equals((string)$expectedManifest['broker64_sha256'], $brokerHash)
        );

        if (!$expectedManifest ||
            !hash_equals((string)$expectedManifest['ex5_sha256'], $ex5Hash) ||
            !hash_equals((string)$expectedManifest['ex4_sha256'], $ex4Hash) ||
            !hash_equals((string)$expectedManifest['dll32_sha256'], $dll32Hash) ||
            !hash_equals((string)$expectedManifest['dll64_sha256'], $dll64Hash) ||
            !$serviceMatches || !$brokerMatches) {
            nutricula_reject($config, 'artifact_mismatch');
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
            nutricula_reject($config, 'update_required');
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

        $lockStmt = $conn->prepare('SELECT status, license_expires_at FROM nutricula_licenses WHERE id=? FOR UPDATE');
        if (!$lockStmt) throw new RuntimeException('DB prepare failed.');
        $lockStmt->bind_param('i', $licenseDbId);
        $lockStmt->execute();
        $lockedLicense = $lockStmt->get_result()->fetch_assoc();
        $lockStmt->close();

        $finalNow = time();

        if (!$lockedLicense || $lockedLicense['status'] !== 'active') {
            $conn->rollback();
            nutricula_log_activity($conn, $licenseDbId, $machineId, $deviceKeyHash, $localIp, $observedIp, 'verify', 'license_inactive', $riskScore);
            $conn->close();
            nutricula_reject($config, 'license_inactive');
        }
        if ((int)$lockedLicense['license_expires_at'] <= $finalNow) {
            $conn->rollback();
            nutricula_log_activity($conn, $licenseDbId, $machineId, $deviceKeyHash, $localIp, $observedIp, 'verify', 'license_expired', $riskScore);
            $conn->close();
            nutricula_reject($config, 'license_expired');
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
            nutricula_reject($config, 'challenge_already_used');
        }

        /* THE time lock - see the design note above. A signature has already
           been proven valid at this point, so a rejection here genuinely
           means "correct device credentials, but too soon" - exactly the
           "identity/device key was copied" signal this is meant to catch. */
        $lock = nutricula_check_and_touch_time_lock($conn, $licenseDbId, $minGapSeconds, $finalNow);
        if (!$lock['allowed']) {
            $conn->commit(); // the challenge-used and time-lock touches must still persist
            nutricula_log_activity($conn, $licenseDbId, $machineId, $deviceKeyHash, $localIp, $observedIp, 'verify', 'too_early', $riskScore);
            $conn->close();
            nutricula_reject($config, 'too_early', $lock['retry_after_seconds']);
        }

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
            '|product_id=' . (int)$license['product_id'] .
            '|machine_id=' . $machineId .
            '|device_key_hash=' . $deviceKeyHash .
            '|license_expires_at=' . $licenseExpires .
            '|requested_at=' . $finalNow;

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
