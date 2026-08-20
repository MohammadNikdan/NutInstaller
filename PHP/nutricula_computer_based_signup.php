<?php

declare(strict_types=1);

date_default_timezone_set('UTC');

require_once __DIR__ . '/license_common.php';

/* Whitelist for this endpoint - anything else in the decrypted payload is
   rejected outright. See nutricula_strict_parse_fields() for why this
   replaces parse_str() here. */
const SIGNUP_ALLOWED_FIELDS = [
    'v', 'rnd_number', 'email', 'purchase_key', 'transfer_key',
    'machine_id', 'device_public_key', 'local_ip', 'platform_profile',
];

/* The only platform_profile values the client-side machine ID DLL can ever
   report - anything else is treated as absent, never trusted verbatim. */
const VALID_PLATFORM_PROFILES = ['WINDOWS', 'WINDOWS_VM', 'MACOS_WINE', 'LINUX_WINE'];

try {
    $config = nutricula_load_config();
    $conn = nutricula_db($config);
    $conn->query("SET time_zone = '+00:00'");

    $minGapSeconds = (int)$config['min_request_gap_seconds']; // guaranteed present - see nutricula_validate_config()

    $outer = nutricula_require_post_data();
    $inner = nutricula_gcm_decrypt($outer, $config);
    $fields = nutricula_strict_parse_fields($inner, SIGNUP_ALLOWED_FIELDS);

    if ((string)($fields['v'] ?? '') !== '3') throw new RuntimeException('Invalid protocol version.');

    $email = trim(nutricula_required_field($fields, 'email'));
    $purchaseKey = trim(nutricula_required_field($fields, 'purchase_key'));
    $rndNumber = trim(nutricula_required_field($fields, 'rnd_number'));
    $machineId = strtoupper(trim(nutricula_required_field($fields, 'machine_id')));
    $devicePublicKey = trim(nutricula_required_field($fields, 'device_public_key'));
    /* Client-claimed only - NEVER treated as authoritative for any security
       decision, and no longer used for device classification or risk
       scoring either (see platform_profile below - IP proved unreliable
       for that purpose: it changes routinely on VPS providers and never
       actually proved hardware uniqueness). Kept only for optional manual
       monitoring/reference. The real, authoritative IP is $observedIp
       below, taken directly from the server's own request environment. */
    $localIp = trim((string)($fields['local_ip'] ?? ''));

    /* Reported directly by the machine ID DLL's own platform detection -
       not inferred from IP presence like the old (unreliable) logic this
       replaces. Anything not in the known set is treated as absent. */
    $platformProfileRaw = trim((string)($fields['platform_profile'] ?? ''));
    $platformProfile = in_array($platformProfileRaw, VALID_PLATFORM_PROFILES, true) ? $platformProfileRaw : '';

    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 320) throw new RuntimeException('Invalid email.');
    if ($purchaseKey === '' || strlen($purchaseKey) > 255) throw new RuntimeException('Invalid purchase key.');
    if (!preg_match('/\A[0-9]{32}\z/', $rndNumber)) throw new RuntimeException('Invalid random number.');
    if (!preg_match('/\A[0-9A-F]{64}\z/', $machineId)) throw new RuntimeException('Invalid machine ID.');
    if ($localIp !== '' && filter_var($localIp, FILTER_VALIDATE_IP) === false) throw new RuntimeException('Invalid local IP.');

    $devicePublicKeyPem = nutricula_validate_device_public_key($devicePublicKey);
    $deviceKeyHash = nutricula_public_key_hash($devicePublicKey);
    $observedIp = nutricula_client_ip($config); // authoritative IP - see comment above

    /* Device classification now comes directly from the client-side machine
       ID DLL's own platform detection (platform_profile), NOT from whether
       local_ip happened to be present - that old rule was broken by design:
       it could never be true "VM detection", only "did the client send an
       IP", and folding local_ip into the identity hash (removed on the DLL
       side) made machine_id unstable on top of that. IP is no longer used
       for classification or risk scoring at all - see the local_ip comment
       above for why. */
    $deviceType = $platformProfile !== '' ? strtolower($platformProfile) : 'unknown';

    $saleInfo = nutricula_find_edd_sale($config, $email, $purchaseKey);
    $productId = (int)$saleInfo['product_id'];
    $productName = (string)$saleInfo['product_name'];
    $duration = $saleInfo['duration'];

    $conn->begin_transaction();

    $select = $conn->prepare(
        'SELECT * FROM nutricula_licenses WHERE purchase_key = ? LIMIT 1 FOR UPDATE'
    );
    if (!$select) throw new RuntimeException('DB prepare failed.');
    $select->bind_param('s', $purchaseKey);
    $select->execute();
    $existing = $select->get_result()->fetch_assoc();
    $select->close();

    $now = time();
    $licenseId = 0;
    $licenseUuid = '';
    $licenseExpires = 0;
    $riskScore = 0;
    /* A small, fixed bump for VM/VPS-hosted licenses - not because IP
       disagreed with anything (that check is gone), but because a VM/VPS
       remains inherently more clonable than physical hardware even with the
       DLL's own strict, multi-signal acceptance rule for this profile. This
       is informational/monitoring weight only, never a rejection by itself. */
    if ($deviceType === 'windows_vm') $riskScore += 10;

    if ($existing !== null) {
        /* Signup never moves a consumed license to another device - that is
           what a (currently deferred) Transfer flow is for.
           Email compared case-insensitively (strcasecmp), matching the
           database column's own case-insensitive collation - a PHP-level
           !== comparison here would be byte-exact and could incorrectly
           reject a legitimate customer who typed their email with different
           capitalization at signup vs. now. */
        if (strcasecmp((string)$existing['user_email'], $email) !== 0 ||
            (int)$existing['product_id'] !== $productId ||
            !hash_equals((string)$existing['machine_id'], $machineId) ||
            !hash_equals((string)$existing['device_public_key_hash'], $deviceKeyHash)) {
            $conn->rollback();
            nutricula_reject($config, 'signup_identity_mismatch');
        }

        $licenseId = (int)$existing['id'];

        if ($existing['status'] !== 'active') {
            $conn->rollback();
            nutricula_log_activity($conn, $licenseId, $machineId, $deviceKeyHash, $localIp, $observedIp, 'signup', 'license_inactive', $riskScore);
            nutricula_reject($config, 'license_inactive');
        }
        if ((int)$existing['license_expires_at'] <= $now) {
            $conn->rollback();
            nutricula_log_activity($conn, $licenseId, $machineId, $deviceKeyHash, $localIp, $observedIp, 'signup', 'license_expired', $riskScore);
            nutricula_reject($config, 'license_expired');
        }

        /* Same anti-abuse time lock as the runtime verify cycle - closes the
           gap where re-signup could otherwise be used to bypass the
           challenge/verify minimum-gap restriction. */
        $lock = nutricula_check_and_touch_time_lock($conn, $licenseId, $minGapSeconds, $now);
        if (!$lock['allowed']) {
            $conn->commit(); // the time-lock touch itself must still persist
            nutricula_log_activity($conn, $licenseId, $machineId, $deviceKeyHash, $localIp, $observedIp, 'signup', 'too_early', $riskScore);
            $conn->close();
            nutricula_reject($config, 'too_early', $lock['retry_after_seconds']);
        }

        $licenseUuid = (string)$existing['license_uuid'];
        $licenseExpires = (int)$existing['license_expires_at'];

        nutricula_touch_success($conn, $licenseId, $now);

        $update = $conn->prepare(
            'UPDATE nutricula_licenses
             SET claimed_local_ip=?, last_observed_ip=?, last_seen_at=NOW()
             WHERE id=?'
        );
        if (!$update) throw new RuntimeException('DB prepare failed.');
        $update->bind_param('ssi', $localIp, $observedIp, $licenseId);
        if (!$update->execute()) throw new RuntimeException('DB update failed.');
        $update->close();

        $conn->commit();
    } else {
        $licenseUuid = nutricula_uuid();
        $licenseExpires = nutricula_total_expiration($duration);

        $insert = $conn->prepare(
            'INSERT INTO nutricula_licenses
             (license_uuid,user_email,purchase_key,product_id,product_name,machine_id,
              device_public_key_b64,device_public_key_hash,device_type,claimed_local_ip,
              first_observed_ip,last_observed_ip,license_issued_at,license_expires_at,
              last_request_time,last_success_time,status,activated_at,last_seen_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,"active",NOW(),NOW())'
        );
        if (!$insert) throw new RuntimeException('DB prepare failed.');

        $insert->bind_param(
            'sssissssssssiiii',
            $licenseUuid,
            $email,
            $purchaseKey,
            $productId,
            $productName,
            $machineId,
            $devicePublicKey,
            $deviceKeyHash,
            $deviceType,
            $localIp,
            $observedIp,
            $observedIp,
            $now,
            $licenseExpires,
            $now,
            $now
        );

        try {
            $executed = $insert->execute();
        } catch (mysqli_sql_exception $e) {
            $executed = false;
        }

        if (!$executed) {
            $duplicateKey = ((int)$conn->errno === 1062);
            $insert->close();
            $conn->rollback();
            if ($duplicateKey) {
                /* Two concurrent first-ever signups for the same
                   purchase_key (uq_purchase_key), or a device that already
                   holds a different license for this exact product
                   (uq_product_device), both land here. The database
                   constraint is the actual source of truth for these two
                   invariants - the SELECT ... FOR UPDATE above narrows the
                   race window but a fresh unique-index violation is still
                   possible and must be handled explicitly rather than
                   surfacing as a generic failure. */
                nutricula_reject($config, 'signup_conflict');
            }
            nutricula_reject($config, 'signup_failed');
        }
        $licenseId = $insert->insert_id;
        $insert->close();

        $conn->commit();
    }

    $canonical =
        'v=3' .
        '|license_id=' . $licenseUuid .
        '|product_id=' . $productId .
        '|machine_id=' . $machineId .
        '|device_key_hash=' . $deviceKeyHash .
        '|license_expires_at=' . $licenseExpires .
        '|requested_at=' . $now .
        /* Binds this specific signed response to this specific request -
           without this, a previously-issued, still-validly-signed response
           for an earlier request to this same license could not be
           distinguished, by the signature alone, from a fresh one. */
        '|rnd_number=' . $rndNumber;

    $serverSignature = nutricula_server_sign($canonical, $config);

    $licensePayload =
        'NL3|' . $canonical . '|server_signature=' . $serverSignature;

    nutricula_log_activity($conn, $licenseId, $machineId, $deviceKeyHash, $localIp, $observedIp, 'signup', null, $riskScore);

    $conn->close();
    nutricula_ok_gcm($licensePayload, $config);

} catch (Throwable $e) {
    if (isset($conn) && $conn instanceof mysqli) {
        try { $conn->rollback(); } catch (Throwable $ignored) {}
        try { $conn->close(); } catch (Throwable $ignored) {}
    }
    /* Never let a helper's exception message end up here containing a
       secret value (purchase_key, email, machine_id, key material, DB
       credentials, etc). Every throw site in this file and in
       license_common.php uses a fixed, generic message with no
       interpolated values for exactly this reason - verify that invariant
       is preserved if this file is ever modified further. */
    error_log('[Nutricula signup] ' . $e->getMessage());
    $fallback = $config ?? null;
    if (is_array($fallback)) nutricula_no($fallback);
    http_response_code(500);
    exit('no');
}
