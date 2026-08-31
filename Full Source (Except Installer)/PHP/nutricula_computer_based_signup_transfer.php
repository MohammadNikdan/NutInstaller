<?php

declare(strict_types=1);

date_default_timezone_set('UTC');

require_once __DIR__ . '/license_common.php';

/* Same field set as signup, but transfer_key is REQUIRED here (it's only
   optional/unused over in signup.php). See nutricula_strict_parse_fields()
   for why this replaces parse_str(). */
const TRANSFER_ALLOWED_FIELDS = [
    'v', 'rnd_number', 'email', 'purchase_key', 'transfer_key',
    'machine_id', 'machine_id_alt', 'machine_id_alt_confirmed',
    'device_public_key', 'local_ip', 'platform_profile',
];

/* The only platform_profile values the client-side machine ID DLL can ever
   report - anything else is treated as absent, never trusted verbatim. */
const VALID_PLATFORM_PROFILES = ['WINDOWS', 'WINDOWS_VM', 'MACOS_WINE', 'LINUX_WINE'];

try {
    $config = nutricula_load_config();
    $conn = nutricula_db($config);
    // DDoS mitigation: rejects cheaply (before any decrypt/DB-heavy work)
    // if this IP has exceeded the request rate for this endpoint - see
    // nutricula_rate_limit_check()'s own doc comment for the exact limit
    // and why a reverse proxy/WAF layer in front of this is still recommended.
    nutricula_rate_limit_check($conn, $config, 'transfer');
    $conn->query("SET time_zone = '+00:00'");

    $outer = nutricula_require_post_data();
    $inner = nutricula_gcm_decrypt($outer, $config);
    $fields = nutricula_strict_parse_fields($inner, TRANSFER_ALLOWED_FIELDS);

    if ((string)($fields['v'] ?? '') !== '3') throw new RuntimeException('Invalid protocol version.');

    $email = trim(nutricula_required_field($fields, 'email'));
    $purchaseKey = trim(nutricula_required_field($fields, 'purchase_key'));
    $transferKey = trim(nutricula_required_field($fields, 'transfer_key'));
    /* Never stored, logged, or compared in plaintext beyond this point - see
       nutricula_transfer_keys_used.transfer_key_hash. The plaintext value
       itself is only ever used transiently here to validate against EDD
       (nutricula_find_edd_transfer_purchase_in below), which needs the real
       value to check against the purchase record. */
    $transferKeyHash = hash('sha256', $transferKey);
    $rndNumber = trim(nutricula_required_field($fields, 'rnd_number'));
    $newMachineId = strtoupper(trim(nutricula_required_field($fields, 'machine_id')));
    /* Secondary machine_id variant (2026 hardening) - same defaulting
       logic as signup.php's identical field. */
    $newMachineIdAltRaw = trim((string)($fields['machine_id_alt'] ?? ''));
    $newMachineIdAlt = ($newMachineIdAltRaw !== '') ? strtoupper($newMachineIdAltRaw) : $newMachineId;
    $machineIdAltConfirmed = (string)($fields['machine_id_alt_confirmed'] ?? '') === '1';
    $newDevicePublicKey = trim(nutricula_required_field($fields, 'device_public_key'));
    /* Client-claimed only - kept for optional monitoring/reference; no
       longer used for device classification or risk scoring at all - see
       the identical, more detailed note in signup.php. $observedIp below
       (the server's own view of the connection) is what actually matters
       for anything security-relevant. */
    $localIp = trim((string)($fields['local_ip'] ?? ''));

    /* Reported directly by the machine ID DLL's own platform detection. */
    $platformProfileRaw = trim((string)($fields['platform_profile'] ?? ''));
    $platformProfile = in_array($platformProfileRaw, VALID_PLATFORM_PROFILES, true) ? $platformProfileRaw : '';

    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 320) throw new RuntimeException('Invalid email.');
    if ($purchaseKey === '' || strlen($purchaseKey) > 255) throw new RuntimeException('Invalid purchase key.');
    if ($transferKey === '' || strlen($transferKey) > 255) throw new RuntimeException('Invalid transfer key.');
    if (!preg_match('/\A[0-9]{32}\z/', $rndNumber)) throw new RuntimeException('Invalid random number.');
    if (!preg_match('/\A[0-9A-F]{64}\z/', $newMachineId)) throw new RuntimeException('Invalid machine ID.');
    if (!preg_match('/\A[0-9A-F]{64}\z/', $newMachineIdAlt)) throw new RuntimeException('Invalid machine ID.');
    if ($localIp !== '' && filter_var($localIp, FILTER_VALIDATE_IP) === false) throw new RuntimeException('Invalid local IP.');

    $newDevicePublicKeyPem = nutricula_validate_device_public_key($newDevicePublicKey);
    $newDeviceKeyHash = nutricula_public_key_hash($newDevicePublicKey);
    $observedIp = nutricula_client_ip($config); // authoritative IP
    /* See the identical, more detailed note in signup.php: classification
       now comes directly from the DLL's own platform detection, not from
       whether local_ip happened to be present. */
    $newDeviceType = $platformProfile !== '' ? strtolower($platformProfile) : 'unknown';

    /* VPS IP-Binding for the NEW (destination) computer - same bug fix as
       signup.php: $newMachineId (raw) stays unchanged everywhere else in
       this file, including the signed lease canonical near the bottom -
       only $newEffectiveMachineId is ever written to the machine_id
       DATABASE column. */
    $newEffectiveMachineId = nutricula_effective_machine_id($newDeviceType, $newMachineId, $observedIp);
    if ($newEffectiveMachineId === '') {
        // Same fail-closed reasoning as signup.php - no transaction is
        // open yet at this point in the flow.
        nutricula_reject($config, 'vps_ip_unavailable');
    }
    $newEffectiveMachineIdAlt = nutricula_effective_machine_id($newDeviceType, $newMachineIdAlt, $observedIp);
    if ($newEffectiveMachineIdAlt === '') {
        nutricula_reject($config, 'vps_ip_unavailable');
    }
    // Audit-only, NEVER used in any security decision.
    $vpsBoundIp = nutricula_is_vps_device_type($newDeviceType) ? nutricula_canonicalize_ip($observedIp) : null;

    $riskScore = 0;
    if ($newDeviceType === 'windows_vm') $riskScore += 10;

    /* One EDD call covers both checks below - see nutricula_fetch_edd_sales(). */
    $sales = nutricula_fetch_edd_sales($config, $email);

    /* --- Step 1: transfer_key must be a real purchase of the Transfer Key
       product (11348) for this exact email. --- */
    try {
        nutricula_find_edd_transfer_purchase_in($sales, $transferKey);
    } catch (RuntimeException $e) {
        nutricula_reject($config, 'transfer_key_invalid');
    }

    /* --- Step 2: this transfer_key must not have been used before. This is
       a cheap first-pass gate on an unlocked read; the UNIQUE constraint on
       nutricula_transfer_keys_used.transfer_key_hash is what actually
       enforces this at the database level against a race (see the INSERT
       near the end, wrapped the same way signup.php handles a duplicate
       purchase_key). Queried and stored as a SHA-256 hash, never plaintext -
       see the column comment in schema_device_type_change.sql. */
    $usedCheck = $conn->prepare('SELECT id FROM nutricula_transfer_keys_used WHERE transfer_key_hash=? LIMIT 1');
    if (!$usedCheck) throw new RuntimeException('DB prepare failed.');
    $usedCheck->bind_param('s', $transferKeyHash);
    $usedCheck->execute();
    $alreadyUsed = $usedCheck->get_result()->fetch_assoc();
    $usedCheck->close();
    if ($alreadyUsed !== null) {
        nutricula_reject($config, 'transfer_key_already_used');
    }

    /* --- Step 3: purchase_key must be a real license purchase (one of the
       6/12/24-month or lifetime products) for this exact email. Reuses the
       exact same product filtering signup.php relies on
       (nutricula_product_duration), applied to the already-fetched list. --- */
    try {
        $saleInfo = nutricula_find_edd_sale_in($sales, $purchaseKey);
    } catch (RuntimeException $e) {
        nutricula_reject($config, 'purchase_key_invalid');
    }
    $productId = (int)$saleInfo['product_id'];

    /* --- Step 4: an unlocked first-pass look-up of the target license by
       purchase_key. Same "cheap gate now, authoritative re-check on the
       locked row later" pattern used throughout license_check.php - closes
       the TOCTOU gap between this read and the final commit below. --- */
    $stmt = $conn->prepare('SELECT * FROM nutricula_licenses WHERE purchase_key=? LIMIT 1');
    if (!$stmt) throw new RuntimeException('DB prepare failed.');
    $stmt->bind_param('s', $purchaseKey);
    $stmt->execute();
    $license = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$license) nutricula_reject($config, 'license_not_found');

    /* Defense in depth, matching signup.php's identical check: don't rely
       solely on the implicit assumption that EDD's API correctly scoped its
       response to this exact email - verify the license row we actually
       found agrees with what was just validated via EDD. This also means a
       purchase_key that DOES exist but belongs to a different email/product
       than the one in this request is treated as license_not_found, not
       silently operated on. Email compared case-insensitively (strcasecmp),
       matching the database column's own case-insensitive collation. */
    if (strcasecmp((string)$license['user_email'], $email) !== 0 || (int)$license['product_id'] !== $productId) {
        nutricula_reject($config, 'license_not_found');
    }

    $licenseDbId = (int)$license['id'];
    $now = time();

    if ($license['status'] !== 'active') {
        nutricula_log_activity($conn, $licenseDbId, $newMachineId, $newDeviceKeyHash, $localIp, $observedIp, 'transfer', 'license_inactive', $riskScore);
        nutricula_reject($config, 'license_inactive');
    }
    if ((int)$license['license_expires_at'] <= $now) {
        nutricula_log_activity($conn, $licenseDbId, $newMachineId, $newDeviceKeyHash, $localIp, $observedIp, 'transfer', 'license_expired', $riskScore);
        nutricula_reject($config, 'license_expired');
    }
    if (hash_equals((string)$license['machine_id'], $newMachineId) ||
        hash_equals((string)$license['machine_id'], $newMachineIdAlt)) {
        nutricula_log_activity($conn, $licenseDbId, $newMachineId, $newDeviceKeyHash, $localIp, $observedIp, 'transfer', 'transfer_same_machine', $riskScore);
        nutricula_reject($config, 'transfer_same_machine');
    }

    /* --- Everything checked out: license exists, active, not expired, and
       genuinely moving to a different machine. Perform the transfer
       atomically, re-verifying the same three conditions on a freshly
       row-locked read first (closes the window since the unlocked read
       above - e.g. an admin revoking the license, or the license expiring,
       in between). --- */
    $conn->begin_transaction();

    $lockStmt = $conn->prepare('SELECT * FROM nutricula_licenses WHERE id=? FOR UPDATE');
    if (!$lockStmt) throw new RuntimeException('DB prepare failed.');
    $lockStmt->bind_param('i', $licenseDbId);
    $lockStmt->execute();
    $lockedLicense = $lockStmt->get_result()->fetch_assoc();
    $lockStmt->close();

    $finalNow = time();

    if (!$lockedLicense || $lockedLicense['status'] !== 'active') {
        $conn->rollback();
        nutricula_log_activity($conn, $licenseDbId, $newMachineId, $newDeviceKeyHash, $localIp, $observedIp, 'transfer', 'license_inactive', $riskScore);
        $conn->close();
        nutricula_reject($config, 'license_inactive');
    }

    /* Defense in depth: re-assert the same identity invariants that were
       checked on the earlier unlocked read (purchase_key, email, product_id)
       against the freshly locked row, not just its mutable state
       (status/expiry/machine) below. In the current codebase these three
       fields are never modified by anything after signup, so this is
       unlikely to ever actually fire - but for an authorization path this
       sensitive, re-asserting every invariant on the exact row about to be
       mutated costs nothing and removes any dependency on that assumption
       continuing to hold as the system evolves. Same rejection reason as
       the identical mismatch check on the unlocked read above, so this
       never becomes a distinguishable new information-disclosure path. */
    if ((string)$lockedLicense['purchase_key'] !== $purchaseKey ||
        strcasecmp((string)$lockedLicense['user_email'], $email) !== 0 ||
        (int)$lockedLicense['product_id'] !== $productId) {
        $conn->rollback();
        nutricula_log_activity($conn, $licenseDbId, $newMachineId, $newDeviceKeyHash, $localIp, $observedIp, 'transfer', 'license_not_found', $riskScore);
        $conn->close();
        nutricula_reject($config, 'license_not_found');
    }

    if ((int)$lockedLicense['license_expires_at'] <= $finalNow) {
        $conn->rollback();
        nutricula_log_activity($conn, $licenseDbId, $newMachineId, $newDeviceKeyHash, $localIp, $observedIp, 'transfer', 'license_expired', $riskScore);
        $conn->close();
        nutricula_reject($config, 'license_expired');
    }
    if (hash_equals((string)$lockedLicense['machine_id'], $newMachineId) ||
        hash_equals((string)$lockedLicense['machine_id'], $newMachineIdAlt)) {
        $conn->rollback();
        nutricula_log_activity($conn, $licenseDbId, $newMachineId, $newDeviceKeyHash, $localIp, $observedIp, 'transfer', 'transfer_same_machine', $riskScore);
        $conn->close();
        nutricula_reject($config, 'transfer_same_machine');
    }

    /* 2026 hardening - dual machine_id confirmation flow, with the same
       device_key-aware safety check as signup.php's INSERT path (see its
       own comment for the full reasoning) - here applied to "does the NEW
       machine already hold a different active license" instead of "brand
       new machine". */
    if ($machineIdAltConfirmed) {
        $conflict = nutricula_find_conflicting_license($conn, $productId, $newEffectiveMachineIdAlt, $purchaseKey);
        if ($conflict !== null) {
            $conn->rollback();
            $conn->close();
            nutricula_reject($config, hash_equals((string)$conflict['device_public_key_hash'], $newDeviceKeyHash)
                ? 'device_already_licensed' : 'machine_already_licensed');
        }
        $finalMachineIdToUse = $newEffectiveMachineIdAlt;
    } else {
        $conflictPrimary = nutricula_find_conflicting_license($conn, $productId, $newEffectiveMachineId, $purchaseKey);
        if ($conflictPrimary === null) {
            $finalMachineIdToUse = $newEffectiveMachineId;
        } elseif (hash_equals((string)$conflictPrimary['device_public_key_hash'], $newDeviceKeyHash)) {
            // Proven to be THIS SAME (new/destination) computer - hard
            // reject, never offer the alt fallback for a same-device
            // conflict.
            $conn->rollback();
            $conn->close();
            nutricula_reject($config, 'device_already_licensed');
        } else {
            $conflictAlt = nutricula_find_conflicting_license($conn, $productId, $newEffectiveMachineIdAlt, $purchaseKey);
            if ($conflictAlt === null) {
                $conn->rollback();
                $conn->close();
                nutricula_reject($config, 'machine_requires_confirmation');
            } elseif (hash_equals((string)$conflictAlt['device_public_key_hash'], $newDeviceKeyHash)) {
                $conn->rollback();
                $conn->close();
                nutricula_reject($config, 'device_already_licensed');
            } else {
                $conn->rollback();
                $conn->close();
                nutricula_reject($config, 'machine_already_licensed');
            }
        }
    }

    /* Capture the source ("old") computer's identity before overwriting it. */
    $oldLicenseUuid = (string)$lockedLicense['license_uuid'];
    $oldMachineId = (string)$lockedLicense['machine_id'];
    $oldDeviceKeyHash = (string)$lockedLicense['device_public_key_hash'];
    $oldObservedIp = (string)$lockedLicense['last_observed_ip'];
    $licenseExpires = (int)$lockedLicense['license_expires_at'];

    /* A fresh license_uuid so the OLD computer's cached license file (which
       still has the OLD uuid) naturally gets license_not_found on its very
       next check - no special-casing needed anywhere else, this alone is
       what makes that happen through the existing, unmodified
       license_check.php lookup. */
    $newLicenseUuid = nutricula_uuid();
    $newRefreshToken = nutricula_generate_refresh_token();
    $newRefreshTokenHash = hash('sha256', $newRefreshToken);

    $update = $conn->prepare(
        'UPDATE nutricula_licenses
         SET license_uuid=?, machine_id=?, device_public_key_b64=?, device_public_key_hash=?,
             device_type=?, claimed_local_ip=?, last_observed_ip=?, vps_bound_ip=?,
             last_request_time=?, last_success_time=?, last_seen_at=NOW(),
             current_refresh_token_hash=?, token_suspicious=0, blocked_until=NULL
         WHERE id=?'
    );
    if (!$update) throw new RuntimeException('DB prepare failed.');
    $update->bind_param(
        'ssssssssiisi',
        $newLicenseUuid,
        $finalMachineIdToUse,
        $newDevicePublicKey,
        $newDeviceKeyHash,
        $newDeviceType,
        $localIp,
        $observedIp,
        $vpsBoundIp,
        $finalNow,
        $finalNow,
        $newRefreshTokenHash,
        $licenseDbId
    );
    try {
        $updateExecuted = $update->execute();
    } catch (mysqli_sql_exception $e) {
        $updateExecuted = false;
    }
    if (!$updateExecuted) {
        $duplicateKey = ((int)$conn->errno === 1062);
        $errorText = (string)$conn->error;
        $update->close();
        $conn->rollback();
        if ($duplicateKey && strpos($errorText, 'uq_product_device') !== false) {
            /* The NEW device (device_public_key_hash being set here)
               already holds a DIFFERENT, existing license for this same
               product - see the identical, more detailed comment in
               signup.php's INSERT handling for the full reasoning
               (cloned/copied device key trying to claim a second license
               via Transfer instead of first-time signup - same underlying
               abuse, different entry point, so it gets the exact same
               precise reason here). */
            nutricula_reject($config, 'device_already_licensed');
        }
        throw new RuntimeException('DB update failed.');
    }
    $update->close();

    /* Hygiene: any still-pending challenge issued under the OLD device is
       now moot regardless (it could never pass verify's signature check
       against the NEW device key anyway), but invalidate it explicitly. */
    $invalidateChallenges = $conn->prepare(
        'UPDATE nutricula_license_challenges SET used_at=NOW() WHERE license_id=? AND used_at IS NULL'
    );
    if ($invalidateChallenges) {
        $invalidateChallenges->bind_param('i', $licenseDbId);
        $invalidateChallenges->execute();
        $invalidateChallenges->close();
    }

    $insertUsed = $conn->prepare(
        'INSERT INTO nutricula_transfer_keys_used
         (transfer_key_hash, user_email, license_id, old_license_uuid, new_license_uuid,
          old_machine_id, old_device_public_key_hash, old_last_observed_ip,
          new_machine_id, new_device_public_key_hash, new_observed_ip, new_claimed_local_ip,
          transferred_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NOW())'
    );
    if (!$insertUsed) throw new RuntimeException('DB prepare failed.');
    $insertUsed->bind_param(
        'ssisssssssss',
        $transferKeyHash,
        $email,
        $licenseDbId,
        $oldLicenseUuid,
        $newLicenseUuid,
        $oldMachineId,
        $oldDeviceKeyHash,
        $oldObservedIp,
        $newMachineId,
        $newDeviceKeyHash,
        $observedIp,
        $localIp
    );

    try {
        $executed = $insertUsed->execute();
    } catch (mysqli_sql_exception $e) {
        $executed = false;
    }

    if (!$executed) {
        $duplicateKey = ((int)$conn->errno === 1062);
        $insertUsed->close();
        $conn->rollback();
        $conn->close();
        /* A second, near-simultaneous request with the SAME transfer_key
           lands here - the UNIQUE constraint on transfer_key is the actual
           source of truth for "used exactly once", the earlier unlocked
           SELECT was only a narrowing pre-check. */
        nutricula_reject($config, $duplicateKey ? 'transfer_key_already_used' : 'transfer_failed');
    }
    $insertUsed->close();

    nutricula_log_activity($conn, $licenseDbId, $newMachineId, $newDeviceKeyHash, $localIp, $observedIp, 'transfer', null, $riskScore);

    $conn->commit();

    /* Same NL3 lease format as signup/verify, so the installer saves this
       exactly the way it already saves a normal signup response - the new
       computer is licensed from this point on, no special handling needed
       anywhere else in the installer or the EA. */
    $canonical =
        'v=3' .
        '|license_id=' . $newLicenseUuid .
        '|product_id=' . $productId .
        '|machine_id=' . $finalMachineIdToUse .
        '|device_key_hash=' . $newDeviceKeyHash .
        '|license_expires_at=' . $licenseExpires .
        '|requested_at=' . $finalNow .
        '|refresh_token=' . $newRefreshToken .
        '|rnd_number=' . $rndNumber;

    $serverSignature = nutricula_server_sign($canonical, $config);
    $licensePayload = 'NL3|' . $canonical . '|server_signature=' . $serverSignature;

    $conn->close();
    nutricula_ok_gcm($licensePayload, $config);

} catch (Throwable $e) {
    if (isset($conn) && $conn instanceof mysqli) {
        try { $conn->rollback(); } catch (Throwable $ignored) {}
        try { $conn->close(); } catch (Throwable $ignored) {}
    }
    /* Same invariant as every other endpoint: never let an exception
       message here contain a secret value. */
    error_log('[Nutricula transfer] ' . $e->getMessage());
    $fallback = $config ?? null;
    if (is_array($fallback)) nutricula_no($fallback);
    http_response_code(500);
    exit('no');
}
