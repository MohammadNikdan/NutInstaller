<?php

declare(strict_types=1);

date_default_timezone_set('UTC');

require_once __DIR__ . '/license_common.php';

/* Same field set as signup, but transfer_key is REQUIRED here (it's only
   optional/unused over in signup.php). See nutricula_strict_parse_fields()
   for why this replaces parse_str(). */
const TRANSFER_ALLOWED_FIELDS = [
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

    $outer = nutricula_require_post_data();
    $inner = nutricula_gcm_decrypt($outer, $config);
    $fields = nutricula_strict_parse_fields($inner, TRANSFER_ALLOWED_FIELDS);

    if ((string)($fields['v'] ?? '') !== '3') throw new RuntimeException('Invalid protocol version.');

    $email = trim(nutricula_required_field($fields, 'email'));
    $purchaseKey = trim(nutricula_required_field($fields, 'purchase_key'));
    $transferKey = trim(nutricula_required_field($fields, 'transfer_key'));
    $rndNumber = trim(nutricula_required_field($fields, 'rnd_number'));
    $newMachineId = strtoupper(trim(nutricula_required_field($fields, 'machine_id')));
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
    if ($localIp !== '' && filter_var($localIp, FILTER_VALIDATE_IP) === false) throw new RuntimeException('Invalid local IP.');

    $newDevicePublicKeyPem = nutricula_validate_device_public_key($newDevicePublicKey);
    $newDeviceKeyHash = nutricula_public_key_hash($newDevicePublicKey);
    $observedIp = nutricula_client_ip($config); // authoritative IP
    /* See the identical, more detailed note in signup.php: classification
       now comes directly from the DLL's own platform detection, not from
       whether local_ip happened to be present. */
    $newDeviceType = $platformProfile !== '' ? strtolower($platformProfile) : 'unknown';

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
       nutricula_transfer_keys_used.transfer_key is what actually enforces
       this at the database level against a race (see the INSERT near the
       end, wrapped the same way signup.php handles a duplicate purchase_key). */
    $usedCheck = $conn->prepare('SELECT id FROM nutricula_transfer_keys_used WHERE transfer_key=? LIMIT 1');
    if (!$usedCheck) throw new RuntimeException('DB prepare failed.');
    $usedCheck->bind_param('s', $transferKey);
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
    if (hash_equals((string)$license['machine_id'], $newMachineId)) {
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
    if ((int)$lockedLicense['license_expires_at'] <= $finalNow) {
        $conn->rollback();
        nutricula_log_activity($conn, $licenseDbId, $newMachineId, $newDeviceKeyHash, $localIp, $observedIp, 'transfer', 'license_expired', $riskScore);
        $conn->close();
        nutricula_reject($config, 'license_expired');
    }
    if (hash_equals((string)$lockedLicense['machine_id'], $newMachineId)) {
        $conn->rollback();
        nutricula_log_activity($conn, $licenseDbId, $newMachineId, $newDeviceKeyHash, $localIp, $observedIp, 'transfer', 'transfer_same_machine', $riskScore);
        $conn->close();
        nutricula_reject($config, 'transfer_same_machine');
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

    $update = $conn->prepare(
        'UPDATE nutricula_licenses
         SET license_uuid=?, machine_id=?, device_public_key_b64=?, device_public_key_hash=?,
             device_type=?, claimed_local_ip=?, last_observed_ip=?,
             last_request_time=?, last_success_time=?, last_seen_at=NOW()
         WHERE id=?'
    );
    if (!$update) throw new RuntimeException('DB prepare failed.');
    $update->bind_param(
        'sssssssiii',
        $newLicenseUuid,
        $newMachineId,
        $newDevicePublicKey,
        $newDeviceKeyHash,
        $newDeviceType,
        $localIp,
        $observedIp,
        $finalNow,
        $finalNow,
        $licenseDbId
    );
    if (!$update->execute()) throw new RuntimeException('DB update failed.');
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
         (transfer_key, user_email, license_id, old_license_uuid, new_license_uuid,
          old_machine_id, old_device_public_key_hash, old_last_observed_ip,
          new_machine_id, new_device_public_key_hash, new_observed_ip, new_claimed_local_ip,
          transferred_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NOW())'
    );
    if (!$insertUsed) throw new RuntimeException('DB prepare failed.');
    $insertUsed->bind_param(
        'ssisssssssss',
        $transferKey,
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
        '|machine_id=' . $newMachineId .
        '|device_key_hash=' . $newDeviceKeyHash .
        '|license_expires_at=' . $licenseExpires .
        '|requested_at=' . $finalNow .
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
