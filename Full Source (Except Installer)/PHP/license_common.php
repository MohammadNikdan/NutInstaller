<?php

declare(strict_types=1);

function nutricula_load_config(): array
{
    $path = '/home/nutricul/domains/nutriculaexpert.com/Private/license_config.php';
    if (!is_file($path)) {
        throw new RuntimeException('License configuration file is missing.');
    }
    $config = require $path;
    if (!is_array($config)) {
        throw new RuntimeException('Invalid license configuration.');
    }
    nutricula_validate_config($config);
    return $config;
}

/**
 * Fail-closed config validation. A missing or malformed security-critical
 * setting throws immediately here, rather than silently falling back to a
 * default value deep inside an endpoint (e.g. min_request_gap_seconds ?? 3180)
 * where an incomplete deployment could otherwise unknowingly run with a
 * weaker policy than intended. Every key listed here MUST be present in
 * license_config.php - there are no defaults.
 */
function nutricula_validate_config(array $config): void
{
    $errors = [];

    $requireString = function (array $c, array $path) use (&$errors) {
        $cur = $c;
        foreach ($path as $segment) {
            if (!is_array($cur) || !array_key_exists($segment, $cur)) {
                $errors[] = implode('.', $path) . ' is missing.';
                return;
            }
            $cur = $cur[$segment];
        }
        if (!is_string($cur) || trim($cur) === '') {
            $errors[] = implode('.', $path) . ' must be a non-empty string.';
        }
    };

    $requirePositiveInt = function (array $c, string $key) use (&$errors) {
        if (!array_key_exists($key, $c)) {
            $errors[] = $key . ' is missing.';
            return;
        }
        if (!is_int($c[$key]) || $c[$key] <= 0) {
            $errors[] = $key . ' must be a positive integer.';
        }
    };

    $requireString($config, ['db', 'host']);
    $requireString($config, ['db', 'name']);
    $requireString($config, ['db', 'user']);
    $requireString($config, ['db', 'pass']);
    $requireString($config, ['db', 'charset']);
    $requireString($config, ['edd', 'api_key']);
    $requireString($config, ['edd', 'api_token']);
    $requireString($config, ['server_signing_private_key_path']);
    $requireString($config, ['transport_key_path']);

    $transportKeyPath = (string)($config['transport_key_path'] ?? '');
    $transportKeyContent = trim((string)(@file_get_contents($transportKeyPath) ?: ''));
    if (!preg_match('/\A[0-9a-fA-F]{64}\z/', $transportKeyContent)) {
        $errors[] = 'transport_key_path does not point to a readable file containing exactly 64 hex characters.';
    }

    $requirePositiveInt($config, 'challenge_ttl_seconds');
    $requirePositiveInt($config, 'min_request_gap_seconds');

    if (!array_key_exists('trust_cloudflare_connecting_ip', $config) ||
        !is_bool($config['trust_cloudflare_connecting_ip'])) {
        $errors[] = 'trust_cloudflare_connecting_ip must be a boolean (true/false).';
    }

    if (!empty($errors)) {
        /* Deliberately generic to anyone outside this codebase (never
           interpolate which VALUE was wrong), but specific enough in the
           server error log for whoever deploys this to fix quickly. */
        error_log('[Nutricula config] Invalid configuration: ' . implode(' ', $errors));
        throw new RuntimeException('License configuration is incomplete or invalid.');
    }
}

function nutricula_db(array $config): mysqli
{
    $db = $config['db'];
    $conn = new mysqli(
        (string)$db['host'],
        (string)$db['user'],
        (string)$db['pass'],
        (string)$db['name']
    );
    if ($conn->connect_error) {
        throw new RuntimeException('Database connection failed.');
    }
    $conn->set_charset((string)$db['charset']);
    return $conn;
}

function nutricula_transport_key(array $config): string
{
    $path = (string)($config['transport_key_path'] ?? '');
    $hex = trim((string)(@file_get_contents($path) ?: ''));
    if (!preg_match('/\A[0-9a-fA-F]{64}\z/', $hex)) {
        throw new RuntimeException('Invalid transport key.');
    }
    $key = hex2bin($hex);
    if ($key === false || strlen($key) !== 32) {
        throw new RuntimeException('Invalid transport key.');
    }
    return $key;
}

function nutricula_gcm_encrypt(string $plaintext, array $config): string
{
    $key = nutricula_transport_key($config);
    $nonce = random_bytes(12);
    $tag = '';
    $cipher = openssl_encrypt(
        $plaintext,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $nonce,
        $tag,
        '',
        16
    );
    if ($cipher === false || strlen($tag) !== 16) {
        throw new RuntimeException('GCM encryption failed.');
    }
    return 'N3:' . base64_encode($nonce . $tag . $cipher);
}

function nutricula_gcm_decrypt(string $envelope, array $config): string
{
    if (strlen($envelope) < 4 || substr($envelope, 0, 3) !== 'N3:') {
        throw new RuntimeException('Unsupported payload version.');
    }
    $packed = base64_decode(substr($envelope, 3), true);
    if ($packed === false || strlen($packed) < 28) {
        throw new RuntimeException('Invalid GCM envelope.');
    }
    $nonce = substr($packed, 0, 12);
    $tag = substr($packed, 12, 16);
    $cipher = substr($packed, 28);
    $plain = openssl_decrypt(
        $cipher,
        'aes-256-gcm',
        nutricula_transport_key($config),
        OPENSSL_RAW_DATA,
        $nonce,
        $tag,
        ''
    );
    if ($plain === false) {
        throw new RuntimeException('GCM authentication failed.');
    }
    return $plain;
}

function nutricula_no(array $config, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=UTF-8');
    try {
        echo nutricula_gcm_encrypt('no', $config);
    } catch (Throwable $e) {
        echo 'no';
    }
    exit;
}

/**
 * Structured rejection for every well-defined business-outcome failure
 * (license not found, expired, mismatched, too early, bad signature, etc.).
 * Distinct from nutricula_no(), which stays reserved for genuinely malformed/
 * undecryptable requests where there isn't enough context to give a specific
 * reason. $reason is a short snake_case code - see README_TIME_LOCK.txt for
 * the full enumerated list of reasons this endpoint can return.
 */
function nutricula_reject(array $config, string $reason, int $retryAfterSeconds = 0): never
{
    $now = time();
    $canonical =
        'reason=' . $reason .
        '|requested_at=' . $now .
        '|retry_after_seconds=' . max(0, $retryAfterSeconds);

    // CRITICAL FIX (found via full end-to-end testing): this function
    // never actually signed its output, despite LicenseProtocol.cpp's own
    // comment claiming it did ("matches the identical fix applied
    // server-side in nutricula_reject()"). The C++ side has always
    // required "|server_signature=" on every Reject (exact same
    // requirement as Challenge, fixed in the previous session) - without
    // it, every Reject response this function ever produced was silently
    // treated as Invalid by every client, for every reason (license
    // expired, too early, machine mismatch, artifact mismatch, update
    // required - all of them).
    try {
        $signature = nutricula_server_sign($canonical, $config);
        $body = 'NL3-REJECT|' . $canonical . '|server_signature=' . $signature;
    } catch (Throwable $e) {
        // Signing itself failed (e.g. key file unreadable) - fall back to
        // the old unsigned format rather than crash. A client will still
        // correctly treat this as Invalid (same as before this fix), which
        // is the safe failure mode - never worse than the previous
        // behavior, just not better either in this one edge case.
        $body = 'NL3-REJECT|' . $canonical;
    }

    http_response_code(200);
    header('Content-Type: text/plain; charset=UTF-8');
    try {
        echo nutricula_gcm_encrypt($body, $config);
    } catch (Throwable $e) {
        echo 'no';
    }
    exit;
}

/** Generates a fresh, cryptographically random refresh token (32 raw bytes,
    hex-encoded to 64 chars) - this is the plaintext value returned to the
    client inside the signed lease. Only its SHA-256 hash is ever stored
    server-side (nutricula_licenses.current_refresh_token_hash). */
function nutricula_generate_refresh_token(): string
{
    return bin2hex(random_bytes(32));
}

/** THE clone/copy detection state machine - see the two worked examples
    that motivated this exact design (in the accompanying design
    discussion): a stale token is forgiven exactly once (token still
    rotates forward, license flagged "suspicious"), but a SECOND stale
    token presented before any successful current-token request in
    between triggers a 24h block for the license, applied identically
    regardless of which of the two colliding machines is "legitimate" -
    the server cannot tell them apart once machine_id and device key are
    both cloned, so both are treated as guilty per the accepted design.

    Must be called with the license row already locked (SELECT ... FOR
    UPDATE) in the same transaction as the caller's other license reads,
    to avoid a race between two near-simultaneous requests for the same
    license.

    Returns an array: ['action' => 'proceed'|'blocked', 'new_token' => ?string]
    - 'proceed': caller should continue issuing a normal lease; if
      new_token is non-null, it MUST be embedded in the lease canonical
      and current_refresh_token_hash updated to hash(new_token) as part of
      the same UPDATE the caller already does for this license row.
    - 'blocked': caller MUST call nutricula_reject($config, 'blocked') and
      stop - blocked_until has already been set by this function. */
function nutricula_check_and_rotate_token(mysqli $conn, array $config, array $license, string $clientToken): array
{
    $now = time();
    $blockedUntil = (int)($license['blocked_until'] ?? 0);
    if ($blockedUntil > $now) {
        return ['action' => 'blocked', 'new_token' => null];
    }

    $storedHash = (string)($license['current_refresh_token_hash'] ?? '');
    $clientHash = hash('sha256', $clientToken);
    $isCurrentToken = ($storedHash !== '' && hash_equals($storedHash, $clientHash));

    $wasSuspicious = ((int)($license['token_suspicious'] ?? 0)) === 1;

    if ($isCurrentToken) {
        // Valid, current token - always resets suspicion, always rotates forward.
        $newToken = nutricula_generate_refresh_token();
        $stmt = $conn->prepare(
            'UPDATE nutricula_licenses
             SET current_refresh_token_hash = ?, token_suspicious = 0
             WHERE id = ?'
        );
        $newHash = hash('sha256', $newToken);
        $stmt->bind_param('si', $newHash, $license['id']);
        $stmt->execute();
        $stmt->close();
        return ['action' => 'proceed', 'new_token' => $newToken];
    }

    // Stale token (any generation distance - we deliberately never compare
    // "how old", only "is it the current one").
    if ($wasSuspicious) {
        // Second consecutive stale-token event -> block both machines for
        // clone_block_hours, clear the suspicious flag (so the license is
        // clean again once the block naturally expires).
        $blockHours = (int)($config['clone_block_hours'] ?? 24);
        $newBlockedUntil = $now + ($blockHours * 3600);
        $stmt = $conn->prepare(
            'UPDATE nutricula_licenses
             SET blocked_until = ?, token_suspicious = 0
             WHERE id = ?'
        );
        $stmt->bind_param('ii', $newBlockedUntil, $license['id']);
        $stmt->execute();
        $stmt->close();
        return ['action' => 'blocked', 'new_token' => null];
    }

    // First stale-token event for this license since the last successful
    // current-token request - forgive once: still rotate the token
    // forward (so the request completes normally), but flag as suspicious
    // so a SECOND stale event (from either machine) before a clean
    // current-token success triggers the block above.
    $newToken = nutricula_generate_refresh_token();
    $stmt = $conn->prepare(
        'UPDATE nutricula_licenses
         SET current_refresh_token_hash = ?, token_suspicious = 1
         WHERE id = ?'
    );
    $newHash = hash('sha256', $newToken);
    $stmt->bind_param('si', $newHash, $license['id']);
    $stmt->execute();
    $stmt->close();
    return ['action' => 'proceed', 'new_token' => $newToken];
}

/**
 * THE anti-abuse time lock. Must be called with $conn already inside an open
 * transaction (begin_transaction() already called by the caller) so the row
 * lock (SELECT ... FOR UPDATE) held here actually prevents two simultaneous
 * requests for the same license from both being accepted - the second one
 * blocks on the row lock until the first request's transaction commits and
 * its last_request_time update becomes visible.
 *
 * Always updates last_request_time to $now, whether the request is allowed
 * or rejected - this is deliberate: a rejected request itself starts the
 * next minimum-gap interval over again, exactly like an accepted one does.
 *
 * There is intentionally no upper bound - only "has at least $minGapSeconds
 * passed" is checked. A NULL last_request_time (this license's very first
 * request ever) is always allowed.
 */
function nutricula_check_and_touch_time_lock(mysqli $conn, int $licenseDbId, int $minGapSeconds, int $now): array
{
    $stmt = $conn->prepare('SELECT last_request_time FROM nutricula_licenses WHERE id=? FOR UPDATE');
    if (!$stmt) throw new RuntimeException('DB prepare failed.');
    $stmt->bind_param('i', $licenseDbId);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    if ($row === null) throw new RuntimeException('License row not found for time lock.');

    $last = $row['last_request_time'] !== null ? (int)$row['last_request_time'] : null;
    $elapsed = $last === null ? null : ($now - $last);
    $allowed = $last === null || $elapsed >= $minGapSeconds;

    $update = $conn->prepare('UPDATE nutricula_licenses SET last_request_time=? WHERE id=?');
    if (!$update) throw new RuntimeException('DB prepare failed.');
    $update->bind_param('ii', $now, $licenseDbId);
    if (!$update->execute()) throw new RuntimeException('DB update failed (time lock).');
    $update->close();

    return [
        'allowed' => $allowed,
        'elapsed' => $elapsed,
        'retry_after_seconds' => $allowed ? 0 : max(0, $minGapSeconds - (int)$elapsed),
    ];
}

/** Touches last_success_time - call only once a request has fully succeeded. */
function nutricula_touch_success(mysqli $conn, int $licenseDbId, int $now): void
{
    $stmt = $conn->prepare('UPDATE nutricula_licenses SET last_success_time=? WHERE id=?');
    if (!$stmt) throw new RuntimeException('DB prepare failed.');
    $stmt->bind_param('ii', $now, $licenseDbId);
    if (!$stmt->execute()) throw new RuntimeException('DB update failed (success touch).');
    $stmt->close();
}

/** Logs one activity row, with an optional reject reason (null for successes). */
function nutricula_log_activity(mysqli $conn, int $licenseDbId, string $machineId, string $deviceKeyHash, string $localIp, string $observedIp, string $requestType, ?string $reason, int $riskScore): void
{
    $stmt = $conn->prepare(
        'INSERT INTO nutricula_license_activity
         (license_id,machine_id,device_public_key_hash,claimed_local_ip,observed_ip,occurred_at,request_type,reason,risk_score)
         VALUES (?,?,?,?,?,NOW(),?,?,?)'
    );
    if (!$stmt) {
        error_log('[Nutricula activity log] prepare failed for license_id=' . $licenseDbId);
        return;
    }
    $stmt->bind_param('issssssi', $licenseDbId, $machineId, $deviceKeyHash, $localIp, $observedIp, $requestType, $reason, $riskScore);
    if (!$stmt->execute()) {
        error_log('[Nutricula activity log] insert failed for license_id=' . $licenseDbId . ' type=' . $requestType);
    }
    $stmt->close();
}

/**
 * Statistics only - records that this computer checked in without having a
 * license, identified by machine_id and/or device_public_key_hash. At least
 * one of the two must be non-empty (enforced by the caller); either one
 * ALONE is sufficient to recognize a returning computer across check-ins -
 * a free install's machine_id can genuinely fail to generate on some
 * systems, in which case the device key is the only identifier available.
 * Deliberately never throws: a failure here can never interfere with the
 * actual response the caller is about to send.
 */
function nutricula_track_unlicensed_checkin(mysqli $conn, ?string $machineId, ?string $deviceKeyHash): void
{
    $machineId = ($machineId !== null && $machineId !== '') ? $machineId : null;
    $deviceKeyHash = ($deviceKeyHash !== null && $deviceKeyHash !== '') ? $deviceKeyHash : null;
    if ($machineId === null && $deviceKeyHash === null) return; // nothing to identify this computer by

    try {
        // Look for an existing row by whichever identifier is available -
        // machine_id first (more stable across device-key resets), then
        // device_key_hash. Either match is treated as "this same computer".
        $existingId = null;
        if ($machineId !== null) {
            $stmt = $conn->prepare('SELECT id, device_public_key_hash FROM nutricula_unlicensed_checkins WHERE machine_id = ? LIMIT 1');
            $stmt->bind_param('s', $machineId);
            $stmt->execute();
            $row = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            if ($row) $existingId = (int)$row['id'];
        }
        if ($existingId === null && $deviceKeyHash !== null) {
            $stmt = $conn->prepare('SELECT id FROM nutricula_unlicensed_checkins WHERE device_public_key_hash = ? LIMIT 1');
            $stmt->bind_param('s', $deviceKeyHash);
            $stmt->execute();
            $row = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            if ($row) $existingId = (int)$row['id'];
        }

        if ($existingId !== null) {
            // Touch last_seen_at, and opportunistically fill in whichever
            // identifier was previously missing (e.g. machine_id becomes
            // available on a later check-in after initially failing).
            $stmt = $conn->prepare(
                'UPDATE nutricula_unlicensed_checkins
                 SET last_seen_at = NOW(),
                     machine_id = COALESCE(machine_id, ?),
                     device_public_key_hash = COALESCE(device_public_key_hash, ?)
                 WHERE id = ?'
            );
            $stmt->bind_param('ssi', $machineId, $deviceKeyHash, $existingId);
            $stmt->execute();
            $stmt->close();
            return;
        }

        $stmt = $conn->prepare(
            'INSERT INTO nutricula_unlicensed_checkins
             (machine_id, device_public_key_hash, first_seen_at, last_seen_at)
             VALUES (?, ?, NOW(), NOW())'
        );
        $stmt->bind_param('ss', $machineId, $deviceKeyHash);
        if (!$stmt->execute()) {
            // Benign race: another concurrent check-in from the same
            // computer inserted first - not an error worth logging.
            if ($conn->errno !== 1062) {
                error_log('[Nutricula unlicensed tracking] insert failed: ' . $conn->error);
            }
        }
        $stmt->close();
    } catch (Throwable $e) {
        error_log('[Nutricula unlicensed tracking] ' . $e->getMessage());
    }
}

function nutricula_ok_gcm(string $plaintext, array $config): never
{
    header('Content-Type: text/plain; charset=UTF-8');
    echo nutricula_gcm_encrypt($plaintext, $config);
    exit;
}

/* The actual encrypted payload is realistically a few hundred bytes (a
   handful of short fields). 8KB is generous headroom for future fields
   while still meaningfully bounding a large-POST attack - the old 128KB
   cap was far larger than anything legitimate this endpoint ever needs. */
const NUTRICULA_MAX_REQUEST_BYTES = 8192;

function nutricula_require_post_data(): string
{
    if (strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? '')) !== 'POST') {
        http_response_code(405);
        header('Allow: POST');
        exit('no');
    }

    /* Reject by Content-Length first, before relying on $_POST having
       already been populated - cheaper, and doesn't depend on PHP's own
       post_max_size being configured the way we'd want. */
    $contentLength = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($contentLength > NUTRICULA_MAX_REQUEST_BYTES) {
        http_response_code(413);
        exit('no');
    }

    $data = $_POST['data'] ?? null;
    if (!is_string($data) || $data === '' || strlen($data) > NUTRICULA_MAX_REQUEST_BYTES) {
        throw new RuntimeException('Missing or oversized data field.');
    }
    return $data;
}

function nutricula_client_ip(array $config): string
{
    $remote = trim((string)($_SERVER['REMOTE_ADDR'] ?? ''));
    if (!filter_var($remote, FILTER_VALIDATE_IP)) {
        throw new RuntimeException('Invalid REMOTE_ADDR.');
    }

    if (!empty($config['trust_cloudflare_connecting_ip']) && nutricula_ip_in_cidrs($remote, (array)($config['trusted_proxy_cidrs'] ?? []))) {
        $cf = trim((string)($_SERVER['HTTP_CF_CONNECTING_IP'] ?? ''));
        if (filter_var($cf, FILTER_VALIDATE_IP)) {
            return $cf;
        }
    }

    return $remote;
}

/* ============================================================================
   VPS IP-Binding (2026) - see the accompanying design discussion for the
   full reasoning. Summary: for VPS installs specifically (device_type ===
   'windows_vm'), the server-observed connection IP (nutricula_client_ip()
   above - already Cloudflare-aware, NOT client-reported) is folded into
   the machine_id used for DATABASE STORAGE AND COMPARISON ONLY.

   CRITICAL DISTINCTION - do not blur these two things:
   - The RAW client-reported machine_id (the $machineId variable everywhere
     else in this codebase) is what goes into the signed lease canonical
     sent back to the client - this MUST stay exactly as before, unchanged,
     because the Coordinator's own Layer 1 defense (comparing the lease's
     machine_id against its own freshly-computed local machine_id) depends
     on this being the same raw value the client itself can reproduce. The
     client never learns about, computes, or needs to know about the IP
     augmentation at all.
   - The EFFECTIVE machine_id (this function's output) is ONLY ever written
     to / compared against the `machine_id` DATABASE COLUMN. It never
     appears in any lease, challenge, or client-facing response.

   This mirrors a design this project already tried once before in a
   different form (folding client-REPORTED local_ip directly into the
   machine_id hash) and deliberately reverted, per the comment on
   $localIp above ("made machine_id unstable... IP proved unreliable").
   That earlier attempt is NOT the same thing as this one: it trusted a
   client-supplied value (trivially wrong/spoofable) and folded it into a
   hash the CLIENT itself also had to reproduce identically forever after
   (impossible, since the client cannot know its own public inbound IP).
   This version instead uses a SERVER-OBSERVED value (the actual TCP
   connection's source IP - not attacker-controllable without genuinely
   controlling that network path) and only the SERVER ever needs to
   reproduce the computation - the client's own hash never changes.
   ============================================================================ */

/** Canonicalizes an IP address to a single, unambiguous string form, so the
    exact same physical address always hashes identically regardless of
    which textual representation arrived (e.g. an IPv4-mapped IPv6 address
    like "::ffff:1.2.3.4" and plain "1.2.3.4" are the same underlying
    address and MUST canonicalize to the same string, or a VPS-bound
    license would break the very first time the web server's dual-stack
    socket layer happened to report the address in the other form).
    Returns '' if the input is not a valid IP at all - callers must treat
    an empty result as "no valid IP available", never fall back to the
    raw input. */
function nutricula_canonicalize_ip(string $ip): string
{
    $binary = @inet_pton($ip);
    if ($binary === false) return '';
    // IPv4-mapped IPv6 (::ffff:a.b.c.d, the 12-byte prefix below) is the
    // exact same address as plain IPv4 a.b.c.d - collapse it down so both
    // representations of the identical connection produce one canonical
    // form.
    if (strlen($binary) === 16 && substr($binary, 0, 12) === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff") {
        $binary = substr($binary, 12);
    }
    $canonical = @inet_ntop($binary);
    return $canonical === false ? '' : $canonical;
}

/** Whether this device_type value should have its machine_id bound to the
    server-observed connection IP at all. Currently only windows_vm - see
    the design discussion for why macos_wine/linux_wine (Wine-hosted, could
    be a real desktop, not necessarily a rented VPS) and windows (a real
    physical machine's IP genuinely does change routinely - home ISP
    reconnects, laptop travel - with no attacker involved at all) are
    deliberately excluded. Centralized here as the single source of truth
    for which device_type values this applies to, rather than repeating
    the string comparison at every call site. */
function nutricula_is_vps_device_type(string $deviceType): bool
{
    return $deviceType === 'windows_vm';
}

/** THE core VPS IP-binding computation - see the block comment above this
    section for the full design and the critical raw-vs-effective
    distinction. For any device_type nutricula_is_vps_device_type() does
    not recognize, returns $rawMachineId completely unchanged (byte for
    byte) - every existing non-VPS code path is a no-op under this
    function, by construction, not by accident.

    For a VPS device_type: canonicalizes $observedIp and, only if that
    succeeds, returns a NEW 64-hex-char value: SHA-256 of
    "NUTRICULA_VPS_BIND_V1|{$rawMachineId}|{$canonicalIp}" (uppercase hex,
    matching this codebase's existing machine_id formatting convention
    throughout). The literal "NUTRICULA_VPS_BIND_V1|" prefix is domain
    separation - without it, e.g. a raw machine_id ending in "1" concatenated
    with an IP starting in "2.3.4.5" is byte-identical to a differently
    split raw machine_id + IP pair; the labeled, pipe-delimited prefix
    removes that ambiguity structurally, the same convention already used
    throughout this file's other canonical-string constructions (license
    lease canonicals, etc.) - not a new pattern introduced just for this.

    If $observedIp cannot be canonicalized to a valid IP at all (should be
    essentially unreachable in practice, since nutricula_client_ip() already
    validates REMOTE_ADDR upstream - kept as defense in depth, e.g. against
    some future refactor of the caller), returns '' - callers MUST treat
    this as "can never match anything, reject" and must NEVER silently fall
    back to $rawMachineId for a VPS device_type in that case; doing so would
    quietly disable this entire binding for exactly the failure case it
    exists to be strict about. */
function nutricula_effective_machine_id(string $deviceType, string $rawMachineId, string $observedIp): string
{
    if (!nutricula_is_vps_device_type($deviceType)) {
        return $rawMachineId;
    }
    $canonicalIp = nutricula_canonicalize_ip($observedIp);
    if ($canonicalIp === '') {
        return '';
    }
    return strtoupper(hash('sha256', "NUTRICULA_VPS_BIND_V1|{$rawMachineId}|{$canonicalIp}"));
}

/* Simple DDoS-mitigation rate limit: a fixed 60-second window counter per
   (client IP, endpoint name), backed by nutricula_rate_limits. Applied as
   the FIRST thing every customer-facing endpoint does, before any
   decryption/DB/crypto work - the whole point is to reject cheaply, before
   spending real resources on a request that might be part of a flood.

   Limit chosen: 30 requests per 60 seconds per IP per endpoint. This is a
   conventional, moderate API rate limit (commonly seen in the 10-100
   req/min range for endpoints like this) - generous enough that legitimate
   retries/troubleshooting during activation never hit it (a real license
   check happens roughly once every 4-15 minutes; even a customer manually
   retrying an activation attempt a dozen times in a minute stays well
   under this), while still capping how much load a single source can put
   on the server during a flood.

   IMPORTANT CAVEAT: this is application-level, defense-in-depth only - a
   true volumetric DDoS (thousands of source IPs, or enough raw traffic to
   saturate the network/webserver before PHP even runs) is NOT something
   any PHP-level check can stop, because the cost of rejecting is still a
   full PHP process + one DB round-trip per request. For real DDoS
   resilience, this should sit BEHIND a reverse proxy or CDN/WAF (e.g.
   Cloudflare, nginx's own limit_req, a load balancer) that drops excess
   traffic before it reaches PHP at all - this function is a secondary
   layer, not a replacement for that. */
function nutricula_rate_limit_check(mysqli $conn, array $config, string $endpointName): void
{
    $limit = 30;         // requests
    $windowSeconds = 60; // per this many seconds

    $ip = nutricula_client_ip($config);
    $rateKey = $endpointName . '|' . $ip;
    $windowStart = intdiv(time(), $windowSeconds) * $windowSeconds;

    // Single atomic upsert: create the window row on first request, or
    // increment it on subsequent ones - no separate SELECT-then-INSERT
    // race window.
    $stmt = $conn->prepare(
        'INSERT INTO nutricula_rate_limits (rate_key, window_start, request_count)
         VALUES (?, ?, 1)
         ON DUPLICATE KEY UPDATE request_count = request_count + 1'
    );
    if (!$stmt) throw new RuntimeException('DB prepare failed.');
    $stmt->bind_param('si', $rateKey, $windowStart);
    $stmt->execute();
    $stmt->close();

    $check = $conn->prepare(
        'SELECT request_count FROM nutricula_rate_limits WHERE rate_key=? AND window_start=? LIMIT 1'
    );
    if (!$check) throw new RuntimeException('DB prepare failed.');
    $check->bind_param('si', $rateKey, $windowStart);
    $check->execute();
    $row = $check->get_result()->fetch_assoc();
    $check->close();

    $count = $row ? (int)$row['request_count'] : 1;
    if ($count > $limit) {
        http_response_code(429);
        header('Retry-After: ' . $windowSeconds);
        exit('no');
    }

    // Best-effort cleanup of old windows so this table doesn't grow
    // unboundedly - cheap (indexed range delete), and safe to skip on
    // failure since it's purely housekeeping, never a correctness
    // requirement.
    try {
        $cutoff = $windowStart - (10 * $windowSeconds);
        $conn->query('DELETE FROM nutricula_rate_limits WHERE window_start < ' . (int)$cutoff . ' LIMIT 1000');
    } catch (Throwable $ignored) {}
}

function nutricula_ip_in_cidrs(string $ip, array $cidrs): bool
{
    $ipBin = @inet_pton($ip);
    if ($ipBin === false) return false;

    foreach ($cidrs as $cidr) {
        $cidr = trim((string)$cidr);
        if ($cidr === '' || strpos($cidr, '/') === false) continue;
        [$network, $bitsText] = explode('/', $cidr, 2);
        $networkBin = @inet_pton(trim($network));
        $bits = (int)$bitsText;
        if ($networkBin === false || strlen($networkBin) !== strlen($ipBin)) continue;
        $maxBits = strlen($ipBin) * 8;
        if ($bits < 0 || $bits > $maxBits) continue;

        $fullBytes = intdiv($bits, 8);
        $remaining = $bits % 8;
        if ($fullBytes > 0 && substr($ipBin, 0, $fullBytes) !== substr($networkBin, 0, $fullBytes)) continue;
        if ($remaining === 0) return true;

        $mask = (0xFF << (8 - $remaining)) & 0xFF;
        if ((ord($ipBin[$fullBytes]) & $mask) === (ord($networkBin[$fullBytes]) & $mask)) return true;
    }
    return false;
}

function nutricula_required_field(array $fields, string $name): string
{
    if (!array_key_exists($name, $fields) || !is_string($fields[$name])) {
        throw new RuntimeException('Missing field: ' . $name);
    }
    return (string)$fields[$name];
}

/**
 * Strict replacement for parse_str() on the decrypted inner payload.
 *
 * parse_str() is a general-purpose query-string parser with behavior that
 * is more permissive than a security-critical protocol should rely on:
 * duplicate keys silently resolve to "last one wins" rather than being
 * rejected, and it happily accepts any field name at all. For an endpoint
 * where the entire inner string is attacker-reachable content IF the
 * transport key were ever extracted, being strict costs nothing for a
 * well-behaved client and closes off a class of "did the parser interpret
 * this the way I assumed" bugs.
 *
 * - Any field name not in $allowedFields is rejected outright.
 * - A repeated field name is rejected outright (no "last one wins").
 * - More than $maxFields distinct fields, or any single value longer than
 *   $maxFieldLength bytes, is rejected outright.
 */
function nutricula_strict_parse_fields(string $decrypted, array $allowedFields, int $maxFields = 24, int $maxFieldLength = 2048): array
{
    if (strlen($decrypted) > $maxFields * $maxFieldLength) {
        throw new RuntimeException('Payload too large.');
    }

    $allowed = array_flip($allowedFields);
    $result = [];

    foreach (explode('&', $decrypted) as $pair) {
        if ($pair === '') continue; // tolerate a trailing '&', nothing else
        if (count($result) >= $maxFields) {
            throw new RuntimeException('Too many fields.');
        }

        $eq = strpos($pair, '=');
        if ($eq === false) {
            throw new RuntimeException('Malformed field: ' . substr($pair, 0, 32));
        }

        $rawKey = substr($pair, 0, $eq);
        $rawValue = substr($pair, $eq + 1);

        /* rawurldecode() does not itself error on malformed percent-encoding
           (a bare '%' not followed by two hex digits) - it just passes the
           bytes through. For a cryptographic protocol, reject that outright
           rather than silently accepting non-canonical encoding. */
        if (preg_match('/%(?![0-9A-Fa-f]{2})/', $rawKey) || preg_match('/%(?![0-9A-Fa-f]{2})/', $rawValue)) {
            throw new RuntimeException('Malformed percent-encoding.');
        }

        $key = rawurldecode($rawKey);
        $value = rawurldecode($rawValue);

        if (!isset($allowed[$key])) {
            throw new RuntimeException('Unknown field: ' . substr($key, 0, 32));
        }
        if (array_key_exists($key, $result)) {
            throw new RuntimeException('Duplicate field: ' . $key);
        }
        if (strlen($value) > $maxFieldLength) {
            throw new RuntimeException('Field too long: ' . $key);
        }

        $result[$key] = $value;
    }

    return $result;
}

/** Strict RFC4122 v4 UUID format check - every UUID this system generates
    (nutricula_uuid()) matches this exact shape, so any incoming value
    claiming to be one of our IDs should too. Narrows attack surface /
    protocol ambiguity; the actual query is always parameterized regardless. */
function nutricula_is_valid_uuid(string $value): bool
{
    return (bool)preg_match(
        '/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/i',
        $value
    );
}

function nutricula_uuid(): string
{
    $data = random_bytes(16);
    $data[6] = chr((ord($data[6]) & 0x0F) | 0x40);
    $data[8] = chr((ord($data[8]) & 0x3F) | 0x80);
    return sprintf(
        '%s-%s-%s-%s-%s',
        bin2hex(substr($data, 0, 4)),
        bin2hex(substr($data, 4, 2)),
        bin2hex(substr($data, 6, 2)),
        bin2hex(substr($data, 8, 2)),
        bin2hex(substr($data, 10, 6))
    );
}

function nutricula_product_duration(int $productId)
{
    return [
        2652 => 6,
        2682 => 12,
        2685 => 24,
        2687 => 'lifetime',
    ][$productId] ?? null;
}

function nutricula_total_expiration($duration): int
{
    if ($duration === 'lifetime') {
        return strtotime('+20 years');
    }
    return strtotime('+' . ((int)$duration * 31) . ' days');
}

function nutricula_build_p256_pem(string $publicKeyB64): string
{
    $raw = base64_decode($publicKeyB64, true);
    if ($raw === false || strlen($raw) !== 64) {
        throw new RuntimeException('Invalid P-256 public key.');
    }

    $oidEc = "\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01";
    $oidCurve = "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07";
    $algorithm = nutricula_der_sequence($oidEc . $oidCurve);
    $point = "\x04" . $raw;
    $bitString = "\x03" . nutricula_der_length(strlen($point) + 1) . "\x00" . $point;
    $spki = nutricula_der_sequence($algorithm . $bitString);

    return "-----BEGIN PUBLIC KEY-----\n" .
        chunk_split(base64_encode($spki), 64, "\n") .
        "-----END PUBLIC KEY-----\n";
}

function nutricula_der_length(int $length): string
{
    if ($length < 128) return chr($length);
    $bytes = '';
    while ($length > 0) {
        $bytes = chr($length & 0xFF) . $bytes;
        $length >>= 8;
    }
    return chr(0x80 | strlen($bytes)) . $bytes;
}

function nutricula_der_sequence(string $body): string
{
    return "\x30" . nutricula_der_length(strlen($body)) . $body;
}

function nutricula_public_key_hash(string $publicKeyB64): string
{
    $raw = base64_decode($publicKeyB64, true);
    if ($raw === false || strlen($raw) !== 64) {
        throw new RuntimeException('Invalid public key.');
    }
    return strtoupper(hash('sha256', $raw));
}

function nutricula_validate_device_public_key(string $publicKeyB64): string
{
    if (!preg_match('/\A[A-Za-z0-9+\/=]{80,100}\z/', $publicKeyB64)) {
        throw new RuntimeException('Malformed public key.');
    }
    $pem = nutricula_build_p256_pem($publicKeyB64);
    $key = openssl_pkey_get_public($pem);
    if ($key === false) throw new RuntimeException('Invalid P-256 public key.');
    $details = openssl_pkey_get_details($key);
    if (!is_array($details) || (int)($details['bits'] ?? 0) !== 256) {
        throw new RuntimeException('Invalid P-256 public key size.');
    }
    return $pem;
}

function nutricula_raw_ecdsa_to_der(string $raw): string
{
    if (strlen($raw) !== 64) throw new RuntimeException('Invalid ECDSA signature length.');
    $r = ltrim(substr($raw, 0, 32), "\0");
    $s = ltrim(substr($raw, 32, 32), "\0");
    if ($r === '') $r = "\0";
    if ($s === '') $s = "\0";
    if ((ord($r[0]) & 0x80) !== 0) $r = "\0" . $r;
    if ((ord($s[0]) & 0x80) !== 0) $s = "\0" . $s;
    $rDer = "\x02" . nutricula_der_length(strlen($r)) . $r;
    $sDer = "\x02" . nutricula_der_length(strlen($s)) . $s;
    return "\x30" . nutricula_der_length(strlen($rDer . $sDer)) . $rDer . $sDer;
}

function nutricula_verify_device_signature(string $publicKeyPem, string $message, string $signatureB64): bool
{
    $key = openssl_pkey_get_public($publicKeyPem);
    if ($key === false) return false;
    $raw = base64_decode($signatureB64, true);
    if ($raw === false || strlen($raw) !== 64) return false;
    try {
        $der = nutricula_raw_ecdsa_to_der($raw);
    } catch (Throwable $e) {
        return false;
    }
    return openssl_verify($message, $der, $key, OPENSSL_ALGO_SHA256) === 1;
}

function nutricula_server_sign(string $canonical, array $config): string
{
    $pem = @file_get_contents((string)$config['server_signing_private_key_path']);
    if ($pem === false || $pem === '') throw new RuntimeException('Server signing key unavailable.');
    $key = openssl_pkey_get_private($pem);
    if ($key === false) throw new RuntimeException('Server signing key invalid.');
    $signature = '';
    if (!openssl_sign($canonical, $signature, $key, OPENSSL_ALGO_SHA256)) {
        throw new RuntimeException('Server signing failed.');
    }
    return base64_encode($signature);
}

/* A licensing endpoint has no legitimate reason to process an arbitrarily
   large response from the EDD sales API, whatever might cause it to grow. */
const NUTRICULA_MAX_EDD_RESPONSE_BYTES = 262144; // 256KB
const NUTRICULA_TRANSFER_KEY_PRODUCT_ID = 11348;

/** Fetches this email's EDD sales list once - shared by every code path that
    needs to check something against it (a license purchase, a transfer-key
    purchase, or both in the same request), so a single caller checking both
    only makes one outbound EDD call, not two. */
function nutricula_fetch_edd_sales(array $config, string $email): array
{
    // NOTE: assumed this EDD store lives at the same domain as everything
    // else in this project (nutriculaexpert.com) - the old value here was
    // nutriculaexpert.ir, which was stale/wrong everywhere else in this
    // codebase too. If your EDD store is genuinely hosted elsewhere,
    // correct this URL manually.
    $url =
        'https://nutriculaexpert.com/edd-api/sales/' .
        '?key=' . urlencode((string)$config['edd']['api_key']) .
        '&token=' . urlencode((string)$config['edd']['api_token']) .
        '&number=100&email=' . urlencode($email);

    $ctx = stream_context_create([
        'http' => [
            'timeout' => 20,
            'ignore_errors' => true,
        ],
    ]);

    /* Cap how much of the response we'll ever read (see constant above). */
    $json = @file_get_contents($url, false, $ctx, 0, NUTRICULA_MAX_EDD_RESPONSE_BYTES);
    if ($json === false) throw new RuntimeException('EDD request failed.');

    $data = json_decode($json, true);
    if (!is_array($data) || !isset($data['sales']) || !is_array($data['sales'])) {
        throw new RuntimeException('EDD response is invalid.');
    }
    return $data['sales'];
}

function nutricula_find_edd_sale(array $config, string $email, string $purchaseKey): array
{
    $sales = nutricula_fetch_edd_sales($config, $email);
    return nutricula_find_edd_sale_in($sales, $purchaseKey);
}

function nutricula_find_edd_sale_in(array $sales, string $purchaseKey): array
{
    foreach ($sales as $sale) {
        if (!isset($sale['key'], $sale['products'][0]['id'])) continue;
        if (!hash_equals((string)$sale['key'], $purchaseKey)) continue;
        $productId = (int)$sale['products'][0]['id'];
        $duration = nutricula_product_duration($productId);
        if ($duration === null) continue;
        return [
            'sale' => $sale,
            'product_id' => $productId,
            'duration' => $duration,
            'product_name' => (string)($sale['products'][0]['name'] ?? 'N/A'),
        ];
    }
    throw new RuntimeException('Purchase was not found.');
}

/** Same idea as nutricula_find_edd_sale(), but scoped to the Transfer Key
    product specifically (11348) rather than the license products. Operates
    on an already-fetched sales list (see nutricula_fetch_edd_sales) so
    checking both a purchase_key and a transfer_key for the same email costs
    one EDD call total, not two. */
function nutricula_find_edd_transfer_purchase_in(array $sales, string $transferKey): array
{
    foreach ($sales as $sale) {
        if (!isset($sale['key'], $sale['products'][0]['id'])) continue;
        if (!hash_equals((string)$sale['key'], $transferKey)) continue;
        $productId = (int)$sale['products'][0]['id'];
        if ($productId !== NUTRICULA_TRANSFER_KEY_PRODUCT_ID) continue;
        return ['sale' => $sale, 'product_id' => $productId];
    }
    throw new RuntimeException('Transfer key was not found.');
}
