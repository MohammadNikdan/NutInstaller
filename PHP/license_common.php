<?php

declare(strict_types=1);

function nutricula_load_config(): array
{
    $path = '/home/nutricu1/domains/nutriculaexpert.ir/private_keys/license_config.php';
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

    if (!array_key_exists('transport_key_hex', $config) ||
        !preg_match('/\A[0-9a-fA-F]{64}\z/', (string)$config['transport_key_hex'])) {
        $errors[] = 'transport_key_hex is missing or not exactly 64 hex characters.';
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
    $hex = (string)($config['transport_key_hex'] ?? '');
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
    $body =
        'NL3-REJECT' .
        '|reason=' . $reason .
        '|requested_at=' . $now .
        '|retry_after_seconds=' . max(0, $retryAfterSeconds);

    http_response_code(200);
    header('Content-Type: text/plain; charset=UTF-8');
    try {
        echo nutricula_gcm_encrypt($body, $config);
    } catch (Throwable $e) {
        echo 'no';
    }
    exit;
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
 * Statistics only - records that this (machine_id, device_public_key_hash)
 * pair checked in without having a license. Purely additive/informational:
 * deliberately never throws, so a failure here can never interfere with the
 * actual license_not_found response the caller is about to send.
 */
function nutricula_track_unlicensed_checkin(mysqli $conn, string $machineId, string $deviceKeyHash): void
{
    try {
        $stmt = $conn->prepare(
            'INSERT INTO nutricula_unlicensed_checkins
             (machine_id, device_public_key_hash, first_seen_at, last_seen_at)
             VALUES (?, ?, NOW(), NOW())
             ON DUPLICATE KEY UPDATE last_seen_at = NOW()'
        );
        if (!$stmt) {
            error_log('[Nutricula unlicensed tracking] prepare failed');
            return;
        }
        $stmt->bind_param('ss', $machineId, $deviceKeyHash);
        if (!$stmt->execute()) {
            error_log('[Nutricula unlicensed tracking] insert/update failed');
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
function nutricula_strict_parse_fields(string $decrypted, array $allowedFields, int $maxFields = 12, int $maxFieldLength = 2048): array
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
    $url =
        'https://nutriculaexpert.ir/edd-api/sales/' .
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
