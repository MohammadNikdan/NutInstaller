<?php

declare(strict_types=1);

/* admin_webauthn_common.php - minimal, dependency-free WebAuthn (passkey)
   support for this admin panel.

   Why hand-rolled instead of a library: the standard PHP WebAuthn libraries
   (web-auth/webauthn-lib and friends) pull in a dozen+ Composer packages
   (CBOR decoding, COSE, PSR interfaces...) - fine on a dev machine, painful
   on ordinary shared hosting with no SSH/Composer access and file-manager-
   only deployment. This file implements only the slice of the spec this
   panel actually needs:
     - ES256 (ECDSA P-256 / SHA-256) credentials only. This covers Face ID,
       Touch ID, and virtually every Android fingerprint/face platform
       authenticator. Windows Hello can also do ES256 - we only ever ask
       for alg -7 (ES256), so an authenticator that can't do it simply won't
       offer itself during registration, which is an acceptable trade-off
       for the simplicity this buys.
     - Non-discoverable credentials ("allowCredentials" lists exactly the
       credential IDs this one admin has registered - there is no separate
       username step, since there is exactly one admin account).
     - NO attestation statement verification. We only parse the
       attestationObject far enough to read authData (rpIdHash, flags,
       signCount, credentialId, the COSE public key) and WE DO NOT verify
       the attestation signature/certificate chain. For a self-hosted
       single-admin tool this is a reasonable simplification (the thing
       actually being defended is "can this device's own fingerprint sensor
       produce a valid signature", not "which vendor manufactured the
       authenticator") - but it does mean this is a lighter trust model than
       a corporate SSO's attestation policy would use.

   Every verification step below throws a WebAuthnError with a specific,
   human-readable reason on failure rather than failing silently - since
   nobody can single-step a live passkey ceremony in a debugger, a precise
   error message is the only diagnostic tool available if something doesn't
   verify on a real device. */

class WebAuthnError extends \RuntimeException {}

// ---------------------------------------------------------------- base64url
function nutricula_b64url_encode(string $bin): string
{
    return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}

function nutricula_b64url_decode(string $str): string
{
    $pad = strlen($str) % 4;
    if ($pad > 0) $str .= str_repeat('=', 4 - $pad);
    $decoded = base64_decode(strtr($str, '-_', '+/'), true);
    if ($decoded === false) throw new WebAuthnError('Invalid base64url data.');
    return $decoded;
}

// --------------------------------------------------------------------------
// Minimal CBOR decoder - just enough to walk attestationObject / COSE_Key
// maps. Only definite-length major types 0,1,2,3,4,5,7 are supported (every
// CTAP2 authenticator response uses definite-length canonical CBOR, so this
// is not a real-world limitation here).
// --------------------------------------------------------------------------
final class MiniCbor
{
    public static function decode(string $data, int &$pos)
    {
        self::needBytes($data, $pos, 1);
        $initial = ord($data[$pos]);
        $majorType = $initial >> 5;
        $additional = $initial & 0x1f;
        $pos++;

        $length = self::readLength($data, $pos, $additional);

        switch ($majorType) {
            case 0: // unsigned int
                return $length;
            case 1: // negative int
                return -1 - $length;
            case 2: // byte string
                self::needBytes($data, $pos, $length);
                $bytes = substr($data, $pos, $length);
                $pos += $length;
                return $bytes;
            case 3: // text string
                self::needBytes($data, $pos, $length);
                $str = substr($data, $pos, $length);
                $pos += $length;
                return $str;
            case 4: // array
                $out = [];
                for ($i = 0; $i < $length; $i++) {
                    $out[] = self::decode($data, $pos);
                }
                return $out;
            case 5: // map
                $out = [];
                for ($i = 0; $i < $length; $i++) {
                    $k = self::decode($data, $pos);
                    $v = self::decode($data, $pos);
                    $out[$k] = $v;
                }
                return $out;
            case 7: // simple/float - only the fixed-width simple values we might see
                if ($additional === 20) return false;
                if ($additional === 21) return true;
                if ($additional === 22) return null;
                throw new WebAuthnError('Unsupported CBOR simple/float value (major type 7).');
            default:
                throw new WebAuthnError('Unsupported CBOR major type: ' . $majorType);
        }
    }

    private static function readLength(string $data, int &$pos, int $additional): int
    {
        if ($additional <= 23) return $additional;
        if ($additional === 24) { self::needBytes($data, $pos, 1); $v = ord($data[$pos]); $pos += 1; return $v; }
        if ($additional === 25) { self::needBytes($data, $pos, 2); $v = unpack('n', substr($data, $pos, 2))[1]; $pos += 2; return $v; }
        if ($additional === 26) { self::needBytes($data, $pos, 4); $v = unpack('N', substr($data, $pos, 4))[1]; $pos += 4; return $v; }
        if ($additional === 27) {
            self::needBytes($data, $pos, 8);
            $hi = unpack('N', substr($data, $pos, 4))[1];
            $lo = unpack('N', substr($data, $pos + 4, 4))[1];
            $pos += 8;
            return ($hi << 32) | $lo;
        }
        throw new WebAuthnError('Indefinite-length CBOR items are not supported.');
    }

    private static function needBytes(string $data, int $pos, int $n): void
    {
        if ($pos + $n > strlen($data)) throw new WebAuthnError('Truncated CBOR data.');
    }
}

// --------------------------------------------------------------------------
// authenticatorData parsing (binary, NOT CBOR - see WebAuthn L2 §6.1).
// --------------------------------------------------------------------------
function nutricula_webauthn_parse_auth_data(string $authData): array
{
    if (strlen($authData) < 37) throw new WebAuthnError('authenticatorData too short.');
    $rpIdHash = substr($authData, 0, 32);
    $flags = ord($authData[32]);
    $signCount = unpack('N', substr($authData, 33, 4))[1];

    $result = [
        'rpIdHash' => $rpIdHash,
        'flags' => $flags,
        'userPresent' => (bool)($flags & 0x01),
        'userVerified' => (bool)($flags & 0x04),
        'signCount' => $signCount,
        'credentialId' => null,
        'cosePublicKey' => null,
    ];

    $pos = 37;
    $attestedDataIncluded = (bool)($flags & 0x40);
    if ($attestedDataIncluded) {
        if (strlen($authData) < $pos + 16 + 2) throw new WebAuthnError('authenticatorData truncated (aaguid/credIdLen).');
        $pos += 16; // aaguid - not checked, we don't pin to a specific authenticator model
        $credIdLen = unpack('n', substr($authData, $pos, 2))[1];
        $pos += 2;
        if (strlen($authData) < $pos + $credIdLen) throw new WebAuthnError('authenticatorData truncated (credentialId).');
        $result['credentialId'] = substr($authData, $pos, $credIdLen);
        $pos += $credIdLen;
        // Remainder is a single CBOR-encoded COSE_Key map. Anything after it
        // (extensions) is ignored - we never request extensions.
        $coseMap = MiniCbor::decode($authData, $pos);
        $result['cosePublicKey'] = $coseMap;
    }

    return $result;
}

/* Builds a PEM "public key" string from raw P-256 (X,Y) coordinates, usable
   directly with openssl_verify(). The DER prefix below is the fixed,
   well-known SubjectPublicKeyInfo header for id-ecPublicKey + prime256v1 -
   only the 64-byte uncompressed point (X || Y) varies per key. */
function nutricula_webauthn_xy_to_pem(string $x, string $y): string
{
    if (strlen($x) !== 32 || strlen($y) !== 32) {
        throw new WebAuthnError('Malformed EC2 public key coordinates (expected 32 bytes each).');
    }
    $derPrefix = hex2bin('3059301306072a8648ce3d020106082a8648ce3d03010703420004');
    $der = $derPrefix . $x . $y;
    $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";

    // Fail loudly here rather than at the call site, with the actual OpenSSL
    // error attached - this is the single most likely spot for a silent,
    // hard-to-diagnose failure if the DER prefix above were ever wrong.
    $key = openssl_pkey_get_public($pem);
    if ($key === false) {
        throw new WebAuthnError('Failed to parse constructed EC public key: ' . (openssl_error_string() ?: 'unknown OpenSSL error'));
    }
    return $pem;
}

/* Validates a COSE EC2/P-256/ES256 key map (as decoded off the wire during
   registration) and returns its raw [x, y] coordinate pair. Rejects anything
   that isn't exactly ES256 - see this file's top comment for why that scope
   is deliberate. */
function nutricula_webauthn_cose_to_xy(array $cose): array
{
    $kty = $cose[1] ?? null;   // 1 = kty
    $alg = $cose[3] ?? null;   // 3 = alg
    $crv = $cose[-1] ?? null;  // -1 = crv
    $x = $cose[-2] ?? null;    // -2 = x
    $y = $cose[-3] ?? null;    // -3 = y

    if ($kty !== 2) throw new WebAuthnError('Only EC2 (kty=2) COSE keys are supported, got kty=' . var_export($kty, true));
    if ($alg !== -7) throw new WebAuthnError('Only ES256 (alg=-7) credentials are supported, got alg=' . var_export($alg, true));
    if ($crv !== 1) throw new WebAuthnError('Only P-256 (crv=1) is supported, got crv=' . var_export($crv, true));
    if (!is_string($x) || strlen($x) !== 32 || !is_string($y) || strlen($y) !== 32) {
        throw new WebAuthnError('Malformed EC2 public key coordinates.');
    }
    return [$x, $y];
}

/* Verifies clientDataJSON's basic shape: correct ceremony type, challenge
   matches what we issued, and origin matches this exact site (never a
   substring/suffix check - that is how origin checks get bypassed). */
function nutricula_webauthn_check_client_data(string $clientDataJSON, string $expectedType, string $expectedChallengeB64url, string $expectedOrigin): array
{
    $clientData = json_decode($clientDataJSON, true);
    if (!is_array($clientData)) throw new WebAuthnError('clientDataJSON is not valid JSON.');
    if (($clientData['type'] ?? null) !== $expectedType) {
        throw new WebAuthnError('Unexpected ceremony type: ' . (string)($clientData['type'] ?? ''));
    }
    if (!hash_equals($expectedChallengeB64url, (string)($clientData['challenge'] ?? ''))) {
        throw new WebAuthnError('Challenge mismatch (replay, or a stale/expired login attempt).');
    }
    if (!hash_equals($expectedOrigin, (string)($clientData['origin'] ?? ''))) {
        throw new WebAuthnError('Origin mismatch: expected ' . $expectedOrigin . ', got ' . (string)($clientData['origin'] ?? ''));
    }
    return $clientData;
}

function nutricula_webauthn_rp_id(): string
{
    // The admin panel's own hostname - passkeys are scoped to this exact
    // subdomain, never the parent domain (no cross-subdomain SSO intended).
    return (string)($_SERVER['HTTP_HOST'] ?? '');
}

function nutricula_webauthn_origin(): string
{
    return 'https://' . nutricula_webauthn_rp_id();
}

/* Every admin_passkey_*.php endpoint queries nutricula_admin_passkeys. If
   that table was never created (the schema.sql block for it not yet run
   against this database), mysqli throws (PHP 8.1+ throws by default on a
   SQL error) and every one of those endpoints would otherwise just show a
   generic "Internal error." - impossible to tell apart from a real bug
   without reading the server's error_log, which this host makes awkward to
   reach. Call this right after nutricula_admin_db() in each of those
   endpoints so a missing table says so in plain language instead. */
function nutricula_webauthn_require_table(mysqli $conn): void
{
    $res = $conn->query("SHOW TABLES LIKE 'nutricula_admin_passkeys'");
    if (!$res || $res->num_rows === 0) {
        throw new WebAuthnError(
            "The nutricula_admin_passkeys table does not exist yet. Run the " .
            "nutricula_admin_passkeys CREATE TABLE block from schema.sql " .
            "against this database, then reload the page."
        );
    }
}
