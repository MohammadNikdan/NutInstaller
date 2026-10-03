<?php

declare(strict_types=1);

date_default_timezone_set('UTC');

/* admin_common.php - shared bootstrap for every admin_*.php endpoint.
   Deliberately self-contained (does NOT require() the public license
   system's license_common.php) even though both ultimately talk to the
   same MySQL database - this admin panel is deployed to its OWN
   subdomain/docroot, which may not sit anywhere near the public license
   endpoints' files on disk, and keeping it self-contained means this
   folder can be copied anywhere without caring about the other codebase's
   internal layout. The only thing genuinely shared is which database to
   connect to (see nutricula_admin_load_config() below).

   SECURITY MODEL (read this before changing anything here):
   - Exactly one admin, authenticated with a password (bcrypt hash) +
     a server-side session. No API token, no "secret URL" is treated as a
     real security boundary - the private config file this reads is well
     outside any web-servable docroot, and the panel's own non-guessable
     subdomain is an obscurity bonus, not the actual gate.
   - Every endpoint except admin_login.php MUST call
     nutricula_admin_require_auth() as its very first action.
   - Every MUTATING endpoint (currently just admin_ban.php) MUST also call
     nutricula_admin_require_csrf() after that.
*/

// ============================================================================
// Private config - EDIT THIS PATH to wherever you place admin_config.php on
// your actual hosting account. It MUST live outside any web-servable
// directory (same principle as license_config.php for the main license
// system) - if a visitor can fetch this file's raw contents over HTTP, the
// DB password and the admin password hash are both compromised.
// ============================================================================
const ADMIN_CONFIG_PATH = '/home/nutricul/domains/nutriculaexpert.com/Private/admin_panel_config.php';

function nutricula_admin_load_config(): array
{
    if (!is_file(ADMIN_CONFIG_PATH)) {
        http_response_code(500);
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode(['error' => 'Admin panel is not configured yet (admin_panel_config.php missing).']);
        exit;
    }
    $config = require ADMIN_CONFIG_PATH;
    if (!is_array($config) || empty($config['admin_password_hash']) || empty($config['db'])) {
        http_response_code(500);
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode(['error' => 'Admin panel configuration is incomplete.']);
        exit;
    }
    return $config;
}

function nutricula_admin_db(array $config): mysqli
{
    $db = $config['db'];
    $conn = new mysqli(
        (string)$db['host'],
        (string)$db['user'],
        (string)$db['pass'],
        (string)$db['name']
    );
    if ($conn->connect_error) {
        http_response_code(500);
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode(['error' => 'Database connection failed.']);
        exit;
    }
    $conn->set_charset((string)($db['charset'] ?? 'utf8mb4'));
    $conn->query("SET time_zone = '+00:00'");
    return $conn;
}

/* Must be called before session_start() anywhere else in this request -
   PHP's defaults (no Secure/SameSite) are not acceptable for a panel that
   can ban/unban users. */
function nutricula_admin_start_session(array $config): void
{
    $cookieName = (string)($config['session_cookie_name'] ?? 'nutricula_admin_sess');
    session_name($cookieName);
    session_set_cookie_params([
        'lifetime' => 0,          // session cookie - cleared when the browser/PWA is fully closed
        'path' => '/',
        'domain' => '',           // current host only (the admin subdomain itself)
        'secure' => true,         // never sent over plain HTTP
        'httponly' => true,       // never readable from JS - defeats a stray XSS reading the cookie
        'samesite' => 'Strict',   // never sent on a cross-site request at all
    ]);
    session_start();
}

function nutricula_admin_client_ip(): string
{
    $remote = trim((string)($_SERVER['REMOTE_ADDR'] ?? ''));
    return filter_var($remote, FILTER_VALIDATE_IP) ? $remote : '0.0.0.0';
}

/* Simple, self-contained login-attempt throttle, reusing the SAME
   nutricula_rate_limits table the public license endpoints already use
   (same database) - a fixed 15-minute window per client IP, independent of
   that table's other 60-second-window rows (different rate_key prefix,
   different window size, so the two never interact). 8 attempts/15min is
   far above any legitimate use (there is exactly one admin logging in from
   exactly one phone) and low enough to make password guessing impractical. */
function nutricula_admin_login_rate_ok(mysqli $conn): bool
{
    $limit = 8;
    $windowSeconds = 900;
    $rateKey = 'admin_login|' . nutricula_admin_client_ip();
    $windowStart = intdiv(time(), $windowSeconds) * $windowSeconds;

    $stmt = $conn->prepare(
        'INSERT INTO nutricula_rate_limits (rate_key, window_start, request_count)
         VALUES (?, ?, 1)
         ON DUPLICATE KEY UPDATE request_count = request_count + 1'
    );
    if (!$stmt) return true; // fail open on infra trouble - never lock the one admin out
    $stmt->bind_param('si', $rateKey, $windowStart);
    $stmt->execute();
    $stmt->close();

    $check = $conn->prepare('SELECT request_count FROM nutricula_rate_limits WHERE rate_key=? AND window_start=?');
    if (!$check) return true;
    $check->bind_param('si', $rateKey, $windowStart);
    $check->execute();
    $row = $check->get_result()->fetch_assoc();
    $check->close();

    return !$row || (int)$row['request_count'] <= $limit;
}

/* Call as the first line of every admin_*.php EXCEPT admin_login.php. */
function nutricula_admin_require_auth(): void
{
    if (empty($_SESSION['nutricula_admin_authenticated'])) {
        http_response_code(401);
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode(['error' => 'Not authenticated.']);
        exit;
    }
    // Idle timeout - 12 hours of inactivity logs the session out even if the
    // PWA/tab is left open, same spirit as a bank app.
    $lastActivity = (int)($_SESSION['nutricula_admin_last_activity'] ?? 0);
    if ($lastActivity > 0 && (time() - $lastActivity) > 12 * 3600) {
        $_SESSION = [];
        session_destroy();
        http_response_code(401);
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode(['error' => 'Session expired.']);
        exit;
    }
    $_SESSION['nutricula_admin_last_activity'] = time();
}

/* Call after nutricula_admin_require_auth() on every MUTATING endpoint.
   Expects the token in the X-Admin-CSRF request header (never in a cookie-
   readable place, never in the URL where it could end up in a server log). */
function nutricula_admin_require_csrf(): void
{
    $sent = (string)($_SERVER['HTTP_X_ADMIN_CSRF'] ?? '');
    $expected = (string)($_SESSION['nutricula_admin_csrf'] ?? '');
    if ($expected === '' || $sent === '' || !hash_equals($expected, $sent)) {
        http_response_code(403);
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode(['error' => 'Invalid or missing CSRF token.']);
        exit;
    }
}

function nutricula_admin_audit(mysqli $conn, string $action, string $targetType, string $targetDetail): void
{
    try {
        $stmt = $conn->prepare(
            'INSERT INTO nutricula_admin_audit_log (occurred_at, action, target_type, target_detail, admin_ip)
             VALUES (NOW(), ?, ?, ?, ?)'
        );
        if (!$stmt) return;
        $ip = nutricula_admin_client_ip();
        $stmt->bind_param('ssss', $action, $targetType, $targetDetail, $ip);
        $stmt->execute();
        $stmt->close();
    } catch (Throwable $e) {
        error_log('[Nutricula admin audit] ' . $e->getMessage());
    }
}

function nutricula_admin_json_body(): array
{
    $raw = file_get_contents('php://input') ?: '';
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function nutricula_admin_send_json($data): never
{
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode($data);
    exit;
}

// Same check as nutricula_is_valid_uuid() in the public license codebase's
// license_common.php - duplicated here rather than shared, since this panel
// is deliberately self-contained (see this file's own top comment).
function nutricula_is_valid_uuid(string $value): bool
{
    return (bool)preg_match(
        '/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/i',
        $value
    );
}
