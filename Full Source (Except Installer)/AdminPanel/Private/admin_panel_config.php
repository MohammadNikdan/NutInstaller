<?php

/* ============================================================================
   admin_panel_config.php - fill in the three REPLACE_ME/REPLACE_WITH_...
   placeholders below, then upload this ONE file to your Private folder
   (the SAME outside-webroot folder license_config.php already lives in,
   e.g. /home/nutricul/Private/) - never inside
   any domain's public_html, not even the admin subdomain's. If
   admin_common.php's ADMIN_CONFIG_PATH constant doesn't already point at
   wherever you put it, update that constant to match.
   ----------------------------------------------------------------------------
   1. 'db': the SAME database credentials license_config.php already uses -
      this panel reads/writes a few extra tables in that same database, it
      is not a separate database.
   2. 'admin_password_hash': NEVER put your real password here as plaintext.
      On the server (or any PHP CLI), run:
          php -r "echo password_hash('your-real-password-here', PASSWORD_BCRYPT), PHP_EOL;"
      and paste the $2y$... output it prints in place of the placeholder
      below. The plaintext password itself is never written anywhere once
      you've done this - only the hash is stored, and only a correct
      password will ever verify against it.
   3. 'session_cookie_name' can be left as-is.
   ============================================================================ */

return [
    'db' => [
        'host' => 'localhost',
        'user' => 'REPLACE_ME',
        'pass' => 'REPLACE_ME',
        'name' => 'REPLACE_ME',
        'charset' => 'utf8mb4',
    ],

    // Generate with: php -r "echo password_hash('your-password', PASSWORD_BCRYPT), PHP_EOL;"
    'admin_password_hash' => '$2y$10$REPLACE_WITH_YOUR_OWN_GENERATED_HASH_____________________',

    // Cookie name for the admin session - can stay as-is, or change to
    // anything else you like (purely cosmetic, not a security control).
    'session_cookie_name' => 'nutricula_admin_sess',

    // Cloudflare real-visitor-IP trust (only matters if panel.nutricula.trade
    // is proxied / orange cloud). Leave '' to disable. If set, it must be at
    // least 32 characters (letters and digits) and EXACTLY equal to the value
    // of the X-Nutricula-Edge header that the Cloudflare Transform Rule adds
    // for panel.nutricula.trade. While the DNS record is gray the header never
    // arrives, so a value here is simply ignored and the real connection IP
    // is used - it is safe to keep it filled in at all times.
    'cloudflare_origin_secret' => '',

    // The hostname passkeys are bound to (the WebAuthn "rpId"). Set it to the
    // exact hostname the panel is browsed at, as a bare hostname: no https://,
    // no port, no trailing slash.
    //
    // Why it is configured rather than taken from the request: the Host header
    // is whatever the client sends, so leaving it to the request meant the
    // panel could register a passkey under one hostname and then try to verify
    // it under another - for instance after being reached through a www.
    // variant, the bare IP, or a staging name that points at the same server.
    // The symptom is a passkey that works from one address and not another,
    // with nothing to indicate why.
    //
    // CHANGING THIS INVALIDATES EVERY REGISTERED PASSKEY, because an
    // authenticator keys its credentials to this value. After changing it,
    // log in with the password and register the passkeys again.
    //
    // Left empty, the panel falls back to the request's Host header (the old
    // behaviour) and notes it in the PHP error log.
    'webauthn_rp_id' => 'panel.nutricula.trade',
];
