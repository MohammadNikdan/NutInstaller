<?php

/* ============================================================================
   SAMPLE admin panel config - DO NOT upload this file as-is.
   ----------------------------------------------------------------------------
   1. Copy this file's CONTENT (not the file itself) to a NEW file at the
      exact path admin_common.php's ADMIN_CONFIG_PATH constant points to,
      e.g.:
          /home/nutricul/domains/nutriculaexpert.com/Private/admin_panel_config.php
      That "Private" folder is the SAME one license_config.php already lives
      in - it is OUTSIDE every domain's public_html, so nothing inside it is
      ever reachable over HTTP. If your hosting uses a different private
      folder name/path, use that instead, and update ADMIN_CONFIG_PATH in
      admin_common.php to match.
   2. Fill in the 'db' block below with the SAME database credentials the
      main license system's license_config.php already uses (same database -
      this panel only reads/writes a few extra tables in it).
   3. Generate your own password hash - NEVER type your real password into
      this file directly as plaintext, and never send it to anyone,
      including me. On the server (or any PHP CLI), run:
          php -r "echo password_hash('your-real-password-here', PASSWORD_BCRYPT), PHP_EOL;"
      Paste the $2y$... output below as admin_password_hash. The plaintext
      password is never stored anywhere once you've done this.
   4. Delete this SAMPLE file from the server - it has no function once the
      real one is in place, and an old copy sitting around face the same
      path-guessing risk this whole setup is trying to avoid.
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
];
