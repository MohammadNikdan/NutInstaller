/* ============================================================================
   Nutricula License System — FULL SCHEMA (fresh install)
   ============================================================================
   This file creates every table needed for the license system from a
   completely empty database. It is always kept fully up to date - there is
   no separate "migration-only" file to track alongside it. Whenever the
   schema changes, THIS file is regenerated in full; if the database is ever
   dropped and recreated, running this one file is always sufficient on its
   own, with nothing else needed first or after.
   ============================================================================ */

CREATE TABLE nutricula_licenses (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    license_uuid CHAR(36) NOT NULL,
    user_email VARCHAR(320) NOT NULL,
    purchase_key VARCHAR(255) NOT NULL,
    product_id INT UNSIGNED NOT NULL,
    product_name VARCHAR(255) NOT NULL,
    machine_id CHAR(64) NOT NULL,
    device_public_key_b64 VARCHAR(128) NOT NULL,
    device_public_key_hash CHAR(64) NOT NULL,
    device_type ENUM('windows','windows_vm','macos_wine','linux_wine','unknown') NOT NULL DEFAULT 'unknown',
    claimed_local_ip VARCHAR(45) NULL,
    first_observed_ip VARCHAR(45) NOT NULL,
    last_observed_ip VARCHAR(45) NOT NULL,
    license_issued_at BIGINT UNSIGNED NOT NULL,
    license_expires_at BIGINT UNSIGNED NOT NULL,
    /* last_request_time: touched on EVERY request attempt for this license
       (challenge stage, and signup's existing-license-match path) - whether
       that attempt was accepted or rejected by the min_request_gap_seconds
       time lock. This is what the time lock itself compares against. */
    last_request_time BIGINT UNSIGNED NULL,
    /* last_success_time: touched ONLY when a request actually completes
       successfully (signup success, or verify success). Distinct from
       last_request_time so "when did this device last try" and "when did it
       last actually succeed" can be told apart. */
    last_success_time BIGINT UNSIGNED NULL,

    /* --- VPS IP-Binding (audit/support only - 2026) ---
       For device_type='windows_vm' licenses, the `machine_id` column above
       already contains SHA-256("NUTRICULA_VPS_BIND_V1|"+raw_machine_id+
       "|"+canonical_ip) - see nutricula_effective_machine_id() in
       license_common.php, which is the ONLY thing any security decision
       ever compares. vps_bound_ip below is NOT used in any authorization
       check anywhere - it exists purely so support staff can see, in
       plain text, which IP a VPS license was bound to when a customer
       reports it broke, without which the opaque machine_id hash gives no
       clue at all what actually changed. NULL for every non-VPS license. */
    vps_bound_ip VARCHAR(45) NULL,

    /* --- Rotating single-use refresh token (Clone/Copy detection) ---
       current_refresh_token_hash: SHA-256 of the ONLY token this license
       currently accepts. Every successful verify rotates this to a fresh
       random value and returns the new plaintext token to the client
       inside the signed lease. A client presenting anything other than
       the CURRENT token (regardless of how many generations old it is -
       generation distance is irrelevant) is presenting a stale token.
       token_suspicious: set true the first time a stale token is seen
       for this license since the last successful (current-token) request;
       cleared on the next successful request. A SECOND stale-token event
       while this is already true triggers the 24h block below - this is
       what "two consecutive stale-token presentations" actually means. */
    current_refresh_token_hash CHAR(64) NULL,
    token_suspicious TINYINT(1) NOT NULL DEFAULT 0,
    /* blocked_until: when set and in the future, ALL verify/challenge
       requests for this license are rejected outright (mapped to tier
       -100 client-side) regardless of token validity - this is the 24h
       punishment applied to BOTH machines sharing a cloned identity,
       since the server cannot tell which one is the legitimate owner. */
    blocked_until BIGINT UNSIGNED NULL,

    status ENUM('active','expired','revoked') NOT NULL DEFAULT 'active',
    activated_at DATETIME NOT NULL,
    last_seen_at DATETIME NULL,
    /* Admin panel (2026): the build_id this license's device verified with
       on its last successful 'verify' request (see license_check.php's
       lease-issuance UPDATE) - lets the admin dashboard show what fraction
       of active installs have adopted the latest release, grouped via
       nutricula_build_manifests.version. NULL until the first verify after
       this column existed. */
    last_build_id VARCHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_license_uuid (license_uuid),
    UNIQUE KEY uq_purchase_key (purchase_key),
    /* Prevents the SAME device from ending up with two different license
       rows for the SAME product (e.g. via two different purchase_keys) -
       an anomaly, not a legitimate use case. Does NOT restrict a device
       from holding licenses for several different products, or the same
       product being legitimately activated on several different devices -
       both are normal and remain fully supported. */
    UNIQUE KEY uq_product_device (product_id, device_public_key_hash),
    KEY idx_machine_id (machine_id),
    KEY idx_device_key_hash (device_public_key_hash),
    KEY idx_user_email (user_email),
    KEY idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE nutricula_license_challenges (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    challenge_id CHAR(36) NOT NULL,
    license_id BIGINT UNSIGNED NOT NULL,
    nonce BINARY(32) NOT NULL,
    request_ip VARCHAR(45) NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_challenge_id (challenge_id),
    KEY idx_challenge_license (license_id),
    KEY idx_challenge_expires (expires_at),
    CONSTRAINT fk_challenge_license
        FOREIGN KEY (license_id) REFERENCES nutricula_licenses(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE nutricula_license_activity (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    license_id BIGINT UNSIGNED NOT NULL,
    machine_id CHAR(64) NOT NULL,
    device_public_key_hash CHAR(64) NOT NULL,
    claimed_local_ip VARCHAR(45) NULL,
    observed_ip VARCHAR(45) NOT NULL,
    occurred_at DATETIME NOT NULL,
    request_type ENUM('signup','challenge','verify','transfer') NOT NULL,
    /* reason is NULL for successful requests, and holds the short reject
       reason code (e.g. "too_early", "license_expired") for rejected ones -
       this makes it possible to audit exactly why any given attempt failed
       without needing to correlate with application logs. */
    reason VARCHAR(32) NULL,
    risk_score SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    KEY idx_activity_license_time (license_id, occurred_at),
    KEY idx_activity_key_time (device_public_key_hash, occurred_at),
    CONSTRAINT fk_activity_license
        FOREIGN KEY (license_id) REFERENCES nutricula_licenses(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

/* Statistics only - not read by any part of the licensing logic itself.
   Tracks distinct (machine_id, device_public_key_hash) pairs - i.e. distinct
   computers - that asked license_check.php to verify a license and got
   license_not_found (using the EA without ever having activated a license -
   the free/unlicensed usage case). first_seen_at is set once; last_seen_at
   is refreshed every time the same computer checks in again without a
   license. Once a computer actually gets a real license, it stops reaching
   the code path that touches this table (license_not_found no longer fires
   for it), so its last_seen_at simply stops advancing and it ages out of
   any "active in the last N days" query naturally - no cleanup needed. */
CREATE TABLE nutricula_unlicensed_checkins (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    /* Both nullable, but at least one is always present (enforced in PHP,
       not in schema) - a free install's machine_id can genuinely fail to
       generate on some systems, in which case device_public_key_hash alone
       is sufficient to recognize this computer across check-ins. Each gets
       its OWN unique key (not a combined one) so that either value alone
       can identify an existing row - MySQL does not enforce uniqueness
       among NULLs, so many rows can share machine_id=NULL (or
       device_public_key_hash=NULL) without conflict. */
    machine_id CHAR(64) NULL,
    device_public_key_hash CHAR(64) NULL,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    /* Admin panel (2026): the last_seen_at value as of the start of the
       CURRENT calendar day (UTC), i.e. "when were they last seen before
       today" - written by nutricula_track_unlicensed_checkin() in
       license_common.php (see its own comment for why it only rolls
       forward once per day). Lets the admin panel's "free user returning
       after 30+ days" card tell a genuine comeback apart from someone who
       simply checked in again a few minutes after their last request -
       last_seen_at alone can never make that distinction, since it's
       overwritten on every single check-in. NULL for a brand-new row (no
       "before" to speak of yet). */
    previous_last_seen_at DATETIME NULL,
    /* Admin panel (2026): same classification/values as nutricula_licenses.
       device_type and nutricula_minus2_log.platform_profile - refreshed on
       every free_checkin (see nutricula_track_unlicensed_checkin), so the
       admin dashboard can break "active free users" down by OS. NULL until
       the first free_checkin that actually included platform_profile (older
       Coordinator, or the local export genuinely unavailable). */
    platform_profile ENUM('windows','windows_vm','macos_wine','linux_wine') NULL,
    /* Admin panel (2026): same build-adoption tracking as
       nutricula_licenses.last_build_id, refreshed on every free_checkin -
       so the admin dashboard's build-adoption view covers free installs
       too, not just premium. */
    last_build_id VARCHAR(64) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_checkin_machine_id (machine_id),
    UNIQUE KEY uq_checkin_device_hash (device_public_key_hash),
    KEY idx_last_seen (last_seen_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

/* One row per successfully-used transfer key. The UNIQUE key on
   transfer_key_hash is what actually enforces "a transfer key can only be
   used once" at the database level (not just application logic) - the same
   defense-in-depth pattern used for purchase_key uniqueness in signup.
   Stores a SHA-256 hash of the transfer key, never the plaintext value -
   even though the key is already single-use by the time a row exists here
   (so this table alone can't be used to replay it), hashing costs nothing
   and means a database-level compromise never exposes any transfer key
   value directly, matching the same non-reversible-storage principle
   already used for device_public_key_hash elsewhere in this schema.
   Captures full source ("old_*") and destination ("new_*") computer
   identity plus timing, specifically so support can answer "when and from
   which computer to which computer was my license transferred" precisely
   if a customer ever disputes having used their transfer key. */
CREATE TABLE nutricula_transfer_keys_used (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    transfer_key_hash CHAR(64) NOT NULL,
    user_email VARCHAR(320) NOT NULL,
    license_id BIGINT UNSIGNED NOT NULL,
    old_license_uuid CHAR(36) NOT NULL,
    new_license_uuid CHAR(36) NOT NULL,
    old_machine_id CHAR(64) NOT NULL,
    old_device_public_key_hash CHAR(64) NOT NULL,
    old_last_observed_ip VARCHAR(45) NULL,
    new_machine_id CHAR(64) NOT NULL,
    new_device_public_key_hash CHAR(64) NOT NULL,
    new_observed_ip VARCHAR(45) NOT NULL,
    new_claimed_local_ip VARCHAR(45) NULL,
    transferred_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_transfer_key_hash (transfer_key_hash),
    KEY idx_transfer_license (license_id),
    KEY idx_transfer_email (user_email),
    CONSTRAINT fk_transfer_license
        FOREIGN KEY (license_id) REFERENCES nutricula_licenses(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

/* Server-side registry of Expected artifact hashes per build (architecture
   points 44/87/119) - the ONLY source of "what should this build's EX5/
   DLL32/DLL64/MachineId32/MachineId64/Broker hash to" that
   license_check.php ever consults. A
   client (Coordinator) can report whatever hashes it wants in a verify
   request, but those reported values are only USED to look up a match here
   - they can never themselves become the expected value (point 46/122).
   Rows are inserted manually (or via a small admin script) whenever a new
   build is signed with NutriculaSignTool - there is no endpoint that lets
   a client create or modify a row here. */
CREATE TABLE nutricula_build_manifests (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    build_id VARCHAR(64) NOT NULL,
    version VARCHAR(32) NOT NULL,
    protocol_version VARCHAR(16) NOT NULL,
    ex5_sha256 CHAR(64) NOT NULL,
    ex4_sha256 CHAR(64) NOT NULL,
    dll32_sha256 CHAR(64) NOT NULL,
    dll64_sha256 CHAR(64) NOT NULL,
    /* MachineId32.dll / MachineId64.dll - loaded by BOTH the thin License
       Check DLL and the Coordinator itself (MachineIdBridge). Unconditional
       and always-both-required, exactly like dll32_sha256/dll64_sha256
       above - never an either/or match like the broker columns below - since
       a 32-bit MT4 and a 64-bit MT5 could both be talking to the same
       Coordinator instance at once, each needing its own genuine MachineId
       DLL to be verifiable. */
    machineid32_sha256 CHAR(64) NOT NULL,
    machineid64_sha256 CHAR(64) NOT NULL,
    /* Both architectures of the Coordinator (the Broker) genuinely ship to
       customers - 32-bit Windows hosts are a real, supported case (e.g.
       Windows tablets). The Installer picks which one to actually install
       based on the CUSTOMER's OS bitness, so whichever one lands on a given
       machine must be independently verifiable against its own hash - a
       single shared broker_sha256 column could never do that once two
       genuinely different binaries are both in circulation. (The Windows
       Service host was removed in 2026 - the Broker is the sole Coordinator
       - so there are no service32/64 columns.) */
    broker32_sha256 CHAR(64) NOT NULL,
    broker64_sha256 CHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_build_id (build_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

/* DDoS-mitigation rate limiting - fixed 60-second window counter per
   (endpoint, client IP), used by nutricula_rate_limit_check() in
   license_common.php. See that function's own doc comment for the exact
   limit (30 req/min) and the important caveat that this is a secondary,
   application-level defense layer - a reverse proxy/CDN/WAF in front of
   PHP is still the primary line of defense against real volumetric DDoS. */
CREATE TABLE nutricula_rate_limits (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    rate_key VARCHAR(255) NOT NULL,   -- "<endpoint>|<client_ip>"
    window_start INT UNSIGNED NOT NULL,
    request_count INT UNSIGNED NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uq_rate_key_window (rate_key, window_start),
    KEY idx_window_start (window_start)   -- serves the periodic cleanup DELETE and the admin panel's time-range reads
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

/* Response-time instrumentation for the admin panel's "server health"
   report - one row per calendar MINUTE (not per request - a per-request
   log would grow unboundedly on a busy server), written by
   nutricula_record_request_timing() in license_common.php via a shutdown-
   function hook in license_check.php, so it costs the real request zero
   observable latency. avg response time for a given minute is
   total_duration_ms / request_count. Rows older than ~40 days are deleted
   opportunistically by the same function (see its own doc comment) - that
   comfortably covers the report's longest lookback (a month ago) while
   keeping this table small (well under 60,000 rows even at full traffic). */
CREATE TABLE nutricula_request_timing (
    window_start INT UNSIGNED NOT NULL,
    request_count INT UNSIGNED NOT NULL DEFAULT 0,
    total_duration_ms BIGINT UNSIGNED NOT NULL DEFAULT 0,
    min_duration_ms INT UNSIGNED NOT NULL DEFAULT 0,
    max_duration_ms INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (window_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

/* Full support-facing log of every "-2" (Check_Core_Integrity() returning
   -2 to MQL, i.e. TIER_FAILED) occurrence across every install in the
   world, free or licensed - one row per occurrence (not deduplicated),
   so support can look up a customer's complaint by machine_id/email/
   license and see exactly when and why their EA stopped working.

   COVERAGE NOTE (2026) - read before treating an empty result as "nothing
   happened": Check_Core_Integrity() can return -2 for five distinct
   reasons, and only ONE of them is something this server can ever learn
   about and log:
     1. The EA<->DLL handshake (inside MetaTrader's own process) is wrong
        or has lapsed - purely local, no network involved, UNLOGGABLE here.
     2. The DLL's signature re-verification of an otherwise-well-formed
        Coordinator reply fails - also purely local (the Coordinator has no
        way to know the DLL rejected what it sent) - UNLOGGABLE here.
     3. The DLL's named-pipe connection attempts to the Broker fail
        repeatedly (e.g. Broker not running at all) - the Broker never even
        receives a failed connection attempt it was never alive for -
        UNLOGGABLE here.
     4. The Coordinator's OWN published tier is TIER_FAILED because it
        exhausted its 10-attempt retry budget without ANY usable server
        response (real network outage, or the request never reaching this
        server for some other reason) - reported via
        nutricula_failure_report.php's 'transport_exhausted' reason_code
        (best-effort: if the network is genuinely down, this report may
        also fail to arrive - its absence in that specific case is itself
        consistent with "customer's internet/firewall was the problem").
     5. The Coordinator's OWN published tier is TIER_FAILED because local
        machine-ID generation failed - reported via
        nutricula_failure_report.php's 'machineid_generation_failed' reason.
   A sixth, server-DECIDED cause - confirmed artifact/hash tampering
   ('artifact_mismatch', detected during 'verify' or 'free_checkin') - is
   logged directly by license_check.php at the moment the server itself
   makes that call, with full context (it has everything already in hand).
   So: reasons 4/5/6 land here; reasons 1/2/3 structurally cannot,
   by construction, ever reach this server - there is no bug to fix, just a
   layer that has no network path at all. */
CREATE TABLE nutricula_minus2_log (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    occurred_at DATETIME NOT NULL,
    /* 'free' when no license_id was involved at all (matches the
       Coordinator's own free-tier/free_checkin definition), 'licensed'
       when a license_id was involved regardless of whether it was
       ultimately valid - this is "what KIND of install hit -2", not this
       event's outcome. */
    install_kind ENUM('free','licensed') NOT NULL,
    /* Fixed, short, machine-readable cause - one of: 'artifact_mismatch'
       (server-confirmed tamper/hash mismatch), 'transport_exhausted'
       (10 attempts, no usable server response), 'machineid_generation_failed'
       (local hardware-ID generation failed). See the table comment above
       for the full reasoning and for which causes can NEVER appear here. */
    reason_code VARCHAR(64) NOT NULL,
    /* Free-text elaboration for support - e.g. exactly which hash field(s)
       mismatched, or how many attempts were made and the last transport
       error. Never parsed or relied on for any decision anywhere. */
    reason_detail TEXT NULL,
    license_id BIGINT UNSIGNED NULL,
    user_email VARCHAR(320) NULL,
    machine_id CHAR(64) NULL,
    machine_id_alt CHAR(64) NULL,
    device_public_key_hash CHAR(64) NULL,
    build_id VARCHAR(64) NULL,
    observed_ip VARCHAR(45) NULL,
    /* Same classification as nutricula_licenses.device_type above (and the
       same client-reported "platform_profile" field used at signup) -
       NULL when the client didn't send one (e.g. a pre-2026 Coordinator,
       or the local MachineId DLL export genuinely wasn't available on that
       machine when this -2 occurred), never defaulted to 'unknown' here
       since "we don't know" and "the client explicitly reported no
       machine ID yet" are worth distinguishing in a support log. */
    platform_profile ENUM('windows','windows_vm','macos_wine','linux_wine') NULL,
    PRIMARY KEY (id),
    KEY idx_minus2_machine (machine_id),
    KEY idx_minus2_device_key (device_public_key_hash),
    KEY idx_minus2_license (license_id),
    KEY idx_minus2_email (user_email),
    KEY idx_minus2_occurred (occurred_at),
    CONSTRAINT fk_minus2_license
        FOREIGN KEY (license_id) REFERENCES nutricula_licenses(id)
        ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

/* ============================================================================
   Admin panel (2026)
   ============================================================================
   Everything below is read/written ONLY by the separate admin panel
   (admin_*.php, on its own subdomain) - license_check.php and the other
   public-facing endpoints only ever READ nutricula_banned_devices (to
   enforce a ban), never write it. Login itself uses no table at all - the
   single admin password hash lives in a private, outside-webroot PHP config
   file (same convention as license_config.php), not in the database, since
   there is exactly one admin and a DB row would just be one more thing an
   attacker who already reached the DB could read. */

/* One row per banned "identity" - either a premium license (scope='license',
   license_id set) or a free/unlicensed install (scope='free_device',
   machine_id and/or device_public_key_hash set, whichever the admin searched
   by). A premium ban does NOT touch nutricula_licenses.status/blocked_until
   (those stay reserved for the existing expiry/clone-block machinery) -
   license_check.php checks this table as an INDEPENDENT extra gate, so an
   admin ban and an automatic clone-block can never clobber each other's
   state. The server-side effect is identical either way (see license_check's
   nutricula_is_banned() call sites): a signed Reject with reason 'banned',
   which the Coordinator maps to the same TIER_BLOCKED outcome as a
   clone-detected block (see CoordinatorCore.cpp). */
CREATE TABLE nutricula_banned_devices (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    scope ENUM('license','free_device') NOT NULL,
    license_id BIGINT UNSIGNED NULL,
    machine_id CHAR(64) NULL,
    device_public_key_hash CHAR(64) NULL,
    /* Denormalized copy of nutricula_licenses.user_email at ban time, purely
       so the admin panel's "currently banned" list can show an email without
       an extra join after the license row might later change - never
       compared against for the ban decision itself (license_id is). */
    user_email VARCHAR(320) NULL,
    reason VARCHAR(255) NULL,
    banned_at DATETIME NOT NULL,
    banned_by VARCHAR(255) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_ban_license (license_id),
    UNIQUE KEY uq_ban_machine (machine_id),
    UNIQUE KEY uq_ban_device_hash (device_public_key_hash),
    KEY idx_ban_email (user_email),
    CONSTRAINT fk_ban_license
        FOREIGN KEY (license_id) REFERENCES nutricula_licenses(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

/* Append-only trail of every mutating action taken from the admin panel
   (ban, unban - and anything added later) - never read by any enforcement
   logic, purely so that if the panel's one password is ever compromised,
   there is a record of exactly what was done, when, and from where. Never
   pruned automatically (unlike nutricula_minus2_log) - this table only ever
   grows at the rate of actual admin clicks, which is tiny. */
CREATE TABLE nutricula_admin_audit_log (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    occurred_at DATETIME NOT NULL,
    action VARCHAR(64) NOT NULL,
    target_type VARCHAR(32) NOT NULL,
    target_detail VARCHAR(500) NOT NULL,
    admin_ip VARCHAR(45) NOT NULL,
    PRIMARY KEY (id),
    KEY idx_audit_occurred (occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

/* Registered fingerprint/Face ID (WebAuthn/passkey) credentials for the
   admin panel's own sign-in - added 2026, alongside the panel's passwordless
   sign-in option. Stores only the PUBLIC key (raw P-256 X/Y coordinates)
   and a replay counter, never anything that could reproduce the actual
   fingerprint/face, which never leaves the device's own secure hardware. */
CREATE TABLE nutricula_admin_passkeys (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    -- The authenticator-chosen opaque credential handle (not secret, but not
    -- meant to be public either) - looked up on every passwordless login.
    credential_id VARBINARY(255) NOT NULL,
    -- Raw P-256 public key coordinates (ES256 only - see
    -- AdminPanel/admin_webauthn_common.php for why this is ES256-only).
    pub_x BINARY(32) NOT NULL,
    pub_y BINARY(32) NOT NULL,
    -- Authenticator's own signature counter, for basic clone detection.
    -- Many platform authenticators (Face ID/Touch ID, most Android) always
    -- report 0 - handled as "no counter support" rather than an error.
    sign_count INT UNSIGNED NOT NULL DEFAULT 0,
    -- Human-friendly device name given at registration time, for your own
    -- list only - never sent to the browser.
    label VARCHAR(100) NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_passkey_credential_id (credential_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
