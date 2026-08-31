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
    machine_id CHAR(64) NOT NULL,
    device_public_key_hash CHAR(64) NOT NULL,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_machine_device (machine_id, device_public_key_hash),
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
   DLL32/DLL64/Service hash to" that license_check.php ever consults. A
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
    /* Both architectures of the Coordinator (Service/Broker) genuinely ship
       to customers - 32-bit Windows hosts are a real, supported case (e.g.
       Windows tablets). The Installer picks which one to actually install
       based on the CUSTOMER's OS bitness, so whichever one lands on a given
       machine must be independently verifiable against its own hash - a
       single shared service_sha256/broker_sha256 column could never do
       that once two genuinely different binaries are both in circulation. */
    service32_sha256 CHAR(64) NOT NULL,
    service64_sha256 CHAR(64) NOT NULL,
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
    UNIQUE KEY uq_rate_key_window (rate_key, window_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
