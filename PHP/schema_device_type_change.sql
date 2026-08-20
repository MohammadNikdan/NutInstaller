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

/* ============================================================================
   MIGRATION for an EXISTING database (run this instead of the CREATE TABLE
   statements above if nutricula_licenses / nutricula_transfer_keys_used
   already exist in production).
   ============================================================================ */

-- 1) device_type ENUM expansion (Mac/Linux/VM platform classification).
ALTER TABLE nutricula_licenses
    MODIFY COLUMN device_type ENUM('windows','windows_vm','macos_wine','linux_wine','unknown')
    NOT NULL DEFAULT 'unknown';

-- 2) transfer_key -> transfer_key_hash (store a SHA-256 hash, never plaintext).
--    Run in this exact order: add the new column, backfill it from the old
--    plaintext column, THEN drop the old unique key and column. Any row that
--    exists at this point represents an already-consumed transfer key, so
--    backfilling from plaintext one final time before removing it is safe.
ALTER TABLE nutricula_transfer_keys_used
    ADD COLUMN transfer_key_hash CHAR(64) NULL AFTER id;

UPDATE nutricula_transfer_keys_used
    SET transfer_key_hash = SHA2(transfer_key, 256)
    WHERE transfer_key_hash IS NULL;

ALTER TABLE nutricula_transfer_keys_used
    MODIFY COLUMN transfer_key_hash CHAR(64) NOT NULL,
    DROP INDEX uq_transfer_key,
    ADD UNIQUE KEY uq_transfer_key_hash (transfer_key_hash),
    DROP COLUMN transfer_key;
