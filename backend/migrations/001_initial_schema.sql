-- Migration 001: Initial Production Schema for Incognito
-- Strict Privacy Invariant: Reports table MUST NOT contain student ID, name, email, IP, or member foreign keys.

CREATE TABLE IF NOT EXISTS members (
    id VARCHAR(64) PRIMARY KEY,
    member_ref VARCHAR(128) UNIQUE NOT NULL,
    status VARCHAR(32) NOT NULL CHECK(status IN ('pending', 'active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT
);

CREATE TABLE IF NOT EXISTS credentials (
    id VARCHAR(64) PRIMARY KEY,
    member_id VARCHAR(64) NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    commitment VARCHAR(128) UNIQUE NOT NULL,
    status VARCHAR(32) NOT NULL CHECK(status IN ('pending', 'registered', 'revoked', 'expired')),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS categories (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128) UNIQUE NOT NULL,
    description TEXT NOT NULL,
    risk_tier VARCHAR(32) NOT NULL CHECK(risk_tier IN ('standard', 'elevated', 'urgent'))
);

CREATE TABLE IF NOT EXISTS reports (
    id VARCHAR(64) PRIMARY KEY,
    reference VARCHAR(64) UNIQUE NOT NULL,
    status_secret_hash VARCHAR(128) NOT NULL,
    category_id VARCHAR(64) NOT NULL REFERENCES categories(id),
    encrypted_body TEXT NOT NULL,
    priority VARCHAR(32) NOT NULL CHECK(priority IN ('low', 'medium', 'high', 'critical')),
    status VARCHAR(32) NOT NULL CHECK(status IN ('received', 'under_review', 'moderation_review', 'assigned', 'action_taken', 'closed')),
    moderation_result JSONB NOT NULL,
    nullifier_hash VARCHAR(128) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    assigned_moderator VARCHAR(128),
    audit_committed INT DEFAULT 0,
    audit_batch_id VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS moderation_actions (
    id VARCHAR(64) PRIMARY KEY,
    report_id VARCHAR(64) NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    action VARCHAR(64) NOT NULL,
    previous_status VARCHAR(32) NOT NULL,
    new_status VARCHAR(32) NOT NULL,
    reason TEXT NOT NULL,
    moderator_id VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_batches (
    id VARCHAR(64) PRIMARY KEY,
    sequence BIGINT UNIQUE NOT NULL,
    merkle_root VARCHAR(128) NOT NULL,
    report_count INT NOT NULL,
    status VARCHAR(32) NOT NULL,
    contract_address VARCHAR(64) NOT NULL,
    network VARCHAR(64) NOT NULL,
    tx_hash VARCHAR(128),
    block_number BIGINT,
    created_at TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_records (
    id VARCHAR(64) PRIMARY KEY,
    batch_id VARCHAR(64) NOT NULL REFERENCES audit_batches(id) ON DELETE CASCADE,
    report_reference VARCHAR(64) NOT NULL,
    commitment_hash VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

-- Performance and Integrity Indexes
CREATE INDEX IF NOT EXISTS idx_members_ref ON members(member_ref);
CREATE INDEX IF NOT EXISTS idx_credentials_member_id ON credentials(member_id);
CREATE INDEX IF NOT EXISTS idx_reports_ref ON reports(reference);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_nullifier ON reports(nullifier_hash);
CREATE INDEX IF NOT EXISTS idx_audit_batches_seq ON audit_batches(sequence);
