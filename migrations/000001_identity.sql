-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Durable identity, session, and audit state. All token columns contain hashes,
-- never bearer token material.

CREATE TABLE users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    github_id BIGINT UNIQUE,
    github_login TEXT UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('developer', 'admin')),
    created_at TIMESTAMPTZ NOT NULL,
    disabled_at TIMESTAMPTZ
);

CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    refresh_family_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    user_agent TEXT NOT NULL,
    remote_address INET NOT NULL
);

CREATE INDEX sessions_user_active_idx ON sessions(user_id, expires_at) WHERE revoked_at IS NULL;
CREATE INDEX sessions_refresh_family_idx ON sessions(refresh_family_id);

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(id),
    family_id UUID NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    replaced_by_id UUID,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX refresh_tokens_family_idx ON refresh_tokens(family_id);

CREATE TABLE invitations (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('developer', 'admin')),
    token_hash BYTEA NOT NULL UNIQUE,
    invited_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE github_role_mappings (
    id UUID PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('user', 'organization', 'team')),
    target TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('developer', 'admin')),
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (kind, target)
);

CREATE TABLE service_metadata (
    key TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE audit_events (
    id UUID PRIMARY KEY,
    actor_user_id UUID REFERENCES users(id),
    subject_user_id UUID REFERENCES users(id),
    session_id UUID REFERENCES sessions(id),
    event_type TEXT NOT NULL,
    remote_address INET,
    created_at TIMESTAMPTZ NOT NULL,
    details JSONB NOT NULL
);

CREATE INDEX audit_events_subject_created_idx ON audit_events(subject_user_id, created_at DESC);
CREATE INDEX audit_events_created_idx ON audit_events(created_at DESC);
