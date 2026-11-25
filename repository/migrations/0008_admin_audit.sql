-- Audit of manager and vendor decisions on the quarantine (review H2).
--
-- vendor_access_log: one row per request made on a vendor user's authority, written in the
-- transaction of the action (ADR-0013 V5). audit_log: the tenant-visible record of who released,
-- discarded or confirmed which held slot, why, and from which status to which.
-- Timestamps are RFC 3339 UTC text so one schema serves Postgres and SQLite.
CREATE TABLE IF NOT EXISTS vendor_access_log (
  tenant_id          TEXT    NOT NULL,
  id                 TEXT    NOT NULL,
  occurred_at        TEXT    NOT NULL,
  vendor_user        TEXT    NOT NULL,
  token_type         TEXT    NOT NULL,
  support_session_id TEXT,
  action_key         TEXT    NOT NULL,
  target_id          TEXT,
  ticket_reference   TEXT,
  outcome            TEXT    NOT NULL CHECK (outcome IN ('ok', 'refused')),
  result_count       INTEGER,
  request_id         TEXT    NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS audit_log (
  tenant_id     TEXT   NOT NULL,
  id            TEXT   NOT NULL,
  occurred_at   TEXT   NOT NULL,
  actor         TEXT   NOT NULL,
  actor_type    TEXT   NOT NULL,
  action        TEXT   NOT NULL,
  origin        TEXT   NOT NULL,
  stream        TEXT   NOT NULL,
  seq           BIGINT NOT NULL,
  reason        TEXT   NOT NULL,
  before_status TEXT   NOT NULL,
  after_status  TEXT   NOT NULL,
  request_id    TEXT   NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, id)
);
