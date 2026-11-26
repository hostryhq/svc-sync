-- ADR-0005 A3 (expand step, forward-only). A3.1: the session row carries the verdict identity gave the session's
-- proof, once, per (tenant, origin, sid); later ops of the session are judged from it. An approval's verdict is kept
-- per approval id the same way. A3.3: the device-signed drain statements the gateway holds (one satisfied statement
-- per origin; any other is kept as fork evidence).
ALTER TABLE sessions ADD COLUMN actor     TEXT   NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN pack_v    BIGINT NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN pin_v     BIGINT NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN opened_at TEXT   NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN verdict   TEXT   NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS approval_verdicts (
  tenant_id   TEXT NOT NULL,
  origin      TEXT NOT NULL,
  approval_id TEXT NOT NULL,
  verdict     TEXT NOT NULL,
  PRIMARY KEY (tenant_id, origin, approval_id)
);

CREATE TABLE IF NOT EXISTS drain_statements (
  tenant_id TEXT NOT NULL,
  origin    TEXT NOT NULL,
  hash      TEXT NOT NULL,
  statement TEXT NOT NULL,
  state     TEXT NOT NULL,
  detail    TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, origin, hash)
);
