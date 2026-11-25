-- Sync op store: one portable schema for Postgres (gateway) and SQLite (hub, simulator devices).
-- Forward-only. Every tenant-owned table carries tenant_id as the first key column (ADR-0003).

CREATE TABLE IF NOT EXISTS ops (
  tenant_id TEXT   NOT NULL,
  stream    TEXT   NOT NULL,
  origin    TEXT   NOT NULL,
  seq       BIGINT NOT NULL,
  h         TEXT   NOT NULL,
  ph        TEXT   NOT NULL,
  body      TEXT   NOT NULL,           -- exact bytes the origin hashed; '' for a placeholder
  status    TEXT   NOT NULL,           -- accepted | flagged | quarantined | voided | placeholder | held_local
  reason    TEXT   NOT NULL DEFAULT '',-- quarantine / void reason code (cloud only, never sent to devices)
  marks     TEXT   NOT NULL DEFAULT '',-- comma list: foreign_series, unsealed, recovered_sealed, ...
  intent    TEXT   NOT NULL DEFAULT '',
  hlc       TEXT   NOT NULL DEFAULT '',
  arr       BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, stream, origin, seq)
);
CREATE INDEX IF NOT EXISTS ops_arrival ON ops (tenant_id, arr);
CREATE INDEX IF NOT EXISTS ops_status ON ops (tenant_id, status);

-- Personal data lives outside the op log so erasure never touches the chain (S4).
CREATE TABLE IF NOT EXISTS op_pii (
  tenant_id TEXT   NOT NULL,
  stream    TEXT   NOT NULL,
  origin    TEXT   NOT NULL,
  seq       BIGINT NOT NULL,
  data      TEXT   NOT NULL,
  PRIMARY KEY (tenant_id, stream, origin, seq)
);

CREATE TABLE IF NOT EXISTS seals (
  tenant_id TEXT   NOT NULL,
  stream    TEXT   NOT NULL,
  origin    TEXT   NOT NULL,
  seq       BIGINT NOT NULL,
  h         TEXT   NOT NULL,
  kid       TEXT   NOT NULL,
  sig       TEXT   NOT NULL,
  PRIMARY KEY (tenant_id, stream, origin, seq)
);

CREATE TABLE IF NOT EXISTS counters (
  tenant_id TEXT   NOT NULL,
  name      TEXT   NOT NULL,
  v         BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS meta (
  tenant_id TEXT NOT NULL,
  k         TEXT NOT NULL,
  v         TEXT NOT NULL,
  PRIMARY KEY (tenant_id, k)
);

CREATE TABLE IF NOT EXISTS sessions (
  tenant_id TEXT NOT NULL,
  origin    TEXT NOT NULL,
  sid       TEXT NOT NULL,
  stype     TEXT NOT NULL,
  PRIMARY KEY (tenant_id, origin, sid)
);

-- Device-side legal number counters, one per series code and financial year (S7).
CREATE TABLE IF NOT EXISTS numbers (
  tenant_id TEXT   NOT NULL,
  code      TEXT   NOT NULL,
  fy        TEXT   NOT NULL,
  n         BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, code, fy)
);

-- Cloud series register: every number seen, whatever its verdict (S7, A1.1).
CREATE TABLE IF NOT EXISTS series_register (
  tenant_id TEXT   NOT NULL,
  code      TEXT   NOT NULL,
  fy        TEXT   NOT NULL,
  num       BIGINT NOT NULL,
  number    TEXT   NOT NULL,
  doc_type  TEXT   NOT NULL,
  origin    TEXT   NOT NULL,
  stream    TEXT   NOT NULL,
  seq       BIGINT NOT NULL,
  state     TEXT   NOT NULL,           -- accepted | flagged | quarantined
  mark      TEXT   NOT NULL DEFAULT '',-- foreign_series | unknown_series | recovered_unsealed | recovered_sealed
  PRIMARY KEY (tenant_id, origin, stream, seq)
);
CREATE INDEX IF NOT EXISTS register_series ON series_register (tenant_id, code, fy, num);

-- Differing content for a slot the cloud already holds (fork evidence, A1.3 items 4 and 9).
CREATE TABLE IF NOT EXISTS forks (
  tenant_id TEXT   NOT NULL,
  stream    TEXT   NOT NULL,
  origin    TEXT   NOT NULL,
  seq       BIGINT NOT NULL,
  h         TEXT   NOT NULL,
  body      TEXT   NOT NULL,
  source    TEXT   NOT NULL,
  PRIMARY KEY (tenant_id, stream, origin, seq, h)
);

-- One row per key-loss recovery, mirrored from identity on first use (A1.3 item 3).
CREATE TABLE IF NOT EXISTS recoveries (
  tenant_id    TEXT   NOT NULL,
  rec_id       TEXT   NOT NULL,
  old_device   TEXT   NOT NULL,
  new_device   TEXT   NOT NULL,
  attested     TEXT   NOT NULL DEFAULT '', -- JSON list of attestations, fixed once
  drained      BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, rec_id)
);

CREATE TABLE IF NOT EXISTS alerts (
  tenant_id TEXT   NOT NULL,
  id        BIGINT NOT NULL,
  audience  TEXT   NOT NULL,           -- owner | vendor
  severity  TEXT   NOT NULL,
  kind      TEXT   NOT NULL,
  detail    TEXT   NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
