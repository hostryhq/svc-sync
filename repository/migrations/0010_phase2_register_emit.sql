-- Phase 2 (expand step, forward-only). series_numbers replaces series_register: one op may carry more than one legal
-- number (bill.rebill: a credit note and a new bill), so the key now includes the number. The old table stays for one
-- release and is no longer written. emit_dedup is the idempotency record of POST /internal/v1/emit (ADR-0014 A2.2 item 4):
-- written in the transaction that stores the op and kept as long as the op.
CREATE TABLE IF NOT EXISTS series_numbers (
  tenant_id TEXT   NOT NULL,
  code      TEXT   NOT NULL,
  fy        TEXT   NOT NULL,
  num       BIGINT NOT NULL,
  number    TEXT   NOT NULL,
  doc_type  TEXT   NOT NULL,
  origin    TEXT   NOT NULL,
  stream    TEXT   NOT NULL,
  seq       BIGINT NOT NULL,
  state     TEXT   NOT NULL,
  mark      TEXT   NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, origin, stream, seq, number)
);
CREATE INDEX IF NOT EXISTS series_numbers_series ON series_numbers (tenant_id, code, fy, num);
INSERT INTO series_numbers (tenant_id, code, fy, num, number, doc_type, origin, stream, seq, state, mark)
  SELECT tenant_id, code, fy, num, number, doc_type, origin, stream, seq, state, mark FROM series_register WHERE true
  ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS emit_dedup (
  tenant_id TEXT   NOT NULL,
  caller    TEXT   NOT NULL,
  key       TEXT   NOT NULL,
  content   TEXT   NOT NULL,
  origin    TEXT   NOT NULL,
  stream    TEXT   NOT NULL,
  seq       BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, caller, key)
);
