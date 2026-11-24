-- Postgres only: the transactional outbox of ADR-0011 B4, copied from go-common outbox.Schema
-- (services copy it into their own migrations). Accepted ops are inserted here in the same
-- transaction that stores them.
CREATE TABLE IF NOT EXISTS outbox (
  id           uuid        PRIMARY KEY,
  seq          bigint      GENERATED ALWAYS AS IDENTITY,
  type         text        NOT NULL,
  subject      text        NOT NULL,
  tenant_id    text        NOT NULL,
  key          text        NOT NULL DEFAULT '',
  key_seq      bigint      NOT NULL DEFAULT 0,
  payload      bytea       NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz
);
CREATE INDEX IF NOT EXISTS outbox_unpublished ON outbox (seq) WHERE published_at IS NULL;
CREATE INDEX IF NOT EXISTS outbox_published_at ON outbox (published_at) WHERE published_at IS NOT NULL;
