-- Gateway endorsements of released unsealed-tail ops and the adopting device's attestations
-- (ADR-0002 A2.1). Every node stores what it verified, and serves it with the ops.
CREATE TABLE IF NOT EXISTS endorsements (
  tenant_id TEXT   NOT NULL,
  stream    TEXT   NOT NULL,
  origin    TEXT   NOT NULL,
  seq       BIGINT NOT NULL,
  h         TEXT   NOT NULL,
  rec       TEXT   NOT NULL,
  kid       TEXT   NOT NULL,
  sig       TEXT   NOT NULL,
  PRIMARY KEY (tenant_id, stream, origin, seq)
);

CREATE TABLE IF NOT EXISTS attestations (
  tenant_id TEXT   NOT NULL,
  stream    TEXT   NOT NULL,
  origin    TEXT   NOT NULL,
  rec       TEXT   NOT NULL,
  seq       BIGINT NOT NULL,
  h         TEXT   NOT NULL,
  by_device TEXT   NOT NULL,
  kid       TEXT   NOT NULL,
  sig       TEXT   NOT NULL,
  PRIMARY KEY (tenant_id, stream, origin, rec)
);
