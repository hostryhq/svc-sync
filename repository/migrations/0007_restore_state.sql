-- go-common restore.StateSchema: the epoch this database last handled (ADR-0002 A2.4). Rolled back
-- with the database, which is how a restore is noticed. Replaces gateway_state.epoch; platform_meta
-- and gateway_state are no longer read (contract step later).
CREATE TABLE IF NOT EXISTS restore_state (
  id         integer     PRIMARY KEY CHECK (id = 1),
  epoch_id   text        NOT NULL,
  handled_at timestamptz NOT NULL
);
