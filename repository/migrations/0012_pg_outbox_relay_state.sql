-- Postgres only: the bus generation the outbox relay last republished for (ADR-0011 B9 item 2), copied from
-- go-common outbox.RelayStateSchema. The relay's generation check reads and writes it at every connect.
CREATE TABLE IF NOT EXISTS outbox_relay_state (
  stream     text        PRIMARY KEY,
  generation text        NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
