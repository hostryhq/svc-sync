-- Platform-level rows (not tenant-owned). platform_meta is written by hostry-restore before any
-- service starts (ADR-0006 H6); gateway_state is the gateway's own record of the epoch it last
-- served under, and is rolled back with the database, which is how a restore is noticed (S16).
CREATE TABLE IF NOT EXISTS platform_meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gateway_state (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
