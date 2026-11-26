-- ADR-0014 A3.3: the gateway keeps, per (tenant, origin, approval id), the record of the approval.grant or
-- approval.self_confirm op beside identity's verdict on its proof, and which op cites it (one op may).
ALTER TABLE approval_verdicts ADD COLUMN kind        TEXT NOT NULL DEFAULT '';
ALTER TABLE approval_verdicts ADD COLUMN sid         TEXT NOT NULL DEFAULT '';
ALTER TABLE approval_verdicts ADD COLUMN intent      TEXT NOT NULL DEFAULT '';
ALTER TABLE approval_verdicts ADD COLUMN permission  TEXT NOT NULL DEFAULT '';
ALTER TABLE approval_verdicts ADD COLUMN target      TEXT NOT NULL DEFAULT '';
ALTER TABLE approval_verdicts ADD COLUMN action_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE approval_verdicts ADD COLUMN requester   TEXT NOT NULL DEFAULT '';
ALTER TABLE approval_verdicts ADD COLUMN approver    TEXT NOT NULL DEFAULT '';
ALTER TABLE approval_verdicts ADD COLUMN reason      TEXT NOT NULL DEFAULT '';
ALTER TABLE approval_verdicts ADD COLUMN approved_at TEXT NOT NULL DEFAULT '';
ALTER TABLE approval_verdicts ADD COLUMN citer       TEXT NOT NULL DEFAULT '';
ALTER TABLE approval_verdicts ADD COLUMN citer_hlc   TEXT NOT NULL DEFAULT '';
