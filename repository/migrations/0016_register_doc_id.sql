-- Phase 2 review fix CR-H5 (expand step). The register keeps the id of the bill or credit note row behind each legal number, so the same
-- number under a different document id is found and refused as duplicate_document. Rows written before this stay with an empty id.
ALTER TABLE series_numbers ADD COLUMN doc_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS series_numbers_number ON series_numbers (tenant_id, number);
