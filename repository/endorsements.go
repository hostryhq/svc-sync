package repository

import (
	"database/sql"
	"errors"
)

// Seal re-signing, endorsements, attestations and alert resolution (ADR-0002 A2.1, A2.2).

func (t *sqlTx) ReplaceSeal(stream, origin string, seq int64, h, kid, sig string) error {
	return t.exec(`INSERT INTO seals (tenant_id, stream, origin, seq, h, kid, sig) VALUES (?,?,?,?,?,?,?)
		ON CONFLICT (tenant_id, stream, origin, seq) DO UPDATE SET h = excluded.h, kid = excluded.kid, sig = excluded.sig`,
		t.tenant, stream, origin, seq, h, kid, sig)
}

func (t *sqlTx) SealsOfOrigins(prefix string) ([]SealRec, error) {
	rows, err := t.query(`SELECT stream, origin, seq, h, kid, sig FROM seals WHERE tenant_id=? AND origin LIKE ? ORDER BY stream, origin, seq`, t.tenant, prefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SealRec
	for rows.Next() {
		var r SealRec
		if err := rows.Scan(&r.Stream, &r.Origin, &r.Seq, &r.H, &r.Kid, &r.Sig); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (t *sqlTx) PutEndorsement(e EndorsementRec) error {
	return t.exec(`INSERT INTO endorsements (tenant_id, stream, origin, seq, h, rec, kid, sig) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`,
		t.tenant, e.Stream, e.Origin, e.Seq, e.H, e.Rec, e.Kid, e.Sig)
}

func (t *sqlTx) ReplaceEndorsement(e EndorsementRec) error {
	return t.exec(`INSERT INTO endorsements (tenant_id, stream, origin, seq, h, rec, kid, sig) VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT (tenant_id, stream, origin, seq) DO UPDATE SET h = excluded.h, rec = excluded.rec, kid = excluded.kid, sig = excluded.sig`,
		t.tenant, e.Stream, e.Origin, e.Seq, e.H, e.Rec, e.Kid, e.Sig)
}

func (t *sqlTx) GetEndorsement(stream, origin string, seq int64) (EndorsementRec, bool, error) {
	e := EndorsementRec{Stream: stream, Origin: origin, Seq: seq}
	err := t.tx.QueryRowContext(t.ctx, t.s.rebind(`SELECT h, rec, kid, sig FROM endorsements WHERE tenant_id=? AND stream=? AND origin=? AND seq=?`),
		t.tenant, stream, origin, seq).Scan(&e.H, &e.Rec, &e.Kid, &e.Sig)
	if errors.Is(err, sql.ErrNoRows) {
		return EndorsementRec{}, false, nil
	}
	return e, err == nil, err
}

func (t *sqlTx) EndorsementSeqs(stream, origin string, after int64) ([]int64, error) {
	rows, err := t.query(`SELECT seq FROM endorsements WHERE tenant_id=? AND stream=? AND origin=? AND seq>? ORDER BY seq`, t.tenant, stream, origin, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var s int64
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (t *sqlTx) Endorsements() ([]EndorsementRec, error) {
	rows, err := t.query(`SELECT stream, origin, seq, h, rec, kid, sig FROM endorsements WHERE tenant_id=? ORDER BY stream, origin, seq`, t.tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EndorsementRec
	for rows.Next() {
		var e EndorsementRec
		if err := rows.Scan(&e.Stream, &e.Origin, &e.Seq, &e.H, &e.Rec, &e.Kid, &e.Sig); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (t *sqlTx) PutAttestation(a AttestationRec) error {
	return t.exec(`INSERT INTO attestations (tenant_id, stream, origin, rec, seq, h, by_device, kid, sig) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`,
		t.tenant, a.Stream, a.Origin, a.Rec, a.Seq, a.H, a.By, a.Kid, a.Sig)
}

func (t *sqlTx) Attestations(stream, origin string) ([]AttestationRec, error) {
	rows, err := t.query(`SELECT rec, seq, h, by_device, kid, sig FROM attestations WHERE tenant_id=? AND stream=? AND origin=? ORDER BY rec`, t.tenant, stream, origin)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AttestationRec
	for rows.Next() {
		a := AttestationRec{Stream: stream, Origin: origin}
		if err := rows.Scan(&a.Rec, &a.Seq, &a.H, &a.By, &a.Kid, &a.Sig); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (t *sqlTx) DeleteMeta(k string) error {
	return t.exec(`DELETE FROM meta WHERE tenant_id=? AND k=?`, t.tenant, k)
}

func (t *sqlTx) ResolveAlerts(kind, detail string) error {
	if t.s.crypt == nil {
		return t.exec(`DELETE FROM alerts WHERE tenant_id=? AND kind=? AND detail=?`, t.tenant, kind, detail)
	}
	// A sealed detail cannot be matched in SQL: read the alerts of the kind, open them, delete the ones that match.
	all, err := t.Alerts()
	if err != nil {
		return err
	}
	for _, a := range all {
		if a.Kind == kind && a.Detail == detail {
			if err := t.exec(`DELETE FROM alerts WHERE tenant_id=? AND id=?`, t.tenant, a.ID); err != nil {
				return err
			}
		}
	}
	return nil
}
