// Package devepoch gives the development binaries, the test double and the simulator a restore
// epoch of their own (ADR-0002 A2.4 item 7): a platform_meta database that restoretest stamps with
// the migrator role. Production reads the real platform_meta through restore.NewReader.
package devepoch

import (
	"context"
	"database/sql"
	"strings"
	"sync"

	"github.com/hostryhq/go-common/restore"
	"github.com/hostryhq/go-common/restore/restoretest"
	_ "github.com/jackc/pgx/v5/stdlib" // driver "pgx"
	_ "modernc.org/sqlite"             // driver "sqlite"
)

// keepers hold one connection to each in-memory SQLite platform database: a shared in-memory
// database lives only while a connection is open, and a Reader closes its own after each read.
var (
	keepMu  sync.Mutex
	keepers = map[string]*sql.DB{}
)

func open(dsn string) (*sql.DB, string, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		db, err := sql.Open("pgx", dsn)
		return db, "postgres", err
	}
	db, err := sql.Open("sqlite", dsn)
	if err == nil {
		db.SetMaxOpenConns(1)
		if strings.Contains(dsn, "mode=memory") {
			keepMu.Lock()
			if keepers[dsn] == nil {
				if k, kerr := sql.Open("sqlite", dsn); kerr == nil {
					k.SetMaxOpenConns(1)
					_ = k.Ping()
					keepers[dsn] = k
				}
			}
			keepMu.Unlock()
		}
	}
	return db, "sqlite", err
}

// Stamp makes epochID the newest epoch of the platform database at dsn (what hostry-restore does).
func Stamp(ctx context.Context, dsn, epochID string) error {
	db, dialect, err := open(dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	return restoretest.Stamp(ctx, db, dialect, restore.Epoch{EpochID: epochID, Class: "test"})
}

// Reader returns a new epoch reader of the platform database at dsn (a reader remembers its first
// answer, so a restarted service needs a new one). Genesis is stamped if the database was never
// stamped, as first provisioning does (ADR-0006 H6).
func Reader(ctx context.Context, dsn string) (*restore.Reader, error) {
	newReader := func() *restore.Reader {
		return restore.NewReaderFunc(func(context.Context) (*sql.DB, error) { db, _, err := open(dsn); return db, err })
	}
	if _, err := newReader().Current(ctx); err != nil {
		// Not stamped (or no restore_epoch table yet): first provisioning.
		if err := Stamp(ctx, dsn, restore.Genesis); err != nil {
			return nil, err
		}
	}
	return newReader(), nil
}
