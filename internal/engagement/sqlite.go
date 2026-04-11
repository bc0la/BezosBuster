package engagement

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/you/bezosbuster/internal/findings"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
  account_id TEXT PRIMARY KEY,
  alias TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  error TEXT,
  started_at DATETIME,
  finished_at DATETIME
);
CREATE TABLE IF NOT EXISTS module_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id TEXT NOT NULL,
  module TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  error TEXT,
  started_at DATETIME,
  finished_at DATETIME,
  UNIQUE(account_id, module)
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL DEFAULT '',
  module TEXT NOT NULL,
  severity TEXT NOT NULL,
  resource_arn TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}',
  raw_output_ref TEXT,
  created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_module ON findings(module);
CREATE INDEX IF NOT EXISTS idx_findings_account ON findings(account_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE TABLE IF NOT EXISTS raw_output (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id TEXT NOT NULL,
  module TEXT NOT NULL,
  name TEXT NOT NULL,
  payload BLOB NOT NULL,
  created_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id TEXT,
  module TEXT,
  level TEXT NOT NULL,
  msg TEXT NOT NULL,
  created_at DATETIME NOT NULL
);
`

type Engagement struct {
	db *sql.DB
	mu sync.Mutex
	// Path to the SQLite file.
	Path string
}

func Open(path string) (*Engagement, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // serialize writes; modernc/sqlite is safe but simpler this way
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &Engagement{db: db, Path: path}, nil
}

func (e *Engagement) Close() error { return e.db.Close() }

func (e *Engagement) DB() *sql.DB { return e.db }

func (e *Engagement) SetMeta(ctx context.Context, key, value string) error {
	_, err := e.db.ExecContext(ctx,
		`INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value)
	return err
}

func (e *Engagement) GetMeta(ctx context.Context, key string) (string, bool, error) {
	row := e.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key)
	var v string
	if err := row.Scan(&v); err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, err
	}
	return v, true, nil
}

// CompletedModules returns the set of (account_id, module) pairs that have
// already finished successfully, keyed as "account|module".
func (e *Engagement) CompletedModules(ctx context.Context) (map[string]bool, error) {
	rows, err := e.db.QueryContext(ctx,
		`SELECT account_id, module FROM module_runs WHERE status = 'completed'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var acc, mod string
		if err := rows.Scan(&acc, &mod); err != nil {
			return nil, err
		}
		out[acc+"|"+mod] = true
	}
	return out, rows.Err()
}

func (e *Engagement) UpsertAccount(ctx context.Context, accountID, alias string) error {
	_, err := e.db.ExecContext(ctx,
		`INSERT INTO accounts(account_id, alias) VALUES(?,?)
		 ON CONFLICT(account_id) DO UPDATE SET alias=excluded.alias`,
		accountID, alias)
	return err
}

func (e *Engagement) MarkAccount(ctx context.Context, accountID, status, errMsg string) error {
	_, err := e.db.ExecContext(ctx,
		`UPDATE accounts SET status=?, error=?, finished_at=CASE WHEN ?='running' THEN NULL ELSE CURRENT_TIMESTAMP END,
		 started_at=COALESCE(started_at, CASE WHEN ?='running' THEN CURRENT_TIMESTAMP END)
		 WHERE account_id=?`,
		status, nullIfEmpty(errMsg), status, status, accountID)
	return err
}

func (e *Engagement) MarkModule(ctx context.Context, accountID, module, status, errMsg string) error {
	_, err := e.db.ExecContext(ctx,
		`INSERT INTO module_runs(account_id, module, status, error, started_at, finished_at)
		 VALUES(?, ?, ?, ?, CASE WHEN ?='running' THEN CURRENT_TIMESTAMP END,
		        CASE WHEN ? IN ('completed','failed','skipped') THEN CURRENT_TIMESTAMP END)
		 ON CONFLICT(account_id, module) DO UPDATE SET status=excluded.status, error=excluded.error,
		   finished_at=CASE WHEN excluded.status IN ('completed','failed','skipped') THEN CURRENT_TIMESTAMP ELSE module_runs.finished_at END`,
		accountID, module, status, nullIfEmpty(errMsg), status, status)
	return err
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Sink implementation

func (e *Engagement) Write(ctx context.Context, f findings.Finding) error {
	detail, err := f.DetailJSON()
	if err != nil {
		return err
	}
	created := f.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, err = e.db.ExecContext(ctx,
		`INSERT INTO findings(account_id, region, module, severity, resource_arn, title, detail_json, raw_output_ref, created_at)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		f.AccountID, f.Region, f.Module, string(f.Severity), f.ResourceARN, f.Title, detail, nullIfEmpty(f.RawOutputRef), created)
	return err
}

func (e *Engagement) WriteRaw(ctx context.Context, module, accountID, name string, payload []byte) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	res, err := e.db.ExecContext(ctx,
		`INSERT INTO raw_output(account_id, module, name, payload, created_at) VALUES(?,?,?,?,?)`,
		accountID, module, name, payload, time.Now().UTC())
	if err != nil {
		return "", err
	}
	id, _ := res.LastInsertId()
	return fmt.Sprintf("raw:%d", id), nil
}

func (e *Engagement) LogEvent(ctx context.Context, module, accountID, level, msg string) error {
	_, err := e.db.ExecContext(ctx,
		`INSERT INTO logs(account_id, module, level, msg, created_at) VALUES(?,?,?,?,?)`,
		nullIfEmpty(accountID), nullIfEmpty(module), level, msg, time.Now().UTC())
	return err
}
