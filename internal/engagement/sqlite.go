package engagement

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
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
  raw_output_path TEXT,
  created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_module ON findings(module);
CREATE INDEX IF NOT EXISTS idx_findings_account ON findings(account_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id TEXT,
  module TEXT,
  level TEXT NOT NULL,
  msg TEXT NOT NULL,
  created_at DATETIME NOT NULL
);
`

// DBFileName is the name of the SQLite file inside an engagement directory.
const DBFileName = "engagement.db"

// Engagement is a per-run container: a directory on disk holding the SQLite
// findings DB plus per-module/per-account subdirectories for raw tool output.
type Engagement struct {
	db *sql.DB
	mu sync.Mutex
	// Dir is the engagement root directory. engagement.db lives at
	// filepath.Join(Dir, DBFileName); raw tool output lives at
	// filepath.Join(Dir, <module>, <accountID>).
	Dir string
}

// Open opens an engagement at the given directory. The directory is created
// if missing, and the SQLite schema is initialized.
func Open(dir string) (*Engagement, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dir, DBFileName)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &Engagement{db: db, Dir: dir}, nil
}

func (e *Engagement) Close() error { return e.db.Close() }

func (e *Engagement) DB() *sql.DB { return e.db }

// DBPath returns the absolute path to the SQLite file.
func (e *Engagement) DBPath() string { return filepath.Join(e.Dir, DBFileName) }

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
		`INSERT INTO findings(account_id, region, module, severity, resource_arn, title, detail_json, raw_output_path, created_at)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		f.AccountID, f.Region, f.Module, string(f.Severity), f.ResourceARN, f.Title, detail, nullIfEmpty(f.RawOutputPath), created)
	return err
}

// RawDir returns (and creates) the directory for a module's raw output for a
// given account inside the engagement dir. Path is absolute.
func (e *Engagement) RawDir(module, accountID string) (string, error) {
	if module == "" {
		return "", fmt.Errorf("module required")
	}
	parts := []string{e.Dir, module}
	if accountID != "" {
		parts = append(parts, accountID)
	}
	dir := filepath.Join(parts...)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func (e *Engagement) LogEvent(ctx context.Context, module, accountID, level, msg string) error {
	_, err := e.db.ExecContext(ctx,
		`INSERT INTO logs(account_id, module, level, msg, created_at) VALUES(?,?,?,?,?)`,
		nullIfEmpty(accountID), nullIfEmpty(module), level, msg, time.Now().UTC())
	return err
}
