package findings

import (
	"context"
	"encoding/json"
	"time"
)

type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

type Finding struct {
	ID          int64
	AccountID   string
	Region      string
	Module      string
	Severity    Severity
	ResourceARN string
	Title       string
	Detail      any
	// RawOutputPath is a filesystem path (relative to the engagement dir)
	// pointing to raw tool output for this finding, if any. Empty for
	// native-check findings.
	RawOutputPath string
	CreatedAt     time.Time
}

func (f *Finding) DetailJSON() (string, error) {
	if f.Detail == nil {
		return "{}", nil
	}
	b, err := json.Marshal(f.Detail)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Sink is the interface modules use to record findings, open raw-output
// directories on disk, and log events.
//
// Findings are normalized and persisted to SQLite for the report UI. Raw
// tool output (ScoutSuite HTML, Pacu session, Steampipe JSON, etc.) is
// written to the filesystem under the engagement directory so the user can
// read it directly off the mount — it does not go into the DB.
type Sink interface {
	Write(ctx context.Context, f Finding) error
	// RawDir returns (and creates if needed) the per-(module, account)
	// directory under the engagement dir where external tools should write
	// their native output.
	RawDir(module, accountID string) (string, error)
	LogEvent(ctx context.Context, module, accountID, level, msg string) error
}
