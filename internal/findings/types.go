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
	ID           int64
	AccountID    string
	Region       string
	Module       string
	Severity     Severity
	ResourceARN  string
	Title        string
	Detail       any
	RawOutputRef string
	CreatedAt    time.Time
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

// Sink is the interface modules use to record findings and raw output.
type Sink interface {
	Write(ctx context.Context, f Finding) error
	WriteRaw(ctx context.Context, module, accountID, name string, payload []byte) (string, error)
	LogEvent(ctx context.Context, module, accountID, level, msg string) error
}
