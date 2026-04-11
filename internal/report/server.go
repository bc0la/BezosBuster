package report

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"

	_ "modernc.org/sqlite"
)

//go:embed index.html
var indexHTML []byte

// Serve starts an HTTP server bound to addr that reads the given engagement
// SQLite DB and exposes a tabbed report plus a small JSON API.
func Serve(addr, dbPath string) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})
	mux.HandleFunc("/api/findings", func(w http.ResponseWriter, r *http.Request) {
		module := r.URL.Query().Get("module")
		rows, err := queryFindings(db, module)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, rows)
	})
	mux.HandleFunc("/api/summary", func(w http.ResponseWriter, r *http.Request) {
		s, err := summary(db)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, s)
	})
	fmt.Printf("report listening on http://%s\n", addr)
	return http.ListenAndServe(addr, mux)
}

type findingRow struct {
	ID          int64  `json:"id"`
	AccountID   string `json:"account_id"`
	Region      string `json:"region"`
	Module      string `json:"module"`
	Severity    string `json:"severity"`
	ResourceARN string `json:"resource_arn"`
	Title       string `json:"title"`
	Detail      any    `json:"detail"`
	CreatedAt   string `json:"created_at"`
}

func queryFindings(db *sql.DB, module string) ([]findingRow, error) {
	query := `SELECT id, account_id, region, module, severity, resource_arn, title, detail_json, created_at FROM findings`
	var args []any
	if module != "" {
		query += " WHERE module = ?"
		args = append(args, module)
	}
	query += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id DESC LIMIT 2000"
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []findingRow
	for rows.Next() {
		var r findingRow
		var detailJSON string
		if err := rows.Scan(&r.ID, &r.AccountID, &r.Region, &r.Module, &r.Severity, &r.ResourceARN, &r.Title, &detailJSON, &r.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(detailJSON), &r.Detail)
		out = append(out, r)
	}
	return out, nil
}

type summaryRow struct {
	Module string `json:"module"`
	Count  int    `json:"count"`
}

func summary(db *sql.DB) (map[string]any, error) {
	rows, err := db.Query(`SELECT module, count(*) FROM findings GROUP BY module ORDER BY module`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var byMod []summaryRow
	for rows.Next() {
		var r summaryRow
		if err := rows.Scan(&r.Module, &r.Count); err != nil {
			return nil, err
		}
		byMod = append(byMod, r)
	}
	sevRows, err := db.Query(`SELECT severity, count(*) FROM findings GROUP BY severity`)
	if err != nil {
		return nil, err
	}
	defer sevRows.Close()
	bySev := map[string]int{}
	for sevRows.Next() {
		var k string
		var v int
		if err := sevRows.Scan(&k, &v); err != nil {
			return nil, err
		}
		bySev[k] = v
	}
	return map[string]any{"modules": byMod, "severity": bySev}, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
