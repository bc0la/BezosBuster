package report

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"

	"github.com/you/bezosbuster/internal/engagement"
	"github.com/you/bezosbuster/internal/module"

	_ "modernc.org/sqlite"
)

//go:embed index.html
var indexHTML []byte

// Serve starts an HTTP server bound to addr that reads the engagement DB
// from dir and exposes a tabbed report, a small JSON API, and a static file
// handler for browsing raw tool output written to dir.
func Serve(addr, dir string) error {
	dbPath := filepath.Join(dir, engagement.DBFileName)
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("engagement db not found at %s: %w", dbPath, err)
	}
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
	// Static browser for raw tool output files under the engagement dir.
	// Safe because http.Dir rejects traversal outside dir.
	mux.Handle("/raw/", http.StripPrefix("/raw/", http.FileServer(http.Dir(dir))))
	mux.HandleFunc("/api/findings", func(w http.ResponseWriter, r *http.Request) {
		module := r.URL.Query().Get("module")
		rows, err := queryFindings(db, dir, module)
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
	ID            int64  `json:"id"`
	AccountID     string `json:"account_id"`
	Region        string `json:"region"`
	Module        string `json:"module"`
	Severity      string `json:"severity"`
	ResourceARN   string `json:"resource_arn"`
	Title         string `json:"title"`
	Detail        any    `json:"detail"`
	RawOutputPath string `json:"raw_output_path,omitempty"`
	CreatedAt     string `json:"created_at"`
}

func queryFindings(db *sql.DB, dir, module string) ([]findingRow, error) {
	query := `SELECT id, account_id, region, module, severity, resource_arn, title, detail_json, raw_output_path, created_at FROM findings`
	var args []any
	if module != "" {
		query += " WHERE module = ?"
		args = append(args, module)
	}
	query += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id DESC LIMIT 1000000"
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []findingRow
	for rows.Next() {
		var r findingRow
		var detailJSON string
		var rawPath sql.NullString
		if err := rows.Scan(&r.ID, &r.AccountID, &r.Region, &r.Module, &r.Severity, &r.ResourceARN, &r.Title, &detailJSON, &rawPath, &r.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(detailJSON), &r.Detail)
		if rawPath.Valid && rawPath.String != "" {
			// Convert absolute path to a /raw/... URL relative to the engagement dir.
			if rel, err := filepath.Rel(dir, rawPath.String); err == nil {
				r.RawOutputPath = "/raw/" + filepath.ToSlash(rel) + "/"
			}
		}
		out = append(out, r)
	}
	return out, nil
}

type summaryRow struct {
	Module string `json:"module"`
	Count  int    `json:"count"`
}

func summary(db *sql.DB) (map[string]any, error) {
	// Get counts from DB.
	dbCounts := map[string]int{}
	rows, err := db.Query(`SELECT module, count(*) FROM findings GROUP BY module ORDER BY module`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var mod string
		var count int
		if err := rows.Scan(&mod, &count); err != nil {
			return nil, err
		}
		dbCounts[mod] = count
	}

	// Merge with all registered modules so empty ones still show up.
	seen := map[string]bool{}
	var byMod []summaryRow
	for name, count := range dbCounts {
		byMod = append(byMod, summaryRow{Module: name, Count: count})
		seen[name] = true
	}
	for _, m := range module.All() {
		if !seen[m.Name()] {
			byMod = append(byMod, summaryRow{Module: m.Name(), Count: 0})
		}
	}
	sort.Slice(byMod, func(i, j int) bool { return byMod[i].Module < byMod[j].Module })

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
