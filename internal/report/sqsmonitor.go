package report

import (
	"context"
	"database/sql"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// This file powers the report UI's Utils → SQS Monitor. It reads the public
// SQS queues discovered by the public_sqs module straight from the findings
// DB, and streams messages from the anonymously-readable ones to the browser
// over SSE — using UNSIGNED requests (no AWS creds), so the report server keeps
// its credential-less, read-only posture. VisibilityTimeout=0 and no deletes
// make it a non-disruptive tap: the real consumer still receives everything.

type sqsQueue struct {
	QueueURL     string   `json:"queue_url"`
	Name         string   `json:"name"`
	Region       string   `json:"region"`
	Actions      []string `json:"actions"`
	HasCondition bool     `json:"has_condition"`
	AnonReceive  bool     `json:"anon_receive"`
}

var reQueueRegion = regexp.MustCompile(`https?://sqs\.([a-z0-9-]+)\.amazonaws\.com`)

func regionFromQueueURL(qurl, fallback string) string {
	if m := reQueueRegion.FindStringSubmatch(qurl); len(m) == 2 {
		return m[1]
	}
	return fallback
}

func anonReceiveAllowed(actions []string) bool {
	for _, a := range actions {
		la := strings.ToLower(a)
		if la == "*" || la == "sqs:*" || strings.Contains(la, "receivemessage") {
			return true
		}
	}
	return false
}

// listPublicQueues returns the distinct anonymous-policy SQS queues recorded by
// the public_sqs module.
func listPublicQueues(db *sql.DB) ([]sqsQueue, error) {
	rows, err := db.Query(`SELECT region, detail_json FROM findings WHERE module = 'public_sqs'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []sqsQueue
	for rows.Next() {
		var region, detailJSON string
		if err := rows.Scan(&region, &detailJSON); err != nil {
			continue
		}
		var d struct {
			QueueURL     string          `json:"queue_url"`
			QueueName    string          `json:"queue_name"`
			Actions      json.RawMessage `json:"actions"`
			HasCondition bool            `json:"has_condition"`
		}
		if err := json.Unmarshal([]byte(detailJSON), &d); err != nil || d.QueueURL == "" {
			continue
		}
		if seen[d.QueueURL] {
			continue
		}
		seen[d.QueueURL] = true

		var acts []string
		_ = json.Unmarshal(d.Actions, &acts)
		name := d.QueueName
		if name == "" {
			parts := strings.Split(strings.TrimRight(d.QueueURL, "/"), "/")
			name = parts[len(parts)-1]
		}
		out = append(out, sqsQueue{
			QueueURL:     d.QueueURL,
			Name:         name,
			Region:       regionFromQueueURL(d.QueueURL, region),
			Actions:      acts,
			HasCondition: d.HasCondition,
			AnonReceive:  anonReceiveAllowed(acts),
		})
	}
	return out, nil
}

func handleSQSQueues(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		qs, err := listPublicQueues(db)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, qs)
	}
}

// --- unsigned SQS receive (query API) ---

type sqsMessage struct {
	MessageID string `xml:"MessageId"`
	Body      string `xml:"Body"`
}

type receiveResult struct {
	XMLName  xml.Name     `xml:"ReceiveMessageResponse"`
	Messages []sqsMessage `xml:"ReceiveMessageResult>Message"`
}

// sqsHTTP timeout must exceed WaitTimeSeconds (long poll) below.
var sqsHTTP = &http.Client{Timeout: 35 * time.Second}

// anonReceive long-polls ReceiveMessage on a public queue with no signature.
// VisibilityTimeout=0 + never deleting → the message stays put for the real
// consumer. Returns the HTTP status so the caller can distinguish
// "not anonymously readable" (403) from transient errors.
func anonReceive(ctx context.Context, queueURL string) ([]sqsMessage, int, error) {
	params := url.Values{}
	params.Set("Action", "ReceiveMessage")
	params.Set("Version", "2012-11-05")
	params.Set("MaxNumberOfMessages", "10")
	params.Set("WaitTimeSeconds", "20")
	params.Set("VisibilityTimeout", "0")
	params.Set("AttributeName.1", "All")
	params.Set("MessageAttributeName.1", "All")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queueURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := sqsHTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("HTTP %d — anonymous receive not permitted", resp.StatusCode)
	}
	var rr receiveResult
	if err := xml.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return nil, resp.StatusCode, err
	}
	return rr.Messages, resp.StatusCode, nil
}

var reSafeName = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// handleSQSStream streams messages from one public queue to the browser via SSE
// and appends each to <dir>/sqs-monitor/<name>.jsonl. Only queues present in
// the findings DB are accepted (SSRF guard).
func handleSQSStream(db *sql.DB, dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		qurl := r.URL.Query().Get("queue")
		known, err := listPublicQueues(db)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var q *sqsQueue
		for i := range known {
			if known[i].QueueURL == qurl {
				q = &known[i]
				break
			}
		}
		if q == nil {
			http.Error(w, "unknown queue (not a public_sqs finding)", http.StatusBadRequest)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		sendEvent := func(event, data string) {
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
			flusher.Flush()
		}

		monDir := filepath.Join(dir, "sqs-monitor")
		_ = os.MkdirAll(monDir, 0o755)
		outPath := filepath.Join(monDir, reSafeName.ReplaceAllString(q.Name, "_")+".jsonl")
		outFile, _ := os.OpenFile(outPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if outFile != nil {
			defer outFile.Close()
		}
		relOut := outPath
		if rel, err := filepath.Rel(dir, outPath); err == nil {
			relOut = rel
		}
		sendEvent("status", fmt.Sprintf(`{"state":"connected","file":%q}`, relOut))

		ctx := r.Context()
		seen := map[string]bool{}
		for {
			if ctx.Err() != nil {
				return
			}
			msgs, code, err := anonReceive(ctx, q.QueueURL)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				sendEvent("status", fmt.Sprintf(`{"state":"error","code":%d,"error":%q}`, code, err.Error()))
				// A clear auth failure won't fix itself — stop this stream.
				if code == http.StatusForbidden || code == http.StatusUnauthorized {
					return
				}
				time.Sleep(5 * time.Second)
				continue
			}
			for _, m := range msgs {
				if m.MessageID != "" && seen[m.MessageID] {
					continue
				}
				if m.MessageID != "" {
					seen[m.MessageID] = true
				}
				line, _ := json.Marshal(map[string]any{
					"message_id": m.MessageID,
					"body":       m.Body,
					"ts":         time.Now().UTC().Format(time.RFC3339),
				})
				if outFile != nil {
					_, _ = outFile.Write(append(line, '\n'))
				}
				sendEvent("message", string(line))
			}
			// Heartbeat comment keeps the SSE connection warm between empty polls.
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}
