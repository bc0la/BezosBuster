package report

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestAnonReceiveAllowed(t *testing.T) {
	if !anonReceiveAllowed([]string{"sqs:*"}) {
		t.Error("sqs:* should allow anon receive")
	}
	if !anonReceiveAllowed([]string{"*"}) {
		t.Error("* should allow anon receive")
	}
	if !anonReceiveAllowed([]string{"SQS:ReceiveMessage"}) {
		t.Error("case-insensitive ReceiveMessage should allow")
	}
	if anonReceiveAllowed([]string{"sqs:SendMessage"}) {
		t.Error("send-only should NOT allow anon receive")
	}
}

func TestRegionFromQueueURL(t *testing.T) {
	got := regionFromQueueURL("https://sqs.eu-west-2.amazonaws.com/123/Q", "fallback")
	if got != "eu-west-2" {
		t.Errorf("region parse = %q, want eu-west-2", got)
	}
	if regionFromQueueURL("https://example.com/weird", "fallback") != "fallback" {
		t.Error("non-SQS URL should use fallback region")
	}
}

func TestListPublicQueues(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE findings (module TEXT, region TEXT, detail_json TEXT)`); err != nil {
		t.Fatal(err)
	}
	recvQueue := `{"queue_url":"https://sqs.us-east-1.amazonaws.com/123456789012/PublicQ","queue_name":"PublicQ","actions":["sqs:ReceiveMessage","sqs:SendMessage"],"has_condition":false}`
	sendOnly := `{"queue_url":"https://sqs.eu-west-1.amazonaws.com/1/SendOnly","queue_name":"SendOnly","actions":["sqs:SendMessage"],"has_condition":true}`
	// Insert the receive queue twice to exercise dedup.
	for _, d := range []string{recvQueue, recvQueue, sendOnly} {
		if _, err := db.Exec(`INSERT INTO findings(module,region,detail_json) VALUES('public_sqs','us-east-1',?)`, d); err != nil {
			t.Fatal(err)
		}
	}
	// A finding from another module must be ignored.
	_, _ = db.Exec(`INSERT INTO findings(module,region,detail_json) VALUES('public_sns','us-east-1','{}')`)

	qs, err := listPublicQueues(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(qs) != 2 {
		t.Fatalf("want 2 distinct queues, got %d", len(qs))
	}
	byName := map[string]sqsQueue{}
	for _, q := range qs {
		byName[q.Name] = q
	}
	if pub, ok := byName["PublicQ"]; !ok || !pub.AnonReceive || pub.Region != "us-east-1" {
		t.Errorf("PublicQ wrong: %+v", pub)
	}
	if so, ok := byName["SendOnly"]; !ok || so.AnonReceive || !so.HasCondition {
		t.Errorf("SendOnly wrong: %+v", so)
	}
}
