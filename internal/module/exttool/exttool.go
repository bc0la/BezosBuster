// Package exttool contains helpers shared by modules that wrap external tools.
package exttool

import (
	"bytes"
	"context"
	"errors"
	"os/exec"

	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
)

// Run executes the given command with environment containing AWS credentials
// harvested from the account target's config. Stdout+stderr are captured
// and stored as a raw_output blob. A summary finding is written so the
// report shows the tool ran.
func Run(ctx context.Context, moduleName string, t creds.AccountTarget, sink findings.Sink, binary string, args []string) error {
	if _, err := exec.LookPath(binary); err != nil {
		_ = sink.LogEvent(ctx, moduleName, t.AccountID, "warn", "binary not found on PATH: "+binary)
		return nil
	}

	env, err := buildAWSEnv(ctx, t)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = append(cmd.Env, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	ref, _ := sink.WriteRaw(ctx, moduleName, t.AccountID, binary+"-stdout", stdout.Bytes())
	_, _ = sink.WriteRaw(ctx, moduleName, t.AccountID, binary+"-stderr", stderr.Bytes())

	sev := findings.SevInfo
	title := binary + " completed"
	if runErr != nil {
		sev = findings.SevLow
		title = binary + " failed: " + runErr.Error()
	}
	_ = sink.Write(ctx, findings.Finding{
		AccountID:    t.AccountID,
		Module:       moduleName,
		Severity:     sev,
		Title:        title,
		RawOutputRef: ref,
		Detail: map[string]any{
			"binary": binary,
			"args":   args,
			"exit":   errString(runErr),
		},
	})
	return nil
}

func errString(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

func buildAWSEnv(ctx context.Context, t creds.AccountTarget) ([]string, error) {
	// Retrieve concrete credentials so child processes can use them.
	v, err := t.Config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, errors.New("retrieve credentials: " + err.Error())
	}
	env := []string{
		"AWS_ACCESS_KEY_ID=" + v.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY=" + v.SecretAccessKey,
		"AWS_DEFAULT_REGION=" + t.Config.Region,
		"AWS_REGION=" + t.Config.Region,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root",
	}
	if v.SessionToken != "" {
		env = append(env, "AWS_SESSION_TOKEN="+v.SessionToken)
	}
	return env, nil
}
