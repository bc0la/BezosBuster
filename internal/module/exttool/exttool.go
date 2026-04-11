// Package exttool contains helpers shared by modules that wrap external tools.
package exttool

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
)

// ArgBuilder produces a command-line argument list given the raw output
// directory for this tool run. Wrappers use it to template the directory
// into tool-specific flags (e.g. --report-dir, --export json=<path>).
type ArgBuilder func(rawDir string) []string

// Run executes a wrapped external tool:
//
//  1. Resolves binary on PATH; logs a warning and returns nil if missing.
//  2. Asks the sink for a per-(module, account) raw output directory.
//  3. Runs the binary with AWS_* env vars and the args produced by buildArgs.
//  4. Tees stdout+stderr to <rawDir>/stdout.log and <rawDir>/stderr.log.
//  5. Writes a single summary Finding pointing at the raw dir so the report
//     UI can link to it; the raw tool output itself is on the filesystem,
//     not in the SQLite DB.
func Run(ctx context.Context, moduleName string, t creds.AccountTarget, sink findings.Sink, binary string, buildArgs ArgBuilder) error {
	if _, err := exec.LookPath(binary); err != nil {
		_ = sink.LogEvent(ctx, moduleName, t.AccountID, "warn", "binary not found on PATH: "+binary)
		return nil
	}

	rawDir, err := sink.RawDir(moduleName, t.AccountID)
	if err != nil {
		return err
	}

	env, err := buildAWSEnv(ctx, t)
	if err != nil {
		return err
	}

	args := buildArgs(rawDir)

	stdoutPath := filepath.Join(rawDir, "stdout.log")
	stderrPath := filepath.Join(rawDir, "stderr.log")
	stdoutFile, err := os.Create(stdoutPath)
	if err != nil {
		return err
	}
	defer stdoutFile.Close()
	stderrFile, err := os.Create(stderrPath)
	if err != nil {
		return err
	}
	defer stderrFile.Close()

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = append(cmd.Env, env...)
	cmd.Stdout = io.MultiWriter(stdoutFile)
	cmd.Stderr = io.MultiWriter(stderrFile)
	runErr := cmd.Run()

	sev := findings.SevInfo
	title := binary + " completed (output: " + rawDir + ")"
	if runErr != nil {
		sev = findings.SevLow
		title = binary + " failed: " + runErr.Error()
	}
	_ = sink.Write(ctx, findings.Finding{
		AccountID:     t.AccountID,
		Module:        moduleName,
		Severity:      sev,
		Title:         title,
		RawOutputPath: rawDir,
		Detail: map[string]any{
			"binary":   binary,
			"args":     args,
			"raw_dir":  rawDir,
			"stdout":   stdoutPath,
			"stderr":   stderrPath,
			"exit":     errString(runErr),
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
	v, err := t.Config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, errors.New("retrieve credentials: " + err.Error())
	}
	env := []string{
		"AWS_ACCESS_KEY_ID=" + v.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY=" + v.SecretAccessKey,
		"AWS_DEFAULT_REGION=" + t.Config.Region,
		"AWS_REGION=" + t.Config.Region,
		"PATH=/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/home/bb",
	}
	if v.SessionToken != "" {
		env = append(env, "AWS_SESSION_TOKEN="+v.SessionToken)
	}
	return env, nil
}
