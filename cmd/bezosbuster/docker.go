package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// DefaultDockerImage is the batteries-included image that bundles the external
// tool zoo (ScoutSuite, Pacu, Steampipe/Powerpipe, Kingfisher, Blue-CloudPEASS).
const DefaultDockerImage = "ghcr.io/bc0la/bezosbuster:latest"

// dockerPlan describes how to re-run a subcommand inside the Docker image.
type dockerPlan struct {
	image   string
	subArgs []string // the bezosbuster subcommand + translated flags to run in-container
	hostDir string   // host dir bind-mounted at /data (engagements root)
	ports   []string // "host:container" port publishes (e.g. steampipe dashboard)
	pull    bool     // force `docker pull` even when the image is present locally
}

// wantDocker decides whether a zoo command should delegate into the image.
//
//	mode "on"   → always (unless already inside the container)
//	mode "off"  → never
//	mode "auto" → only when docker is available AND the sentinel tool (the
//	              flagship external binary for this command) is missing locally
//
// The returned reason is surfaced to the user so the choice is never silent.
func wantDocker(mode, sentinel string) (bool, string) {
	if os.Getenv("BB_IN_DOCKER") == "1" {
		return false, "already running inside the container"
	}
	switch mode {
	case "off":
		return false, "disabled with --docker=false"
	case "on":
		if _, err := exec.LookPath("docker"); err != nil {
			return false, "forced with --docker but docker is not on PATH"
		}
		return true, "forced with --docker"
	default: // auto
		if _, err := exec.LookPath("docker"); err != nil {
			return false, "docker not found — running locally"
		}
		if _, err := exec.LookPath(sentinel); err == nil {
			return false, sentinel + " found locally — running natively"
		}
		return true, sentinel + " not found locally — using the Docker image"
	}
}

// dockerMode collapses the tri-state --docker flag into "on"/"off"/"auto".
// Unset → auto; --docker → on; --docker=false → off.
func dockerMode(changed, value bool) string {
	if !changed {
		return "auto"
	}
	if value {
		return "on"
	}
	return "off"
}

// runInDocker ensures the image is present (pulling if needed), then executes
// the subcommand inside it with ~/.aws, the engagements dir, AWS_* env, and any
// ports wired through. Stdio is inherited so the TUI and prompts work.
func runInDocker(ctx context.Context, p dockerPlan) error {
	image := p.image
	if image == "" {
		image = DefaultDockerImage
	}

	if p.pull || !imagePresent(ctx, image) {
		fmt.Fprintf(os.Stderr, "pulling %s ...\n", image)
		pull := exec.CommandContext(ctx, "docker", "pull", image)
		pull.Stdout, pull.Stderr = os.Stderr, os.Stderr
		if err := pull.Run(); err != nil {
			return fmt.Errorf("docker pull %s: %w", image, err)
		}
	}

	// Make sure the bind-mount source exists so docker doesn't create it as root.
	if p.hostDir != "" {
		if err := os.MkdirAll(p.hostDir, 0o755); err != nil {
			return err
		}
	}

	args := []string{"run", "--rm"}
	if isTTY(os.Stdin) && isTTY(os.Stdout) {
		args = append(args, "-it")
	} else {
		args = append(args, "-i")
	}
	args = append(args, "-e", "BB_IN_DOCKER=1")

	// Forward whatever AWS_* identity vars are set so env-credential and
	// SSO/assume-role-via-profile users both work. `-e KEY` (no value) passes
	// the value through from the current environment.
	for _, k := range []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION",
	} {
		if os.Getenv(k) != "" {
			args = append(args, "-e", k)
		}
	}

	// Mount ~/.aws read-only at the container user's home (uid 1000 == bb, so
	// permissions line up) — covers named profiles, SSO token cache, and the
	// role-chaining config the cross-account flags rely on.
	if home, err := os.UserHomeDir(); err == nil {
		awsDir := filepath.Join(home, ".aws")
		if st, err := os.Stat(awsDir); err == nil && st.IsDir() {
			args = append(args, "-v", awsDir+":/home/bb/.aws:ro")
		}
	}

	if p.hostDir != "" {
		args = append(args, "-v", p.hostDir+":/data")
	}
	for _, port := range p.ports {
		args = append(args, "-p", port)
	}

	args = append(args, image)
	args = append(args, p.subArgs...)

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func imagePresent(ctx context.Context, image string) bool {
	return exec.CommandContext(ctx, "docker", "image", "inspect", image).Run() == nil
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
