package ssm_commands

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/you/bezosbuster/internal/awsapi"
	"github.com/you/bezosbuster/internal/creds"
	"github.com/you/bezosbuster/internal/findings"
	"github.com/you/bezosbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "ssm_commands" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"ssm:ListCommands", "ssm:ListCommandInvocations"}
}

var secretKeys = []string{"password", "secret", "token", "key", "credential", "passwd"}

func looksLikeSecret(key string) bool {
	k := strings.ToLower(key)
	for _, s := range secretKeys {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// commandGroup deduplicates commands that share the same document + parameters.
type commandGroup struct {
	docName        string
	params         map[string]string
	secretHits     []string
	sev            findings.Severity
	commandIDs     []string
	targets        []string
	firstRequested string
	lastRequested  string
	statuses       map[string]int
	invocations    []invocationInfo
}

type invocationInfo struct {
	CommandID  string `json:"command_id"`
	InstanceID string `json:"instance_id"`
	Status     string `json:"status"`
	Output     string `json:"output,omitempty"`
}

// groupKey produces a dedup key from document name + sorted parameters.
func groupKey(docName string, params map[string]string) string {
	var parts []string
	for k, v := range params {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	h := sha256.Sum256([]byte(docName + "|" + strings.Join(parts, "|")))
	return fmt.Sprintf("%x", h[:8])
}

func (Module) Run(ctx context.Context, t creds.AccountTarget, sink findings.Sink) error {
	regions := awsapi.EnabledRegions(ctx, t.Config)
	for _, region := range regions {
		if err := scanRegion(ctx, t, region, sink); err != nil {
			_ = sink.LogEvent(ctx, "ssm_commands", t.AccountID, "warn", region+": "+err.Error())
		}
	}
	return nil
}

func scanRegion(ctx context.Context, t creds.AccountTarget, region string, sink findings.Sink) error {
	cli := ssm.NewFromConfig(t.Config, func(o *ssm.Options) { o.Region = region })

	// Collect all commands, grouped by document+params.
	groups := map[string]*commandGroup{}

	pager := ssm.NewListCommandsPaginator(cli, &ssm.ListCommandsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("ssm list commands: %w", err)
		}
		for _, cmd := range page.Commands {
			commandID := aws.ToString(cmd.CommandId)
			docName := aws.ToString(cmd.DocumentName)
			status := string(cmd.Status)

			// Flatten parameters.
			params := map[string]string{}
			for k, v := range cmd.Parameters {
				params[k] = strings.Join(v, " ")
			}

			key := groupKey(docName, params)
			g, ok := groups[key]
			if !ok {
				// Check for secrets.
				sev := findings.SevInfo
				var secretHits []string
				for k, v := range params {
					if looksLikeSecret(k) && v != "" {
						sev = findings.SevHigh
						secretHits = append(secretHits, k)
					}
				}
				if strings.Contains(docName, "RunShellScript") || strings.Contains(docName, "RunPowerShellScript") {
					if sev == findings.SevInfo {
						sev = findings.SevLow
					}
				}
				g = &commandGroup{
					docName:    docName,
					params:     params,
					secretHits: secretHits,
					sev:        sev,
					statuses:   map[string]int{},
				}
				groups[key] = g
			}

			g.commandIDs = append(g.commandIDs, commandID)
			g.statuses[status]++

			// Collect targets.
			for _, id := range cmd.InstanceIds {
				g.targets = append(g.targets, id)
			}
			for _, tgt := range cmd.Targets {
				g.targets = append(g.targets, fmt.Sprintf("%s=%s", aws.ToString(tgt.Key), strings.Join(tgt.Values, ",")))
			}

			// Track time range.
			if cmd.RequestedDateTime != nil {
				ts := cmd.RequestedDateTime.Format("2006-01-02 15:04:05 UTC")
				if g.firstRequested == "" || ts < g.firstRequested {
					g.firstRequested = ts
				}
				if ts > g.lastRequested {
					g.lastRequested = ts
				}
			}
		}
	}

	// For each group, fetch invocation output from the most recent command.
	for _, g := range groups {
		if len(g.commandIDs) == 0 {
			continue
		}
		// Use the last command ID (most recent) for invocation output.
		latestCmdID := g.commandIDs[len(g.commandIDs)-1]
		invPager := ssm.NewListCommandInvocationsPaginator(cli, &ssm.ListCommandInvocationsInput{
			CommandId: aws.String(latestCmdID),
			Details:   true,
		})
		for invPager.HasMorePages() {
			invPage, err := invPager.NextPage(ctx)
			if err != nil {
				break
			}
			for _, inv := range invPage.CommandInvocations {
				info := invocationInfo{
					CommandID:  aws.ToString(inv.CommandId),
					InstanceID: aws.ToString(inv.InstanceId),
					Status:     string(inv.Status),
				}
				// Collect output from plugins.
				var outputs []string
				for _, p := range inv.CommandPlugins {
					out := aws.ToString(p.Output)
					if out != "" {
						outputs = append(outputs, out)
					}
				}
				if len(outputs) > 0 {
					info.Output = strings.Join(outputs, "\n---\n")
					// Truncate very long output.
					if len(info.Output) > 4000 {
						info.Output = info.Output[:4000] + "\n... (truncated)"
					}
				}
				g.invocations = append(g.invocations, info)
			}
		}
	}

	// Deduplicate targets.
	for _, g := range groups {
		seen := map[string]bool{}
		var unique []string
		for _, t := range g.targets {
			if !seen[t] {
				seen[t] = true
				unique = append(unique, t)
			}
		}
		g.targets = unique
	}

	// Emit one finding per group.
	for key, g := range groups {
		count := len(g.commandIDs)
		title := fmt.Sprintf("SSM %s (%dx)", g.docName, count)
		if len(g.secretHits) > 0 {
			title += " — secrets in params: " + strings.Join(g.secretHits, ", ")
		}

		// Build status summary string.
		var statusParts []string
		for s, c := range g.statuses {
			statusParts = append(statusParts, fmt.Sprintf("%s:%d", s, c))
		}
		sort.Strings(statusParts)

		// Collect invocation outputs for display.
		var invocationDetails []map[string]any
		for _, inv := range g.invocations {
			entry := map[string]any{
				"instance_id": inv.InstanceID,
				"status":      inv.Status,
			}
			if inv.Output != "" {
				entry["output"] = inv.Output
			}
			invocationDetails = append(invocationDetails, entry)
		}

		// Check invocation output for secrets too.
		if g.sev != findings.SevHigh {
			for _, inv := range g.invocations {
				lower := strings.ToLower(inv.Output)
				if strings.Contains(lower, "akia") || strings.Contains(lower, "begin rsa") ||
					strings.Contains(lower, "begin private") || strings.Contains(lower, "password") {
					g.sev = findings.SevHigh
					break
				}
			}
		}

		_ = sink.Write(ctx, findings.Finding{
			AccountID:   t.AccountID,
			Region:      region,
			Module:      "ssm_commands",
			Severity:    g.sev,
			ResourceARN: fmt.Sprintf("arn:aws:ssm:%s:%s:document/%s", region, t.AccountID, g.docName),
			Title:       title,
			Detail: map[string]any{
				"group_key":       key,
				"document":        g.docName,
				"execution_count": count,
				"parameters":      g.params,
				"targets":         g.targets,
				"statuses":        strings.Join(statusParts, ", "),
				"first_run":       g.firstRequested,
				"last_run":        g.lastRequested,
				"command_ids":     g.commandIDs,
				"invocations":     invocationDetails,
				"secret_matches":  g.secretHits,
			},
		})
	}

	return nil
}
