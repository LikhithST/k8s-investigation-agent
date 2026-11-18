// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package app

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"google.golang.org/adk/v2/agent"
)

// ParseLogsArgs defines the input for the parse_k8s_logs tool.
type ParseLogsArgs struct {
	RawLogs      string `json:"raw_logs" jsonschema:"Raw Kubernetes pod, container, or event logs to inspect."`
	FilterString string `json:"filter_string,omitempty" jsonschema:"Optional substring or keyword to filter specific log lines."`
}

// EvidenceLine represents a single notable log line with its line number and matched category.
type EvidenceLine struct {
	LineNumber int    `json:"line_number"`
	Category   string `json:"category"`
	Content    string `json:"content"`
}

// ParseLogsResult contains structured signals and evidence extracted from raw logs.
type ParseLogsResult struct {
	TotalLines      int            `json:"total_lines"`
	SeverityCounts  map[string]int `json:"severity_counts"`
	DetectedSignals []string       `json:"detected_signals"`
	EvidenceLines   []EvidenceLine `json:"evidence_lines"`
}

// ReadLogFileArgs defines the input for reading logs from a local file.
type ReadLogFileArgs struct {
	FilePath string `json:"file_path" jsonschema:"Path to the log file on disk."`
}

// ReadLogFileResult contains the file content read from disk.
type ReadLogFileResult struct {
	FilePath string `json:"file_path"`
	Content  string `json:"content"`
}

// KubectlReadArgs defines the input for the run_kubectl_readonly tool.
type KubectlReadArgs struct {
	Command string `json:"command" jsonschema:"Read-only kubectl command arguments (e.g., 'get pods -n production', 'describe pod payment-service', 'logs payment-service --tail=100', 'get events --sort-by=.lastTimestamp'). Do not include 'kubectl' prefix or any shell operators."`
}

// KubectlReadResult contains the output from executing a read-only kubectl command.
type KubectlReadResult struct {
	Command string `json:"command"`
	Output  string `json:"output"`
	Error   string `json:"error,omitempty"`
}

var allowedKubectlSubcommands = map[string]bool{
	"get":           true,
	"describe":      true,
	"logs":          true,
	"events":        true,
	"top":           true,
	"explain":       true,
	"api-resources": true,
	"api-versions":  true,
	"cluster-info":  true,
	"version":       true,
	"diff":          true,
}

var forbiddenKubectlSubcommands = map[string]bool{
	"apply":        true,
	"create":       true,
	"delete":       true,
	"patch":        true,
	"replace":      true,
	"edit":         true,
	"scale":        true,
	"autoscale":    true,
	"rollout":      true,
	"exec":         true,
	"run":          true,
	"attach":       true,
	"cp":           true,
	"port-forward": true,
	"proxy":        true,
	"cordon":       true,
	"uncordon":     true,
	"drain":        true,
	"taint":        true,
	"label":        true,
	"annotate":     true,
	"set":          true,
	"expose":       true,
	"debug":        true,
}

var k8sFailurePatterns = map[string][]string{
	"OOMKilled / Memory Exhaustion": {"oomkilled", "out of memory", "exit code 137", "cannot allocate memory"},
	"CrashLoopBackOff":              {"crashloopbackoff", "back-off restarting failed container"},
	"ImagePull / Registry Failure":  {"imagepullbackoff", "errimagepull", "manifest unknown", "pull access denied"},
	"Probe Failure":                 {"liveness probe failed", "readiness probe failed", "startup probe failed", "unhealthy"},
	"Config / Volume Mount Error":   {"createcontainerconfigerror", "mountvolume.setup failed", "secret", "configmap"},
	"Network / DNS / Timeout":       {"connection refused", "context deadline exceeded", "i/o timeout", "no such host", "connection reset by peer"},
	"Scheduling / Resource Quota":   {"failedscheduling", "insufficient cpu", "insufficient memory", "node(s) had untolerated taint", "evicted"},
	"Permission / RBAC Error":       {"forbidden", "unauthorized", "permission denied"},
}

func parseK8sLogs(_ agent.Context, args ParseLogsArgs) (ParseLogsResult, error) {
	lines := strings.Split(args.RawLogs, "\n")
	severityCounts := map[string]int{
		"ERROR": 0,
		"FATAL": 0,
		"WARN":  0,
		"INFO":  0,
	}
	signalSet := make(map[string]bool)
	var evidence []EvidenceLine
	filterLower := strings.ToLower(strings.TrimSpace(args.FilterString))

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)

		if filterLower != "" && !strings.Contains(lower, filterLower) {
			continue
		}

		matchedCategory := ""

		switch {
		case strings.Contains(lower, "fatal") || strings.Contains(lower, "panic"):
			severityCounts["FATAL"]++
			matchedCategory = "FATAL/PANIC"
		case strings.Contains(lower, "error") || strings.Contains(lower, "err") || strings.Contains(lower, "exception") || strings.Contains(lower, "failed"):
			severityCounts["ERROR"]++
			matchedCategory = "ERROR"
		case strings.Contains(lower, "warn"):
			severityCounts["WARN"]++
			matchedCategory = "WARN"
		case strings.Contains(lower, "info"):
			severityCounts["INFO"]++
		}

		for signal, keywords := range k8sFailurePatterns {
			for _, kw := range keywords {
				if strings.Contains(lower, kw) {
					signalSet[signal] = true
					matchedCategory = signal
				}
			}
		}

		if matchedCategory != "" || filterLower != "" {
			if len(evidence) < 100 {
				evidence = append(evidence, EvidenceLine{
					LineNumber: i + 1,
					Category:   matchedCategory,
					Content:    trimmed,
				})
			}
		}
	}

	var signals []string
	for sig := range signalSet {
		signals = append(signals, sig)
	}

	return ParseLogsResult{
		TotalLines:      len(lines),
		SeverityCounts:  severityCounts,
		DetectedSignals: signals,
		EvidenceLines:   evidence,
	}, nil
}

func readLogFile(_ agent.Context, args ReadLogFileArgs) (ReadLogFileResult, error) {
	data, err := os.ReadFile(args.FilePath)
	if err != nil {
		return ReadLogFileResult{}, fmt.Errorf("failed to read log file %q: %w", args.FilePath, err)
	}
	return ReadLogFileResult{
		FilePath: args.FilePath,
		Content:  string(data),
	}, nil
}

// validateKubectlReadArgs parses and validates that the kubectl command is strictly read-only.
func validateKubectlReadArgs(rawCommand string) ([]string, error) {
	trimmed := strings.TrimSpace(rawCommand)
	if trimmed == "" {
		return nil, fmt.Errorf("empty kubectl command")
	}

	// Block shell operators and command chaining
	for _, forbidden := range []string{";", "|", "&", "`", "$", ">", "<", "\n", "\r"} {
		if strings.Contains(trimmed, forbidden) {
			return nil, fmt.Errorf("forbidden shell character %q detected; only direct read-only kubectl arguments are allowed", forbidden)
		}
	}

	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return nil, fmt.Errorf("empty kubectl command")
	}

	// Strip optional leading "kubectl"
	if fields[0] == "kubectl" {
		fields = fields[1:]
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("missing kubectl subcommand")
	}

	// Find the subcommand (first non-flag token, skipping flag values for common global flags)
	subcommand := ""
	subcommandIdx := -1
	flagsWithValues := map[string]bool{
		"-n": true, "--namespace": true,
		"--context": true, "--cluster": true, "--user": true,
		"-l": true, "--selector": true,
		"--field-selector": true,
		"-o": true, "--output": true,
	}

	for _, tok := range fields {
		lowerTok := strings.ToLower(tok)
		for _, blockedFlag := range []string{"--kubeconfig", "--token", "--as", "--server", "-s", "--client-key", "--client-certificate", "--certificate-authority"} {
			if lowerTok == blockedFlag || strings.HasPrefix(lowerTok, blockedFlag+"=") {
				return nil, fmt.Errorf("flag %q is not allowed in read-only mode", tok)
			}
		}
		if lowerTok == "-w" || lowerTok == "--watch" || lowerTok == "--watch-only" || lowerTok == "-f" || lowerTok == "--follow" || strings.HasPrefix(lowerTok, "--watch=") || strings.HasPrefix(lowerTok, "--follow=") {
			return nil, fmt.Errorf("streaming/watch/file flag %q is not allowed", tok)
		}
	}

	for i := 0; i < len(fields); i++ {
		tok := fields[i]
		if strings.HasPrefix(tok, "-") {
			if flagsWithValues[tok] && !strings.Contains(tok, "=") {
				i++ // skip flag value
			}
			continue
		}

		subcommand = strings.ToLower(tok)
		subcommandIdx = i
		break
	}

	if subcommand == "" {
		return nil, fmt.Errorf("could not identify kubectl subcommand in %q", rawCommand)
	}

	if forbiddenKubectlSubcommands[subcommand] {
		return nil, fmt.Errorf("kubectl subcommand %q is forbidden: cluster modifications and interactive commands are strictly prohibited", subcommand)
	}

	// Allow "auth can-i" and "config view" / "config get-contexts" / "config current-context"
	if subcommand == "auth" {
		if subcommandIdx+1 >= len(fields) || strings.ToLower(fields[subcommandIdx+1]) != "can-i" {
			return nil, fmt.Errorf("only 'kubectl auth can-i' is allowed under 'auth'")
		}
		return fields, nil
	}
	if subcommand == "config" {
		if subcommandIdx+1 >= len(fields) {
			return nil, fmt.Errorf("missing config subcommand (allowed: view, get-contexts, current-context)")
		}
		cfgSub := strings.ToLower(fields[subcommandIdx+1])
		if cfgSub != "view" && cfgSub != "get-contexts" && cfgSub != "current-context" {
			return nil, fmt.Errorf("kubectl config %q is forbidden; only view, get-contexts, and current-context are allowed", cfgSub)
		}
		return fields, nil
	}

	if !allowedKubectlSubcommands[subcommand] {
		return nil, fmt.Errorf("kubectl subcommand %q is not in the read-only allowlist (allowed: get, describe, logs, events, top, explain, api-resources, api-versions, cluster-info, version, diff)", subcommand)
	}

	return fields, nil
}

func runKubectlReadonly(ctx agent.Context, args KubectlReadArgs) (KubectlReadResult, error) {
	validatedArgs, err := validateKubectlReadArgs(args.Command)
	if err != nil {
		return KubectlReadResult{
			Command: args.Command,
			Error:   err.Error(),
		}, err
	}

	var baseCtx context.Context = ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	execCtx, cancel := context.WithTimeout(baseCtx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(execCtx, "kubectl", validatedArgs...)
	out, execErr := cmd.CombinedOutput()
	fullCmd := "kubectl " + strings.Join(validatedArgs, " ")

	if execErr != nil {
		return KubectlReadResult{
			Command: fullCmd,
			Output:  string(out),
			Error:   fmt.Sprintf("kubectl execution failed: %v", execErr),
		}, nil
	}

	return KubectlReadResult{
		Command: fullCmd,
		Output:  string(out),
	}, nil
}
