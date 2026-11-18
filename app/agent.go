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

// Package app contains the root agent implementation.
package app

import (
	"context"
	"log"
	"os"

	"github.com/joho/godotenv"
	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
	"google.golang.org/adk/v2/agent/workflowagents/sequentialagent"
	"google.golang.org/adk/v2/model/openaimodel"
	"google.golang.org/adk/v2/tool"
	"google.golang.org/adk/v2/tool/functiontool"
)

const logParserInstruction = `You are the Log Parser Agent (Stage 1 of the Kubernetes Investigation Pipeline).
Your responsibility is to ingest raw Kubernetes logs or live cluster state and extract a structured inventory of facts, signals, and line-numbered log entries.

## Steps
1. If the user provides a file path (e.g., sample-k8s.log), call the read_log_file tool first to load the raw logs.
2. If the user asks to investigate a live cluster, namespace, pod, or workload without providing raw logs, use the run_kubectl_readonly tool (strictly read-only: get, describe, logs, events, top) to gather pod statuses, events, resource descriptions, and container logs.
3. Call the parse_k8s_logs tool on the raw logs to extract severity counts, Kubernetes failure signals, and line-numbered evidence lines.
4. Produce a structured parsing report containing:
   - **Affected Resources**: Pods, containers, nodes, namespaces, and services mentioned in the logs or cluster state.
   - **Severity & Signal Summary**: Counts of FATAL/ERROR/WARN/INFO lines and all detected Kubernetes failure categories.
   - **Chronological Event Log**: Key events ordered by timestamp.
   - **Line-Numbered Evidence Catalog**: Every notable log line or kubectl state observation with its exact line number, timestamp, category, and verbatim text.`

const rootCauseInvestigatorInstruction = `You are the Root Cause Investigator Agent (Stage 2 of the Kubernetes Investigation Pipeline).
Your responsibility is to analyze the structured log summary produced by logparseragent, optionally inspect additional read-only cluster state or related log files if needed, and determine the technical root cause and cascading failure chain.

## Parsed Log Summary from Stage 1
{parsed_logs_summary?}

## Steps
1. If additional cluster context (e.g., describing related pods, deployments, services, configmaps, events, or logs) or local files are needed to confirm the root cause, use run_kubectl_readonly or read_log_file. Never attempt any mutating operations.
2. Distinguish between the **Primary Root Cause** (the initial trigger) and **Cascading Symptoms** (secondary failures such as probe failures, OOMKills, or CrashLoopBackOff).
3. Reconstruct the exact **Failure Propagation Chain** step-by-step across components.
4. Cite the specific line numbers, timestamps, and kubectl outputs from Stage 1 (or your own read-only queries) for every technical claim you make.
5. Propose concrete **Remediation & Prevention Steps** (Kubernetes manifest changes, resource limits/requests, probe tuning, application fixes, and diagnostic kubectl commands).`

const evidenceVerifierInstruction = `You are the Evidence Verifier Agent (Stage 3 of the Kubernetes Investigation Pipeline).
Your responsibility is to audit the Root Cause Analysis against the parsed log evidence and deliver the final, verified Post-Investigation Report to the user.

## Parsed Log Summary (Stage 1)
{parsed_logs_summary?}

## Root Cause Analysis (Stage 2)
{root_cause_analysis?}

## Steps & Required Final Report Structure
Cross-check every claim in Stage 2 against the verbatim log lines from Stage 1, eliminate any unsupported assumptions, and present the final report with these exact sections:

### 1. Executive Summary
- Concise summary of the incident, impacted Kubernetes workloads/nodes, and overall severity.

### 2. Verified Root Cause Analysis (RCA)
- **Primary Root Cause**: The verified underlying trigger of the incident.
- **Cascading Failure Chain**: How the initial fault propagated into downstream symptoms.

### 3. Supporting Evidence & Verification Matrix
- Present a Markdown table mapping each finding to its supporting log evidence:
  | Finding / Claim | Line # & Timestamp | Exact Verbatim Log Evidence | Verification Status |
- Explain the technical significance of key evidence (e.g., Exit Code 137 = SIGKILL due to OOM).

### 4. Chronological Timeline of Events
- Step-by-step timeline reconstructed from the verified timestamps.

### 5. Remediation & Next Steps
- Actionable fixes (YAML config adjustments, resource tuning, code changes) and exact kubectl commands to verify recovery.`

func loadEnv(key string) string {
	err := godotenv.Load("./.env")
	if err != nil {
		log.Fatalln("error while loading env")
		return ""
	}
	return os.Getenv(key)
}

func NewRootAgent(ctx context.Context) (agent.Agent, error) {

	// Configure openaimodel to route through OpenRouter
	cfg := &openaimodel.ClientConfig{
		APIKey:  loadEnv("OPENROUTER_API_KEY"),
		BaseURL: "https://openrouter.ai/api/v1",
		API:     openaimodel.APIChatCompletions,
	}

	model, err := openaimodel.NewModel(ctx, "google/gemini-3.8-flash", cfg)
	if err != nil {
		log.Fatalf("Failed to create model: %v", err)
	}

	parseLogsTool, err := functiontool.New(functiontool.Config{
		Name:        "parse_k8s_logs",
		Description: "Parses raw Kubernetes logs to count severities, detect known K8s failure signals (OOMKilled, CrashLoopBackOff, probe failures, timeouts, etc.), and extract line-numbered evidence.",
	}, parseK8sLogs)
	if err != nil {
		log.Fatalf("Failed to create parse_k8s_logs tool: %v", err)
	}

	readLogFileTool, err := functiontool.New(functiontool.Config{
		Name:        "read_log_file",
		Description: "Reads Kubernetes logs or related configuration files from a local file path when the user provides a file path for investigation.",
	}, readLogFile)
	if err != nil {
		log.Fatalf("Failed to create read_log_file tool: %v", err)
	}

	kubectlReadonlyTool, err := functiontool.New(functiontool.Config{
		Name:        "run_kubectl_readonly",
		Description: "Executes strictly read-only kubectl commands (get, describe, logs, events, top, explain, cluster-info, version, diff) to inspect Kubernetes cluster state, pod statuses, events, and logs without making any modifications to the cluster.",
	}, runKubectlReadonly)
	if err != nil {
		log.Fatalf("Failed to create run_kubectl_readonly tool: %v", err)
	}

	// Stage 1: logparseragent
	logParserAgent, err := llmagent.New(llmagent.Config{
		Name:            "logparseragent",
		Model:           model,
		Description:     "Reads and parses raw Kubernetes logs and read-only cluster states into structured signals, severity counts, and line-numbered evidence.",
		Instruction:     logParserInstruction,
		Tools:           []tool.Tool{readLogFileTool, parseLogsTool, kubectlReadonlyTool},
		IncludeContents: llmagent.IncludeContentsDefault,
		OutputKey:       "parsed_logs_summary",
	})
	if err != nil {
		log.Fatalf("Failed to create logparseragent: %v", err)
	}

	// Stage 2: rootcauseinvestigatoragent
	rootCauseInvestigatorAgent, err := llmagent.New(llmagent.Config{
		Name:            "rootcauseinvestigatoragent",
		Model:           model,
		Description:     "Investigates parsed Kubernetes log signals and read-only cluster states to identify the primary root cause, cascading effects, and remediation steps.",
		Instruction:     rootCauseInvestigatorInstruction,
		Tools:           []tool.Tool{kubectlReadonlyTool, readLogFileTool, parseLogsTool},
		IncludeContents: llmagent.IncludeContentsDefault,
		OutputKey:       "root_cause_analysis",
	})
	if err != nil {
		log.Fatalf("Failed to create rootcauseinvestigatoragent: %v", err)
	}

	// Stage 3: evidenceverifieragent
	evidenceVerifierAgent, err := llmagent.New(llmagent.Config{
		Name:            "evidenceverifieragent",
		Model:           model,
		Description:     "Verifies root cause claims against exact log lines and compiles the final Kubernetes investigation report with supporting evidence.",
		Instruction:     evidenceVerifierInstruction,
		IncludeContents: llmagent.IncludeContentsDefault,
		OutputKey:       "verified_investigation_report",
	})
	if err != nil {
		log.Fatalf("Failed to create evidenceverifieragent: %v", err)
	}

	// Sequential Pipeline: logparseragent -> rootcauseinvestigatoragent -> evidenceverifieragent
	k8sInvestigationPipeline, err := sequentialagent.New(sequentialagent.Config{
		AgentConfig: agent.Config{
			Name:        "k8s_investigation_pipeline",
			Description: "Sequential Kubernetes log investigation pipeline (logparseragent -> rootcauseinvestigatoragent -> evidenceverifieragent).",
			SubAgents: []agent.Agent{
				logParserAgent,
				rootCauseInvestigatorAgent,
				evidenceVerifierAgent,
			},
		},
	})
	if err != nil {
		log.Fatalf("Failed to create sequential investigation pipeline: %v", err)
		return nil, err
	}
	return k8sInvestigationPipeline, nil
}
