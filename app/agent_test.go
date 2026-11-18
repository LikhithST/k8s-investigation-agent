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
	"testing"
)

func TestValidateKubectlReadArgs(t *testing.T) {
	tests := []struct {
		name    string
		command string
		wantErr bool
	}{
		{
			name:    "allowed get pods",
			command: "get pods -n production",
			wantErr: false,
		},
		{
			name:    "allowed with leading kubectl",
			command: "kubectl describe pod payment-service -n prod",
			wantErr: false,
		},
		{
			name:    "allowed logs with tail",
			command: "logs payment-service --tail=100",
			wantErr: false,
		},
		{
			name:    "allowed namespace flag before subcommand",
			command: "-n kube-system get events",
			wantErr: false,
		},
		{
			name:    "allowed auth can-i",
			command: "auth can-i get pods",
			wantErr: false,
		},
		{
			name:    "allowed config view",
			command: "config view",
			wantErr: false,
		},
		{
			name:    "forbidden delete pod",
			command: "delete pod payment-service",
			wantErr: true,
		},
		{
			name:    "forbidden apply manifest",
			command: "apply -f deployment.yaml",
			wantErr: true,
		},
		{
			name:    "forbidden exec",
			command: "exec -it payment-service -- /bin/sh",
			wantErr: true,
		},
		{
			name:    "forbidden patch",
			command: "patch deployment payment-service -p '{}'",
			wantErr: true,
		},
		{
			name:    "forbidden scale",
			command: "scale deployment payment-service --replicas=0",
			wantErr: true,
		},
		{
			name:    "forbidden rollout restart",
			command: "rollout restart deployment payment-service",
			wantErr: true,
		},
		{
			name:    "forbidden shell injection semicolon",
			command: "get pods; rm -rf /",
			wantErr: true,
		},
		{
			name:    "forbidden shell pipe",
			command: "get pods | grep payment",
			wantErr: true,
		},
		{
			name:    "forbidden watch flag",
			command: "get pods -w",
			wantErr: true,
		},
		{
			name:    "forbidden follow logs flag",
			command: "logs payment-service -f",
			wantErr: true,
		},
		{
			name:    "forbidden config use-context",
			command: "config use-context prod",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateKubectlReadArgs(tt.command)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateKubectlReadArgs(%q) error = %v, wantErr %v", tt.command, err, tt.wantErr)
			}
		})
	}
}

func TestParseK8sLogs(t *testing.T) {
	raw := "2026-11-18T10:00:00Z ERROR Pod payment-service CrashLoopBackOff\n2026-11-18T10:00:05Z FATAL Container killed due to OOMKilled (exit code 137)"
	res, err := parseK8sLogs(nil, ParseLogsArgs{RawLogs: raw})
	if err != nil {
		t.Fatalf("parseK8sLogs() unexpected error: %v", err)
	}
	if res.TotalLines != 2 {
		t.Errorf("got TotalLines=%d, want 2", res.TotalLines)
	}
	if len(res.DetectedSignals) < 2 {
		t.Errorf("expected at least 2 signals, got %v", res.DetectedSignals)
	}
}
