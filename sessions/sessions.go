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

// Package sessions builds the process-wide ADK session service for the chosen backend.
package sessions

import (
	"context"
	"fmt"
	"os"
	"strings"

	"google.golang.org/api/option"

	"google.golang.org/adk/v2/session"
	"google.golang.org/adk/v2/session/vertexai"
)

// NewService returns the ADK session service for the selected backend.
func NewService(ctx context.Context) (session.Service, error) {
	engineID := os.Getenv("GOOGLE_CLOUD_AGENT_ENGINE_ID")
	if engineID == "" {
		return session.InMemoryService(), nil
	}
	loc := agentRuntimeLocation()
	// vertexService parses a full resource name; GOOGLE_CLOUD_AGENT_ENGINE_ID
	// is a bare id, so build the full name from it.
	name := fmt.Sprintf(
		"projects/%s/locations/%s/reasoningEngines/%s",
		os.Getenv("GOOGLE_CLOUD_PROJECT"), loc, engineID,
	)
	return vertexService(ctx, name)
}

// defaultAgentRuntimeLocation is the region Agent Runtime sessions default to
// when the agent itself is deployed elsewhere.
const defaultAgentRuntimeLocation = "us-central1"

// vertexService builds an ADK vertexai session service against an existing Agent Runtime.
func vertexService(ctx context.Context, engineName string) (session.Service, error) {
	parts := strings.Split(engineName, "/")
	project := parts[1]
	location := parts[3]
	id := parts[5]

	svc, err := vertexai.NewSessionService(
		ctx,
		vertexai.VertexAIServiceConfig{
			ProjectID:       project,
			Location:        location,
			ReasoningEngine: id,
		},
		option.WithEndpoint(aiplatformEndpoint(location)),
	)
	if err != nil {
		return nil, fmt.Errorf("create Agent Runtime session service: %w", err)
	}
	return svc, nil
}

// agentRuntimeLocation resolves the region for Agent Runtime operations.
//
// Agent Runtime is a regional resource and it doesn't support global location.
func agentRuntimeLocation() string {
	if loc := os.Getenv("GOOGLE_CLOUD_AGENT_ENGINE_LOCATION"); loc != "" {
		return loc
	}
	if loc := os.Getenv("GOOGLE_CLOUD_LOCATION"); loc != "" && loc != "global" {
		return loc
	}
	return defaultAgentRuntimeLocation
}

// aiplatformEndpoint returns the regional aiplatform endpoint for a location.
func aiplatformEndpoint(location string) string {
	return fmt.Sprintf("%s-aiplatform.googleapis.com:443", location)
}
