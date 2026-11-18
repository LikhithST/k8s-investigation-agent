# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies, retrying so a dropped module proxy connection doesn't
# fail the image build
RUN go mod download || (sleep 10 && go mod download) || (sleep 20 && go mod download)

# Copy source code
COPY *.go ./
COPY app/ ./app/
COPY appinfo/ ./appinfo/
COPY sessions/ ./sessions/

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /agent .

# Runtime stage
FROM gcr.io/distroless/static-debian12

COPY --from=builder /agent /agent

ARG COMMIT_SHA=""
ENV COMMIT_SHA=${COMMIT_SHA}

EXPOSE 8080

# The api launcher is mounted with `-path_prefix /` to serve the app at root, instead of under `/api`.
# appinfo already defaults to `/`, so it needs no explicit flag.
# The web launcher binds 127.0.0.1 by default, which traffic into the container cannot reach.
# Cloud Run sets PORT env var which ADK launcher reads automatically.
ENTRYPOINT ["/agent", "web", "--host", "0.0.0.0", "api", "-path_prefix", "/", "a2a", "webui", "appinfo"]
