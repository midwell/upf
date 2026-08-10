<!--
SPDX-License-Identifier: Proprietary
SPDX-FileCopyrightText: Copyright (c) 2025 Forsway Scandinavia AB. All rights reserved.
This software is proprietary and confidential.
-->
# Repository Guidelines

## Project Structure & Module Organization
- `cmd/`: Go entrypoints for PFCP agent tools, including the P4 constant generator.
- `pfcpiface/`: core PFCP agent, protocol handlers, and datapath plugins; make this the first review stop.
- `internal/` & `pkg/`: shared helpers for control-plane logic, metrics, and adapters.
- `conf/`, `deployments/`, `docs/`: reference configurations, manifests, and design notes—update alongside code.
- `test/`, `ptf/`: Go integration suites and Python PTF harness; keep both in step with datapath changes.

## Build, Test, and Development Commands
- `make docker-build`: builds the `bess` and `pfcpiface` images; set `DOCKER_TARGETS=pfcpiface` for a narrow rebuild.
- `make test`: runs Go unit tests with race detection and coverage, writing `.coverage/coverage-unit.txt`.
- `make test-bess-integration-native`: drives integration tests against the BESS datapath (`DATAPATH=bess`).
- `make test-up4-integration-docker`: builds the PFCP agent image and exercises UP4 integration cases in Docker.
- `make fmt` / `make golint`: apply `go fmt` and run `golangci-lint` under `.golangci.yml` rules.

## Coding Style & Naming Conventions
- Follow Go defaults: tabs for indentation, `gofmt` ordering, `camelCase` locals, and exported `CamelCase` types.
- Honour `.golangci.yml`; resolve lint findings locally before pushing.
- Keep protobuf artifacts generated via `make pb` or `make py-pb`; never edit them manually.
- Place new commands under `cmd/<tool>` and shared logic under `internal/` to limit the public API.

## Testing Guidelines
- Name Go tests using `Test<Component>` and keep table-driven cases in `_test.go` files beside the source.
- Update integration fixtures in `test/integration` when PFCP flows or datapath expectations change.
- For PTF changes, sync Python dependencies with `requirements.txt` and document any new environment variables in `docs/`.
- Upload coverage summaries or key logs when the CI job exercises new code paths.

## Commit & Pull Request Guidelines
- **ALWAYS use `git commit -s`** to add a Signed-off-by line to commits.
- Match the existing history: concise imperative subject (≤72 chars) with optional issue or PR reference in parentheses, e.g., `Fix PFCP session cleanup (#942)`.
- Squash fixups before review; one logical change per commit keeps release notes manageable.
- PRs should call out datapath impact, required config changes, and test evidence (commands run, logs, metrics screenshots if relevant).
- Link related Jira/GitHub issues and mention reviewers or owners of touched modules (PFCP, BESS, UP4).

## Security & Configuration Tips
- Validate secrets stay out of the repo; use `conf/` templates and reference external secret managers in docs.
- Regenerate `internal/p4constants/p4constants.go` with `make p4-constants` when updating `conf/p4/bin/p4info.txt` and commit both artifacts together.
