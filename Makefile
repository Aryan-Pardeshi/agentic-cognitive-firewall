.PHONY: build test lint opa-test sdk-test-python sdk-test-ts examples integration test-all \
        bench-setup bench bench-agent bench-overhead docker-up docker-down clean

# ── Sidecar ──────────────────────────────────────────────────────────────────
build:
	cd sidecar && go build -o ../bin/acf-sidecar ./cmd/sidecar

test:
	cd sidecar && go test ./...

lint:
	cd sidecar && go vet ./...

# ── Policies ─────────────────────────────────────────────────────────────────
opa-test:
	opa test policies/v1/ policies/tests/ -v

# ── SDKs ─────────────────────────────────────────────────────────────────────
sdk-test-python:
	cd sdk/python && python -m pytest

sdk-test-ts:
	cd sdk/typescript && npm install --no-audit --no-fund && npm test

# ── Examples: every example against a freshly built sidecar ──────────────────
examples:
	scripts/run_examples.sh

# ── Integration ──────────────────────────────────────────────────────────────
integration:
	cd tests/integration && go test ./... -v -timeout 300s

# Everything that needs no model or network beyond package installs.
test-all: test sdk-test-python sdk-test-ts examples integration
	python -m pytest benchmarkv2 benchmarks/test_run_benchmark.py

# ── Benchmarks ───────────────────────────────────────────────────────────────
# AgentDojo is the default benchmark (benchmarkv2/agentdojo/README.md).
bench-setup:
	benchmarkv2/agentdojo/run_overnight.sh setup

# Model-free replay: a worst-case agent that obeys every injected instruction,
# every arm, the 609 attacked cases with reference calls. About 7 minutes.
bench:
	benchmarkv2/agentdojo/run_overnight.sh replay

# A live agent against an OpenAI-compatible server, e.g.
#   make bench-agent MODEL=gemma4 BASE_URL=http://localhost:8000/v1
bench-agent:
	MODEL=$(MODEL) BASE_URL=$(BASE_URL) benchmarkv2/agentdojo/run_overnight.sh pilot
	MODEL=$(MODEL) BASE_URL=$(BASE_URL) benchmarkv2/agentdojo/run_overnight.sh full

bench-overhead:
	python benchmarkv2/overhead/run_overhead.py

# ── Docker ───────────────────────────────────────────────────────────────────
docker-up:
	docker compose up -d

docker-down:
	docker compose down

# ── Clean ────────────────────────────────────────────────────────────────────
clean:
	rm -rf bin/
