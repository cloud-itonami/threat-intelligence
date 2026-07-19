# etzhayyim-project-threat-intelligence

Public Threat Intelligence (TI) project for collecting, deduplicating, and publishing cybercrime-related IOCs (email addresses, URLs, domains, IPs, etc).

## Components

- `legacy-runtime/ti-collector-m7t8k2p1`: Ingest + extract + store API (App service invocation).
- `wasm/ti-ui-n3q6v8s4/svelte`: Public SvelteKit UI for searching and exporting indicators.

## Local Development (Quick Start)

1. Start legacy runtime + the collector service:

```bash
cd 60-apps/etzhayyim-project-threat-intelligence/legacy-runtime/ti-collector-m7t8k2p1
go test ./...

# Example (requires legacy runtime installed):
# legacy-runtime run --app-id ti-collector --app-port 8080 --legacy-runtime-http-port 3500 -- go run ./cmd/server
```

### Resources JSON-LD Output (resources.etzhayyim.com)

On ingest, the collector writes JSON-LD entity files into:

- `60-apps/etzhayyim-project-resources/content/ti/**`

Optional automation:

- `RESOURCES_GIT_AUTOCOMMIT=true` to `git add` + `git commit` after writing.
- `RESOURCES_GIT_AUTOPUSH=true` to also push `origin HEAD`.

2. Ingest sample data via App service invocation:

```bash
curl -sS "http://127.0.0.1:3500/v1.0/invoke/ti-collector/method/api/v1/ingest" \
  -H 'content-type: application/json' \
  -d '{"source":"manual","text":"contact: badguy@example.com hxxps://evil[.]example/path 1.2.3.4"}' | jq .
```

3. Start the UI:

```bash
cd 60-apps/etzhayyim-project-threat-intelligence/wasm/ti-ui-n3q6v8s4/svelte
pnpm i
VITE_PUBLIC_TI_API_BASE_URL="http://127.0.0.1:3500/v1.0/invoke/ti-collector/method" pnpm dev
```
