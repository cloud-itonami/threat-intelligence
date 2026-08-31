# threat-intelligence

Public Threat Intelligence (TI) project: a registry of cybercrime-related IOCs
(indicators of compromise — IPs, domains, URLs, file hashes, emails, CVEs) with
per-indicator confidence and TLP sharing class.

Indicator data here is published and non-PII.

**Start here: [`docs/operator-quickstart.md`](docs/operator-quickstart.md)** —
install, typecheck, and run the test suite, with the observed output of each
step.

## What is in this repo

- `kotoba/` — the IOC registry reference implementation (TypeScript, on
  `@etzhayyim/sdk`; AT PDS records, no read-write vendor DB). Exports
  `registerIndicator` / `getIndicator` / `listIndicators` / `coverage`, and is
  covered by a 10-test vitest suite that runs fully in memory against
  `@etzhayyim/sdk-mock` — no network and no credentials.
- `catalog.edn` — the public threat-intelligence feeds a collector for this
  registry may draw from, keyed by the exact string to write into an
  indicator's `source` field. Twelve sources, each with the indicator types its
  payload actually carries, read off the feed rather than inferred from its
  name. Every URL in it returned 2xx with a non-empty payload when it was
  written; three further candidates were dropped, two of which returned 200 and
  served nothing but comments.
- `scripts/verify-catalog.cljs` — checks `catalog.edn` against the
  `IndicatorType` and `Tlp` unions in `kotoba/src/types.ts`, and with `--live`
  fetches every URL. Exits 0 clean / 1 findings / **2 refused**, so "could not
  check" is never reported as "checked and fine".
- `PROJECT.jsonld`, `README.edn`, `migration.edn`, `NOTICE` — declarations and
  provenance records.
- `appview/README.md` — placeholder for a staged App-services migration.

## What is *not* in this repo

Earlier revisions of this README described a `legacy-runtime/ti-collector-*`
ingest service and a `wasm/ti-ui-*/svelte` search UI, and gave a quickstart that
began by `cd`-ing into `60-apps/etzhayyim-project-threat-intelligence/…`.

Those components did not come across when this repo was extracted from
`etzhayyim/root` (see `migration.edn`), and none of those paths exist here. The
upstream source path recorded in `migration.edn` no longer resolves either. The
instructions were therefore unfollowable, and have been removed rather than left
in place to be discovered by whoever tried them next.

## Licence

Apache License 2.0 with the etzhayyim Charter Compliance Rider v3.1 — see
`NOTICE`.
