# Operator quickstart

Get the one runnable thing in this repo — the `kotoba/` IOC registry reference
implementation — installed, typechecked, and under test.

Every command below was walked end to end on 2026-08-20 (Darwin 25.3.0, arm64,
`node v26.3.0` / `npm 11.16.0`). The outputs quoted are the outputs observed,
not expected values written from the source.

## What is actually in this repo

`kotoba/` — a TypeScript reference implementation of a public IOC (Indicator of
Compromise) registry on the etzhayyim substrate (AT PDS records, no read-write
vendor DB). Four exported operations, in `kotoba/src/registry.ts`:

| operation | what it does |
|---|---|
| `registerIndicator` | register an IOC; rkey is `{type}_{djb2(value)}`, so it is idempotent on the normalized `(type, value)` |
| `getIndicator` | look one up by `(type, value)` |
| `listIndicators` | cursor paging + filter by type / TLP / source / min confidence |
| `coverage` | counts by type, TLP, and source |

Records land in the collection `com.etzhayyim.apps.threatIntelligence.indicator`.
Indicator types are `ipv4 ipv6 domain url md5 sha1 sha256 email cve`; confidence
is carried as **permille** (0–1000 integer) because the AT Lexicon has no float.

Nothing else in the repo executes. `PROJECT.jsonld`, `README.edn`, `NOTICE`, and
`migration.edn` are declarations; `appview/README.md` is a migration placeholder.

## 1. Install

```bash
cd kotoba
npm install
```

Took **about 4 minutes** and added **135 packages** — the dependency tree is
pulled from git, not a registry, and several packages build themselves via a
`prepare: tsc` step.

> **If this fails with `EALLOWSCRIPTS`, the cause is your user-level npm config,
> not this repo.** npm ≥ 11 refuses `allow-scripts` in a project-scoped install,
> and preparing a git dependency runs exactly such an install. If your
> `~/.npmrc` sets `allow-scripts[]=...` for anything, that entry is inherited
> and the install dies with:
>
> ```
> npm error code EALLOWSCRIPTS
> npm error --allow-scripts is not allowed in project-scoped installs.
> ```
>
> Confirm the diagnosis, and get unblocked, by ignoring the user config for the
> one command: `npm install --userconfig /dev/null`. Do not "fix" this by adding
> an `allowScripts` field to `kotoba/package.json` — the repo installs cleanly
> on a machine without that user-level entry, so a committed workaround would be
> encoding one workstation's configuration into the project.

Install leaves two untracked paths behind: `kotoba/node_modules/` (gitignored)
and `kotoba/package-lock.json`. The lockfile is deliberately *not* ignored —
whether to commit it is an open project decision, and silently ignoring it would
be making that decision by omission. The direct dependencies are already pinned
by commit SHA in `kotoba/package.json`.

A successful install prints a warning listing 8 packages whose install scripts
are not yet covered by `allowScripts` (7 × `@etzhayyim/*` with `prepare: tsc`,
plus `@signalapp/libsignal-client`). That warning is advisory in npm 11 and does
not stop the install.

## 2. Typecheck

```bash
npm run typecheck      # tsc --noEmit
```

Exits 0 and prints nothing beyond the npm banner. `tsconfig.json` is `strict`,
but only `src/**/*.ts` is in `include`.

**`test/` is therefore typechecked by nothing.** vitest transpiles TypeScript
with esbuild, which strips types without checking them — verified by adding a
test file containing `const bad: number = isValidIndicator("ipv4", "8.8.8.8")`
(a `boolean`) and watching `npm test` report `11 passed` rather than an error.
If you want the test file covered, widen `include` in `kotoba/tsconfig.json`;
this quickstart records the gap rather than silently implying it is covered.

## 3. Test

```bash
npm test               # vitest run
```

Observed:

```
 Test Files  1 passed (1)
      Tests  10 passed (10)
   Duration  312ms
```

The suite (`kotoba/test/threat-intelligence.test.ts`) runs against
`@etzhayyim/sdk-mock`, an in-memory substrate — **no network, no PDS, and no
credentials are needed to run it.** It covers per-type validation and
normalization, rkey stability, register defaults (`amber`, 500‰), confidence
clamping to 0–1000, idempotency on the normalized value, rejection of invalid
indicators, list filtering, and coverage aggregation.

## 4. Confirm the test step is a real check

A test run you have never seen fail tells you nothing. Break one behaviour and
confirm the suite reports *that* behaviour:

```bash
cp kotoba/src/types.ts /tmp/types.ts.bak
# make CVE normalization stop upper-casing
sed -i '' 's|if (type === "cve") return v.toUpperCase();|if (type === "cve") return v;|' kotoba/src/types.ts
( cd kotoba && npm test )
cp /tmp/types.ts.bak kotoba/src/types.ts        # restore
```

Observed with the mutation in place:

```
 FAIL  test/threat-intelligence.test.ts > ... > normalizes case for case-insensitive types
AssertionError: expected 'cve-2026-1234' to be 'CVE-2026-1234'
 Test Files  1 failed (1)
      Tests  1 failed | 9 passed (10)
```

and after restoring, `10 passed (10)` again. The failure names the behaviour
that was actually mutated, so the suite discriminates rather than merely
running.

## 5. Check the source catalog

`catalog.edn` names the public feeds a collector for this registry may draw
from, keyed by the exact string to write into `IndicatorRecord.source`. It
exists because `coverage()` groups by `source` and nothing defined what a
`source` was, so `bySource` could report counts for names no one had agreed on.

```bash
nbb scripts/verify-catalog.cljs           # structure only, no network
nbb scripts/verify-catalog.cljs --live    # also fetch every URL
```

`nbb` is the only extra tool required, and only for this step; `npx --yes nbb`
works if you do not have it installed (verified, `nbb v1.5.212`).

Observed on 2026-09-01:

```
$ nbb scripts/verify-catalog.cljs
SCANNED	12 sources
VOCABULARY	9 indicator types, 4 TLP classes, from kotoba/src/types.ts
OK — every source is well-formed (structure only; pass --live to fetch)

$ nbb scripts/verify-catalog.cljs --live
SCANNED	12 sources, 24 URLs fetched
VOCABULARY	9 indicator types, 4 TLP classes, from kotoba/src/types.ts
OK — every source is well-formed and every URL served a payload
```

The exit code is three-valued, and the third value is the reason this script is
worth running:

| exit | meaning |
|---|---|
| 0 | checked, nothing wrong |
| 1 | checked, findings printed |
| 2 | **REFUSED** — could not check (catalog missing or unreadable, `types.ts` missing, its unions unparseable) |

A check that cannot run must not return the value of a check that ran and found
nothing. Exit 2 exists so that "I could not look" never accumulates as green.

The `VOCABULARY` line is the other half: the allowed indicator types and TLP
classes are parsed out of the `IndicatorType` and `Tlp` unions in
`kotoba/src/types.ts`, not written down a second time in the verifier. Rename a
member in `types.ts` and the catalog entries using it become findings.

### Why `--live` counts payload lines instead of trusting the status code

The catalog was assembled by fetching fifteen candidate feeds and keeping the
ones that answered. Three were dropped, and **only one of the three was caught
by looking at the status code**:

| candidate | status | what it actually served |
|---|---|---|
| `osint.digitalside.it/…/latestdomains.txt` | connection failure | — |
| `botvrij.eu/data/ioclist.domain` | **200** | 6 lines, all comments |
| `sslbl.abuse.ch/blacklist/sslipblacklist.csv` | **200** | 13 lines, all comments, including `ATTENTION: This list has been deprecated on 2025-01-03` |

The SSLBL entry was written into the catalog by hand after an eyeball check of
the first 220 bytes — which showed a normal-looking abuse.ch CSV banner — and
was removed only because `--live` reported `[empty-feed]` on it. A feed that has
stopped carrying indicators answers a reachability check exactly like one that
never stopped, so reachability alone is not the check.

Feodo Tracker is still listed and still carries entries, but its own
`Last updated` header was about six months behind the fetch date; its
`:source/note` says so.

## 6. Confirm the catalog check is a real check

As with the test suite, break it and watch it name what you broke:

```bash
cp catalog.edn /tmp/catalog.edn.bak
sed -i '' 's|:source/format :jsonl|:source/format :parquet|' catalog.edn
nbb scripts/verify-catalog.cljs          # → [format] …, exit 1
cp /tmp/catalog.edn.bak catalog.edn      # restore
```

Seventeen mutations were run against isolated copies on 2026-09-01, one per
finding kind, plus an unmutated control. Every one produced *its own* finding
rather than merely a non-zero exit, and the control exited 0:

```
PASS  control (structural, unmutated) exit=0
PASS  catalog absent                            → exit=2 REFUSED
PASS  catalog is broken EDN                     → exit=2 REFUSED
PASS  catalog is not a vector                   → exit=2 REFUSED
PASS  catalog is empty                          → exit=2 REFUSED
PASS  types.ts absent                           → exit=2 REFUSED
PASS  IndicatorType union unparseable           → exit=2 REFUSED
PASS  duplicate :source/id                      → exit=1 [duplicate-id]
PASS  required key removed                      → exit=1 [missing-key]
PASS  id is not dash-lowercase                  → exit=1 [id-shape]
PASS  feed url downgraded to http               → exit=1 [url-shape]
PASS  unknown :source/format                    → exit=1 [format]
PASS  TLP class outside the Tlp union           → exit=1 [tlp]
PASS  indicator type outside IndicatorType      → exit=1 [indicator-type]
PASS  types.ts renames a member the catalog uses → exit=1 [indicator-type]
PASS  feed URL 404s                             → exit=1 [url-dead]
PASS  homepage 404s                             → exit=1 [homepage-dead]
PASS  feed 200s but is header-only              → exit=1 [empty-feed]
```

The last structural case is the one worth keeping: renaming `"cve"` to
`"vuln"` in `kotoba/src/types.ts` — touching the implementation, not the
catalog — turns the CVE sources into `[indicator-type]` findings. That is the
evidence that the vocabulary is genuinely read from the code and not a copy
that agrees with it today.

## Known gap — the collector and UI are not in this repo

The top-level `README.md` used to describe a `legacy-runtime/ti-collector-*`
service and a `wasm/ti-ui-*/svelte` front end, with a quickstart that `cd`s into
`60-apps/etzhayyim-project-threat-intelligence/…`. **None of those paths exist
here.** This repo was extracted from `etzhayyim/root` (see `migration.edn`) and
only the `kotoba/` slice came across; the source path named in `migration.edn`
no longer resolves upstream either. Treat the collector and UI as absent, not as
something you have failed to find.

`catalog.edn` does not close this gap — it is the collector's input list, not
the collector. It says which public feeds a collector *would* read and what
each one actually carries; nothing in this repo fetches them except
`scripts/verify-catalog.cljs`, which checks that they answer and then throws
the payload away.
