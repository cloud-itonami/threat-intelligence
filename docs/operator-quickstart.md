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

## Known gap — the collector and UI are not in this repo

The top-level `README.md` used to describe a `legacy-runtime/ti-collector-*`
service and a `wasm/ti-ui-*/svelte` front end, with a quickstart that `cd`s into
`60-apps/etzhayyim-project-threat-intelligence/…`. **None of those paths exist
here.** This repo was extracted from `etzhayyim/root` (see `migration.edn`) and
only the `kotoba/` slice came across; the source path named in `migration.edn`
no longer resolves upstream either. Treat the collector and UI as absent, not as
something you have failed to find.
