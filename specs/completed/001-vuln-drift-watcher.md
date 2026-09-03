---
status: completed
approved: "2026-09-03T18:25:30Z"
generating: "2026-09-03T18:25:31Z"
verifying: "2026-09-03T19:48:34Z"
completed: "2026-09-03T19:54:53Z"
branch: dark-factory/vuln-drift-watcher
---

## Summary

- A new scheduled Go watcher service (sibling of `github-update-go-watcher`, template `github-release-watcher`) that detects Go vulnerabilities published against **unchanged** dependencies — a repo's CI goes red with no code change — and emits one `github-update-go` create-task per affected repo for `github-update-go-agent` to fix.
- Each cycle it inventories the GitHub owner's repos, filters by allowlist + explicit `.maintainer.yaml: goUpdate.autoUpdate: true` consent, clones each consenting repo fresh, and runs the repo's **own** vuln gates (`make vulncheck` + `make check`) — reusing each repo's gates and suppression, never reimplementing a scanner.
- Findings are published to Kafka as `github-update-go` CreateTaskCommands under the frozen consumer contract, with a deterministic task identifier derived from (repo, sorted vuln IDs) — so unchanged finding sets go quiet and only finding-set changes produce new tasks.
- Service-side dedup via a persistent JSON cursor (atomic writes, corrupt-file recovery) keeps unfixable findings from spamming; the operator suppresses them via the repos' own `.trivyignore` / `.osv-scanner.toml` / `VULNCHECK_IGNORE`.
- Polling runs at a configurable interval (default 12h, latency ≤ 24h) with an immediate first cycle, a CycleGate against overlapping cycles, and a forced `/trigger` endpoint.

## Problem

Today the only vuln scan in the fleet is a manual slash command. When a new Go/CVE vulnerability is published against a dependency a repo already uses, the repo's CI gate (`make vulncheck` / `make check`) goes red **without any code change** — a drift event nothing in the fleet detects or reacts to. The `github-update-go-agent` dependency-update flow has no automated trigger for vuln findings, so unpatched dependencies ship and linger in prod until a human happens to run the manual scan. This watcher is the missing trigger: it detects the drift and files the work item the agent then fixes.

## Goal

After this work, a newly published vulnerability affecting any consenting, allowlisted repo under the configured GitHub owner is detected and filed as a `github-update-go` create-task within one poll interval (≤ 24h), without any human action. A repo whose finding set does not change is never re-filed, so unfixable findings surface exactly once per finding set and the operator's suppression is honored through the repo's own gates.

## Non-goals

- Not a vuln scanner: the watcher never invokes govulncheck/trivy/osv-scanner binaries directly, and never reimplements suppression (`VULNCHECK_IGNORE`, `.trivyignore`, `.osv-scanner.toml` are the repos' own gates' business).
- No auto-fix and no auto-suppression: unfixable findings are reported once (stable identifier), and suppression is operator-driven through the repos' own ignore files.
- Not webhook/event-driven: poll-primary only; no GitHub Actions or webhook subscription.
- No Kafka consumption: publish-only service.
- No multi-owner support: one GitHub owner per instance (mirrors the sibling).
- Deployment (Helm chart + quant deploy unit) is a separate step after merge — out of this spec's execution scope, but its verification commands are documented in the operator rung below. k8s manifest cleanup belongs to that deploy step: the stale `DATADIR` env entry in `k8s/*.yaml` is inert (struct-tag config ignores unknown envs) and is dropped there, NOT by the code prompts; the `/data` volume must be retained as the home of `CURSOR_PATH` (default `/data/cursor.json`).
- No new scenario: unit + integration tests reach the behavior (real `git` binary, fixture repo, mock sender) — see the four-condition test in `docs/rules/scenario-writing.md`.

## Acceptance Criteria

- [ ] `make precommit` exits 0 in the repo — evidence: exit code.
- [ ] The consent/allowlist inventory gates skip pre-clone with the named reasons: in the integration test, a fixture repo with no `.maintainer.yaml` and one with `goUpdate.autoUpdate: false` are both skipped with reason `auto_update_disabled`, and a repo outside `REPO_ALLOWLIST` is skipped with reason `scope`; the counter `filter_skipped_total{reason="auto_update_disabled"}` increments by 2 and `filter_skipped_total{reason="scope"}` by 1 during the run, and the test asserts no clone directory is created for any skipped repo — evidence: integration-test stdout + metric deltas + negative clone-dir check.
- [ ] The signal round-trip works end-to-end: the integration test clones a fixture repo whose own `make vulncheck` gate exits 1 with a known `GO-2024-XXXX` marker and asserts exactly one CreateTaskCommand is sent whose frontmatter `vulns` contains `GO-2024-XXXX` — evidence: captured command payload; an implementation that always concludes "no vulnerabilities" fails this AC.
- [ ] The published command matches the frozen 12-key emit contract: frontmatter `task_type=github-update-go`, `assignee=github-update-go-agent`, `phase=planning`, `status=in_progress`, `stage=<STAGE config>`, `task_identifier=<uuid5>`, title matching `Update Go <owner>-<repo> <sha[:7]>` with no `/`, `repo=<owner>/<repo>`, `clone_url=git@github.com:<owner>/<repo>.git`, `ref=<full 40-char HEAD sha>`, `vuln_count`, `vulns=<sorted id list>`; body contains header `# Update Go: <owner>/<repo>`, the vuln line with two-space middots, `**HEAD:** <sha[:7]>`, and `**Repo:** [<owner>/<repo>](https://github.com/<owner>/<repo>)` — evidence: integration-test assertions over the captured command; `grep -c '/' <title value>` returns 0.
- [ ] Dedup + cursor persistence: running the cycle twice against an unchanged fixture repo emits on the first run only — `published_total{status="create"}` increments by exactly 1 across the two runs and the second run produces no CreateTaskCommand (negative kafka evidence); the cursor file records `last_emitted_task_identifier` for the repo; a corrupt cursor file is renamed `<path>.corrupt` and the cycle still completes — evidence: metric delta == 1, `grep -n 'last_emitted_task_identifier' <cursor file>` returns ≥1, `<path>.corrupt` exists, `poll_cycle_total{result="success"}` increments.
- [ ] Trigger + CycleGate: a burst of N concurrent `/trigger` calls runs exactly one cycle — `poll_cycle_total` increments by exactly 1 over the burst window, and the CycleGate unit test asserts `TryAcquire` returns false while a cycle holds the slot — evidence: metric delta == 1 + unit-test outcome.
- [ ] Detection latency ≤ 24h: the service performs a scan cycle immediately at startup and at the configured interval thereafter, and the default `POLL_INTERVAL` is 12h — evidence: `grep -n 'POLL_INTERVAL' main.go` shows `default:"12h"`, and the watcher log contains a cycle-complete line within the first minute of startup.
- [ ] **Post-Deploy (Rung-2):** the deployed dev pod completes poll cycles — evidence: `curl -s https://dev.quant.benjamin-borbe.de/admin/github-vuln-watcher/metrics | grep 'github_vuln_watcher_poll_cycle_total{result="success"}'` returns a non-zero value. (Prerequisite: the separate Helm/quant deploy step for this repo has been performed.)
  - `deploy_check:` `kubectlquant -n dev get deploy/github-vuln-watcher -o jsonpath='{.spec.template.spec.containers[0].image}' | awk -F: '{print $NF}'`
  - `deploy_target:` `dev`

**Scenario coverage:** NO new scenario. Unit tests cover the filters, task builder, cursor, and classification; an integration test covers the dispatch path with a fixture repo (real `git` clone, real `make` invocation, mock sender) — the behavior is reachable without a real cluster, and no existing scenario is needed.

## Verification

### Container-executable (runs inside the YOLO container at prompt time)

```
make precommit
make test
grep -n 'github_vuln_watcher' pkg/metrics.go        # ≥1 hit — metric namespace present
grep -n 'vulns' pkg/taskbuilder.go                  # ≥1 hit — vuln payload fork present
grep -n 'last_emitted_task_identifier' pkg/cursor.go  # ≥1 hit — dedup state present
```

The integration test run must include the fixture-repo dispatch round-trip (`make test` covers it); its stdout must contain the fixture's `GO-2024-XXXX` id and the `filter_skipped_total` deltas from AC 2.

### Operator-executable (runs on the host after PR merge, spec verification ladder)

Prerequisite note: the Helm chart + quant deploy unit for this service is a **separate step after merge** and is outside this spec's execution scope. The rung below verifies the merged code once that deploy has happened.

```
BRANCH=dev make buca        # from the deploy worktree (github-vuln-watcher-dev) — separate deploy step
kubectlquant -n dev get pods   # github-vuln-watcher pod Running/Ready; the deploy manifest ships replicas: 0 — raise to ≥1 first, or the metrics curl below returns no non-zero counter
curl -s https://dev.quant.benjamin-borbe.de/admin/github-vuln-watcher/metrics | grep 'github_vuln_watcher_poll_cycle_total{result="success"}'
```

## Desired Behavior

1. **Scheduled poll loop.** The service runs one scan cycle immediately at startup, then on a ticker at `POLL_INTERVAL` (config, default 12h, must not exceed 24h). A `CycleGate` enforces exactly one cycle at a time — a cycle that cannot acquire the slot is dropped, not queued. Each cycle outcome is counted on `poll_cycle_total{result}` with the closed label set `success | rate_limited | github_error | scan_error`.
2. **Inventory + consent.** Each cycle lists the configured GitHub owner's repos via the GitHub-App installation. A repo is eligible only when (a) it matches `REPO_ALLOWLIST` (host-qualified `github.com/owner/repo`, comma-separated; empty = allow-all within OWNER), (b) its `.maintainer.yaml` at HEAD carries `goUpdate.autoUpdate: true` (absent file, absent section, absent key, or any other value = skip — positive opt-in only), and (c) it has a `go.mod` at HEAD. Ineligible repos are skipped before any clone, each with its named skip reason counted on `filter_skipped_total{reason}` (`scope | auto_update_disabled | no_gomod`).
3. **Signal.** For each eligible repo, clone fresh to an ephemeral directory (full clone via the `git` binary — not shallow — env allowlist `HOME`+`PATH`), then run the repo's own `make vulncheck` and `make check` capturing combined stdout+stderr; extract every `GO-\d+` and `CVE-\d+` marker, dedupe, and sort into a canonical list. Zero markers → skip with reason `already_clean`. A gate that fails to run or produces no classifiable output → skip with reason `scan_failed` (retried next cycle; a red gate with no vuln markers is not a vuln-drift signal). Each gate invocation is bounded by a hard 20-minute timeout → on expiry, kill the gate and skip with reason `gate_timeout`. The clone directory is removed when the repo's scan finishes. `VULNCHECK_IGNORE`, `.trivyignore`, and `.osv-scanner.toml` are applied by the repos' own gates — the watcher never parses or applies them.
4. **Emit.** For each repo with ≥1 marker, publish exactly one CreateTaskCommand to topic `agent-task-v1-request` (optional `TOPIC_PREFIX`) carrying the frozen 12-key contract (10 consumer keys byte-identical in semantics: `task_type=github-update-go`, `assignee=github-update-go-agent`, `phase=planning`, `status=in_progress`, `stage` from config, deterministic UUID5 `task_identifier`, dash-form `title`, `repo`, `clone_url=git@github.com:<owner>/<repo>.git`, `ref=<full HEAD sha>`; plus the vuln payload `vuln_count` and `vulns=<sorted id list>`) and the frozen body shape with the vuln line replacing the `Current Go/Latest Go` line. Publish outcomes are counted on `published_total{status=create|error}`. A failed publish does not advance the repo's cursor entry, so it retries next cycle.
5. **Dedup + cursor.** The service persists per-repo `last_emitted_task_identifier` in the JSON cursor at `CURSOR_PATH` (default `/data/cursor.json`). On each cycle, a repo whose computed task identifier equals the stored one is skipped with reason `finding_set_unchanged` — unchanged finding sets (including unfixable findings) are emitted exactly once, and the deterministic identifier makes any downstream repeat a no-op. Forced `/trigger` cycles bypass only this filter. Cursor writes are atomic (tmp file + rename); a corrupt cursor is renamed `<path>.corrupt` and the cycle cold-starts.
6. **Metrics + observability.** Prometheus namespace `github_vuln_watcher`; counters `poll_cycle_total{result}`, `published_total{status}`, `filter_skipped_total{reason}`, `repos_scanned_total`, and `vulns_detected_total` (increments by the number of markers found across a cycle). Metrics are created via an injected `prometheus.Registerer` (nil → `DefaultRegisterer`) with every label combination pre-initialised to 0 before the first cycle; the build-info metric is retained.
7. **HTTP surface.** Keep `/healthz`, `/readiness`, `/metrics`, `/setloglevel`, `/gc`, `/testloglevel`, `/sentryalert`. Add `/trigger` (POST) forcing an immediate cycle through the CycleGate. Remove the BoltDB dependency, the `/resetdb` and `/resetbucket` handlers, and the `DATADIR`/`BATCH_SIZE` config (the cursor is the JSON file, mirroring the sibling's removal of `boltkv`/`libkv`).

## Constraints

- **Frozen emit contract** (source of truth: `github-update-go-watcher` `pkg/taskbuilder.go`). The 10 consumer keys (`task_type`, `assignee`, `phase`, `status`, `stage`, `task_identifier`, `title`, `repo`, `clone_url`, `ref`) keep their semantics byte-identical. The fork documented by this spec: replace `current_go`/`latest_go` with `vuln_count` + `vulns`, and replace the `Current Go/Latest Go` body line with the vuln line; the header `# Update Go: <owner>/<repo>`, the two-space middot separation, the `**HEAD:** <sha[:7]>` line, and the `**Repo:** [<owner>/<repo>](https://github.com/<owner>/<repo>)` line stay byte-identical. The `github-update-go-agent` consumer must be able to parse the vuln payload — the task type and title form are unchanged, so its existing parse path applies.
- **Title form is frozen dash-form**: `Update Go <owner>-<repo> <sha[:7]>` — never a `/` (the CreateCommand validator rejects `/` and other forbidden characters in titles).
- **Task identifier** is a deterministic UUID5 (dedicated frozen namespace) seeded from `vuln-drift-<owner>-<repo>-<sorted-vuln-ids>` — over (repo, sorted vuln IDs), never over head SHA or timestamp. The vuln ID list is canonical (deduped + sorted) before hashing.
- **Consent gate is positive opt-in only**: `goUpdate.autoUpdate: true` is the only passing value.
- **`os/exec` is allowed ONLY for** (a) `git clone` and (b) invoking the repo's own `make vulncheck` / `make check`. Never shell out to a vuln scanner directly.
- **Full clone** (not shallow) with env allowlist `HOME`+`PATH`; gate subprocesses never receive the watcher's full environment.
- **No reimplementation of suppression**: `VULNCHECK_IGNORE`, `.trivyignore`, `.osv-scanner.toml` are honored only through the repos' own gates; the watcher neither reads them nor filters markers against them.
- **Kafka stack**: `github.com/bborbe/kafka` SyncProducer (`NewSyncProducerWithName`), `github.com/bborbe/agent/command/task` `CreateCommandSender` over `github.com/bborbe/cqrs/cdb`; topic `agent-task-v1-request` unprefixed, optional `TOPIC_PREFIX`.
- **Filter chain semantics**: `TaskCreationFilter { Skip(candidate) string }` — `""` = pass, non-empty = the metric-label skip reason; `TaskCreationFilterList` short-circuits on the first non-empty reason; `#counterfeiter:generate` per interface; filters live in `pkg/filter`, each with a `NewXxxFilter` constructor.
- **Cursor**: JSON at `CURSOR_PATH` (default `/data/cursor.json`); missing file = fresh empty; corrupt JSON = rename `<path>.corrupt` + cold start; save = marshal → write `<path>.tmp` (0600) → atomic rename. Per-repo state stores `last_emitted_task_identifier`. The cursor is single-writer (one cycle at a time, one instance).
- **Metrics**: namespace `github_vuln_watcher`, injected registerer, pre-initialised closed label sets. The metric names and label values in Desired Behavior 6 are frozen.
- **Package layout mirrors the sibling**: `pkg/auth`, `pkg/filter`, `pkg/factory`, `pkg/handler`, `pkg/watcher.go`, `pkg/taskbuilder.go`, `pkg/taskpublisher.go`, `pkg/cursor.go`, `pkg/metrics.go`.
- **Config style**: struct-tag config (`arg:`/`env:`/`required:`/`default:`/`usage:`). New surface: `OWNER` (required), `STAGE` (required, `dev|prod`), `REPO_ALLOWLIST` (optional, empty = allow-all within OWNER), `POLL_INTERVAL` (default 12h, ≤24h), `CURSOR_PATH` (default `/data/cursor.json`), `TOPIC_PREFIX` (optional), GitHub-App auth config mirroring the sibling's `pkg/auth`. `DATADIR` and `BATCH_SIZE` are removed. `LISTEN`, `SENTRY_DSN`, `SENTRY_PROXY`, build-info config remain.
- **Go version** as in the sibling (go 1.27.x).
- **Signal source is `Makefile.precommit`'s gates as they exist today**: `make vulncheck` runs govulncheck in JSON mode, honors `VULNCHECK_IGNORE`, and exits 1 printing `OSV\tmodule@version -> fixed_version\tsummary` lines on unignored findings; `make check = lint vet errcheck vulncheck osv-scanner gosec trivy`. The classification extracts markers from captured output; the `VULNCHECK_IGNORE` default list and the govulncheck known-benign panic handling are the repos' own business.
- Existing HTTP handlers and their behavior must not regress (dod.md governs prompt completion: `make precommit`, Ginkgo/Gomega, counterfeiter, `github.com/bborbe/errors` patterns).

## Failure Modes

| Trigger | Expected behavior | Detection | Reversibility | Concurrency |
|---|---|---|---|---|
| GitHub API rate limit during repo listing | Cycle aborts; retried next interval | `poll_cycle_total{result="rate_limited"}` increments + warning log | reversible | n/a (single instance, single owner) |
| GitHub API error (auth failure, installation revoked) | Cycle aborts; retried next interval | `poll_cycle_total{result="github_error"}` increments + warning log | reversible | n/a |
| `git clone` fails (repo deleted, network) | Repo skipped this cycle with reason `clone_failed`; other repos continue; retried next cycle | `filter_skipped_total{reason="clone_failed"}` + log | reversible | n/a |
| Gate hangs (e.g. `make vulncheck` stalls on network) | 20-minute per-gate timeout kills the gate; repo skipped `gate_timeout`; retried next cycle | `filter_skipped_total{reason="gate_timeout"}` + log | reversible | n/a |
| Gate exits non-zero with no vuln markers (lint/vet break, missing make) | Repo skipped `scan_failed`; not a vuln-drift signal; retried next cycle | `filter_skipped_total{reason="scan_failed"}` + log | reversible | n/a |
| Kafka publish fails | `published_total{status="error"}` increments; repo's cursor entry not advanced → re-emitted next cycle (deterministic identifier makes the repeat a downstream no-op) | metric + error log | reversible | n/a |
| Crash mid-cycle after partial emissions, before cursor save | Next cycle reloads the old cursor; repos already emitted with an unchanged finding set are skipped (`finding_set_unchanged`); emitted-but-unsaved repos re-emit once, absorbed downstream | process restart + log | partial | cursor is single-writer: atomic tmp+rename prevents torn files; one replica only |
| Cursor file corrupt | Renamed `<path>.corrupt`; cycle cold-starts; repos re-emit once, absorbed downstream | warning log + `.corrupt` file presence | reversible | n/a |
| Cursor unwritable (permissions, disk full) | Cycle aborts with `scan_error`; operator fixes the mount | `poll_cycle_total{result="scan_error"}` + error log | reversible | n/a |
| Consumer contract drift (`github-update-go-agent` changes payload) | CreateCommand validation fails at publish; every publish errors | `published_total{status="error"}` spike + error logs | irreversible (contract change — coordinated fix) | n/a |
| Disk exhaustion from clones | Per-repo clone dirs removed after each scan; on failure the cycle aborts `scan_error`; operator clears the data dir | metric + log | reversible | n/a |
| Clock skew on the pod | Interval timing drifts only; identifiers and cursor contain no wall-clock data — no correctness impact | n/a | n/a | n/a |

## Security / Abuse Cases

- **The service executes code from the scanned repos** (their `Makefile` via `make vulncheck` / `make check`). A compromised, forked, or malicious repo under OWNER can run arbitrary commands as the watcher's user. Mitigations, frozen as constraints: gate subprocesses receive only the allowlisted env (`HOME`, `PATH`) — never the pod's full environment containing Kafka/GitHub credentials; clone dirs are ephemeral and removed after each scan; the deployment must run the service as a non-root, non-privileged service account; no gate output is ever written back to any repo or persisted beyond logs and the cursor.
- **GitHub App token / private key** are used read-only (list repos, read `.maintainer.yaml`, `go.mod` presence) and must live in the pod via a secret; never logged.
- **Attacker-controlled strings entering task fields**: repo/owner names come from the GitHub API and must be validated against `[a-zA-Z0-9_.-]+` before entering frontmatter or the cursor; markers are extracted only via `GO-\d+` / `CVE-\d+` regexes, so a hostile gate output cannot inject arbitrary task content; the dash-form title blocks `/` injection (also rejected by the CreateCommand validator).
- **`/trigger`** exposes no input surface beyond forcing a cycle; it is gated and idempotent, and must not be exposed outside the cluster (admin-gateway-only, mirroring the sibling).
- **What can hang or retry forever**: gate subprocesses are bounded by the 20-minute hard timeout; SyncProducer publish returns an error on failure (no retry loop); the interval loop is the only retry and is the designed cadence.

## Suggested Decomposition

Prompts are generated in this order — each row is a single prompt with a clear scope.

| # | Prompt focus | Covers DBs | Covers ACs | Depends on |
|---|---|---|---|---|
| 1 | Service skeleton: config surface (add `OWNER`/`STAGE`/`REPO_ALLOWLIST`/`POLL_INTERVAL`/`CURSOR_PATH`/`TOPIC_PREFIX`; drop `DATADIR`/`BATCH_SIZE` + BoltDB + `/reset*`), poll loop + CycleGate + immediate first cycle + interval, `/trigger` handler, metrics scaffold (`poll_cycle_total`, `published_total`, `filter_skipped_total`, `repos_scanned_total`) | 1, 6, 7 | 1, 6, 7 | — |
| 2 | Inventory + filter chain: GitHub-App auth + repo listing client, allowlist / consent / go.mod-presence filters with metric labels and skip logging | 2 | 2 | prompt 1 |
| 3 | Signal stage: ephemeral full clone (env allowlist), repo's own `make vulncheck` + `make check` with 20-min gate timeout, `GO-\d+`/`CVE-\d+` marker classification into a canonical list | 3 | 3 | prompt 2 |
| 4 | Emit: taskbuilder vuln fork (frozen 12-key contract, `vuln_count`/`vulns`, dash title, body shape), deterministic UUID5 task id, taskpublisher + Kafka wiring (`agent-task-v1-request`, `TOPIC_PREFIX`), `vulns_detected_total` | 4 | 4 | prompts 1, 3 |
| 5 | Cursor + dedup + integration round-trip: JSON cursor (atomic persist, corrupt → `.corrupt`), `finding_set_unchanged` filter, fixture-repo dispatch integration test (evidence for ACs 3–5) | 5, 7 | 3, 4, 5 | prompts 3, 4 |

Rationale: prompt 1 establishes the loop skeleton every later layer plugs into; prompt 2 supplies the inventory the signal stage consumes; prompt 3 produces the classification the task builder needs; prompt 4 freezes the emit contract on top of that; prompt 5 closes the dedup loop and proves the whole dispatch path end-to-end with a fixture repo. AC 8 (post-deploy) is verified via the operator rung after the separate Helm/quant deploy step, not by any prompt.

## Do-Nothing Option

Today the only vuln scan is a manual slash command. New vulnerabilities published against unchanged dependencies remain invisible to the fleet until a human runs the scan or a bump happens to trip CI — the drift (CI red, zero code change) has no automated reaction, and `github-update-go-agent`'s update flow has no vuln trigger to feed it. Unpatched dependencies ship and linger in prod between manual scans; the gap widens as the repo count grows. The current manual-only approach is not acceptable as the only mechanism.

## Verification Result

**Verified:** 2026-09-03T19:54:10Z (HEAD 7437790)
**Binary:** worktree HEAD 7437790 (branch feature/vuln-drift-watcher); no deployed pod yet — AC8 verified-minus-live
**Scenario:** no scenario file (spec declares none); runtime replay = fixture-repo dispatch integration test (real git clone + real make gates, mock kafka sender) + full test suite
**Evidence:**
- `make precommit` exit 0; `make test` exit 0 (pkg: 92/92 specs pass, 0 fail)
- fixture dispatch: `fixture vuln marker: [GO-2024-1234 GO-2024-5678]`; 12-key contract asserted; published_total{status=create}=1
- inventory gates: `filter_skipped_total auto_update_disabled=2 scope=1`; ScanCallCount=1 — no clone for skipped repos
- dedup: `filter_skipped_total finding_set_unchanged=1`; 2nd cycle emits 0; cursor records `last_emitted_task_identifier`; corrupt cursor -> `.corrupt` + cycle success
- greps: pkg/metrics.go:33 `github_vuln_watcher`; pkg/taskbuilder.go:38,70 `vulns`; pkg/cursor.go:35 `last_emitted_task_identifier`; main.go:46 `POLL_INTERVAL` default:"12h"
**Verdict:** PASS (AC8 Post-Deploy deferred per spec Non-goals — verified-minus-live; follow-up: operator rung after Helm/quant deploy)
