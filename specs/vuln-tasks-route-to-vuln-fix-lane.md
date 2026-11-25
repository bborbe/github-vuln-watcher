---
status: draft
---

## Summary

- Every task this watcher emits is stamped `assignee: github-update-go-agent`, so vuln work competes for the **single** `maxConcurrentJobs: 1` slot that routine dependency updates already saturate.
- A dedicated `vuln-fix-agent` lane exists on nuke dev (`bborbe/nuke` `agent/values-dev.yaml`, added 2026-09-16) with its own `concurrency: 1` ResourceQuota, `taskTypes: [github-update-go, healthcheck]` and the same `github-update-go-agent` image. Its own values file states the contract: *"PRODUCER CONTRACT: the scanner watcher must stamp `assignee: vuln-fix-agent`"*.
- That contract was never wired. The lane has received **zero watcher-produced vuln tasks**; the one task it has ever run is a manual `task_type: healthcheck` probe, which proves the lane is reachable and the producer is the missing half.
- The fix is one value in `pkg/taskbuilder.go`'s `buildFrontmatter`, plus the two tests that assert it, the README line that describes it, and a `CHANGELOG.md` bullet.

## Problem

The watcher's entire product is the emitted task. Its purpose is to detect a Go advisory published against a dependency a repo already uses — a drift event where CI goes red with no code change — and file the work item that fixes it.

That work item currently lands on the same lane as the monthly routine dependency bump. The updater lane runs one job at a time, so a vuln finding waits behind whatever bulk update is in flight, and during a fleet-wide update window it can wait a long time. The dedicated lane was created precisely to remove that queueing and has been idle since it was created, because nothing routes to it.

The failure is silent in the direction that matters: the emitted task is valid, published and claimed — just by the wrong lane. No metric, log line or alert distinguishes "vuln task queued behind an update" from "vuln task being worked".

## Goal

Every task this watcher emits carries `assignee: vuln-fix-agent`, so vuln work is claimed by the lane that was built for it.

## Desired Behavior

1. `buildFrontmatter` stamps `assignee: vuln-fix-agent`.
2. The remaining eleven frontmatter keys are byte-identical to today — `task_type` stays `github-update-go` (the lane claims that task type), `title`, `phase`, `status`, `stage`, `task_identifier`, `repo`, `clone_url`, `ref`, `vuln_count` and `vulns` are untouched.
3. The body shape is untouched, so the consumer's existing parse path still applies.
4. The frontmatter key count stays 12 — this changes a value, never adds or removes a key.
5. Both tests that assert the assignee assert the new value, so the contract is pinned rather than merely edited.

## Expected vs Actual

| Aspect | Expected | Actual |
|---|---|---|
| `Frontmatter["assignee"]` on an emitted task | `vuln-fix-agent` | `github-update-go-agent` |
| Lane that claims a vuln task | `vuln-fix-agent` (own concurrency slot) | `github-update-go-agent` (single shared slot) |
| Operator-visible signal that routing is wrong | n/a — the emitted task is valid | none: the task publishes, validates and is claimed |

## Constraints

- **The frontmatter contract is frozen at 12 keys.** `pkg/taskbuilder_test.go` asserts `HaveLen(12)` and the dispatch integration test asserts the same; this change must not alter the count.
- **`task_type` stays `github-update-go`.** The `vuln-fix-agent` lane's `taskTypes` includes `github-update-go`; changing the task type would match no lane and the task would be claimed by nobody.
- **No new config field, no new flag.** The assignee is a fleet-wide routing constant, not per-deployment configuration. A configurable assignee would let dev and prod diverge silently, which is the class of bug this change fixes.
- **No change to the task identifier, title, body or dedup cursor.** The UUID5 seed is `(repo, sorted vuln IDs)`; the cursor keys on it. Changing anything upstream of the identifier would re-emit every finding set fleet-wide.
- **The change touches `pkg/taskbuilder.go`, `pkg/taskbuilder_test.go`, `pkg/dispatch_integration_test.go`, `README.md` and `CHANGELOG.md`.** No other package.
- **Rollout order is not part of this spec, and it is load-bearing.** The `vuln-fix-agent` lane exists on **dev only**. Deploying this watcher build to a stage that has no `vuln-fix-agent` lane would stamp an assignee nothing claims, so vuln tasks would be published and never worked — strictly worse than today. The nuke pin bump and the prod lane's creation are owned by the consuming vault task; this spec only guarantees what the watcher stamps.

## Assumptions

All four hold today and were read from the live configuration, not recalled; they are the safety argument for the change, so a future reader can re-check each one.

1. **The `vuln-fix-agent` lane exists on nuke dev only.** `bborbe/nuke` `agent/values-dev.yaml` defines it; `agent/values-prod.yaml` contains no `vuln-fix-agent` entry (grep count 0).
2. **The lane claims `github-update-go`.** Its `taskTypes: [github-update-go, healthcheck]`, so the watcher's unchanged `task_type` matches it.
3. **The controller routes on `assignee` alone.** It matches the task's `assignee` against a lane's own `assignee` value; nothing downstream compares the literal string `github-update-go-agent`.
4. **The lane is reachable.** A manual `task_type: healthcheck` task assigned to `vuln-fix-agent` completed there, so the lane accepts and runs tasks — the producer's stamp is the only missing half.

## Failure Modes

| Trigger | Expected behavior | Recovery | Detection |
|---|---|---|---|
| Watcher deployed to a stage with no `vuln-fix-agent` lane | Tasks are published with an assignee nothing claims; they sit unclaimed | Add the lane to that stage's `agent/values-*.yaml` and apply, or roll the watcher back | An emitted task whose `assignee` names a lane absent from the stage's Config |
| Lane present but its `taskTypes` drops `github-update-go` | Task matches no lane and is never claimed | Restore `github-update-go` to the lane's `taskTypes` | Emitted task unclaimed past its heartbeat |
| A consumer asserts the old assignee | Nothing in the fleet reads the value — the controller routes on `assignee` alone, and no code matches the literal `github-update-go-agent` | n/a | `grep -rn 'github-update-go-agent'` over the fleet repos |

## Acceptance Criteria

**Scenario coverage:** none. This is a constant change whose boundary — the emitted frontmatter — is fully reachable from the unit and dispatch integration tests that already assert the contract; a scenario would add no signal.

- [ ] `buildFrontmatter` stamps the vuln lane — evidence: `pkg/taskbuilder_test.go`'s `stamps the 10 consumer keys byte-identical to the sibling` asserts `cmd.Frontmatter["assignee"]` equals `vuln-fix-agent`, and `make test` exits 0.
- [ ] The dispatch path emits the same value end to end, not only the builder in isolation — evidence: `pkg/dispatch_integration_test.go`'s publish assertion reads `cmd.Frontmatter["assignee"]` as `vuln-fix-agent` after a real `Poll`, and `make test` exits 0. (Guards the lazy "change the builder, leave the integration assertion green against the old value" implementation.)
- [ ] The frontmatter key count is still exactly 12 — evidence: the existing `HaveLen(12)` assertions in both test files still pass with no edit to the count, and `make test` exits 0. (Guards the lazy "add a second assignee key" implementation.)
- [ ] `task_type` is unchanged — evidence: both tests still assert `github-update-go`, and `grep -c '"task_type":       "github-update-go"' pkg/taskbuilder.go` returns `1`.
- [ ] No Go file still names the old lane — evidence: `grep -rn 'github-update-go-agent' --include='*.go' .` prints nothing.
- [ ] The README describes the lane the watcher actually targets — evidence: `grep -n 'vuln-fix-agent' README.md` prints the line describing the emitted task's consumer.
- [ ] `CHANGELOG.md` carries the change under a new `## Unreleased` heading — evidence: `awk '/^## /{sec=$0} /vuln-fix-agent/{print sec}' CHANGELOG.md` prints `## Unreleased`.
- [ ] `make precommit` exits 0.

## Verification

### Container-executable (runs inside the YOLO container at prompt time)

- `make precommit` — format, lint, test and security checks clean
- `make test` — unit + dispatch integration suite passes
- `grep -n '"assignee"' pkg/taskbuilder.go` — prints `vuln-fix-agent`
- `grep -rn 'github-update-go-agent' --include='*.go' .` — no hit outside spec/prompt history
- `grep -n 'vuln-fix-agent' README.md` — the consumer line names the lane

### Operator-executable (runs on the host after PR merge)

- `/coding:github-release` from the repo checkout — cuts the tag the nuke pin will reference
- The consuming vault task then bumps the nuke pin and creates the prod lane; behaviour on a stage is verified there, not here

## Security / Abuse Cases

None. The value is a fixed identifier compared against a lane's own `assignee` by the task controller; it is not user input, not a credential, and it does not reach a filesystem path. The routing authority remains the controller's own Config matching — this change only changes which existing lane matches.

## Suggested Decomposition

One prompt. The value, its two test assertions and the README line are indivisible: any subset leaves the repo asserting a lane it does not stamp, which is the exact state this spec exists to end.

| # | Prompt focus | Covers DBs | Covers ACs | Depends on |
|---|---|---|---|---|
| 1 | Stamp `vuln-fix-agent` in `buildFrontmatter`; update both test assertions, README and CHANGELOG | 1-5 | 1-8 | — |

## Non-goals

- Adding the `vuln-fix-agent` lane to nuke prod, and bumping the dev/prod pins — owned by the consuming vault task.
- The `github-update-go-agent` release that carries the targeted vuln-scoped mode (`v0.27.0`) — already shipped.
- Targeted bump logic and the monthly full-update cadence — separate tasks.
- Auto-merge for vuln PRs — deliberately human-merged.

## Do-Nothing Option

Not tolerable. The dedicated lane was created to stop vuln fixes queueing behind routine updates and has been idle since 2026-09-16 because the producer never adopted the contract its own values file documents. Leaving it unwired means the concurrency slot exists on paper only, and every vuln finding keeps waiting behind a bulk dependency update — while the system reports a healthy watcher and a busy updater.

## Related

- Lane definition and the producer-contract comment: `bborbe/nuke` `agent/values-dev.yaml` (`vuln-fix-agent`).
- The line this change edits: `pkg/taskbuilder.go` `buildFrontmatter`.
- Frozen contract origin: `specs/completed/001-vuln-drift-watcher.md` § Constraints.
- Consumer: `github-update-go-agent` (same image), reached through the `vuln-fix-agent` lane.
