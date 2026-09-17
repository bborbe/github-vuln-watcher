---
status: approved
approved: "2026-09-17T07:53:31Z"
branch: dark-factory/bug-create-task-missing-target-vault
---

## Summary

- The watcher never stamps a target vault on the tasks it publishes, so the controller silently drops every one of them. The setting does not exist on the watcher's own task config — the fleet's `TARGET_VAULT` value is read by nobody.
- The controller `agent-task-controller` runs with `VAULT_NAME=agent`. Its `routing.ShouldProcess` resolves an empty `TargetVault` to `routing.LegacyDefaultVault` (`openclaw`), which is not `agent` — so the command is **skipped with no git write, no error event and no result event**. The task the watcher just published disappears.
- The fleet already configures the value: the octopus unit sets `TARGET_VAULT=agent` on the watcher pod, and `maintainer/values-dev.yaml` documents that it "stamps CreateTaskCommand.TargetVault → controller vaultName=agent". The binary has no config field for it, so the env var is inert.
- The sibling `github-release-watcher` implements exactly this contract — a `TARGET_VAULT` config field, threaded into `CreateWatcher`, carried on `TaskConfig`, stamped by `BuildCreateCommand`. Its commands land; this watcher's do not.
- Live proof from dev, 2026-09-17 07:23Z: the cycle emitted `taskID=8d91521b-f93b-5acb-bceb-2ba1ee6c5f42`; the controller logged `create-task: skipped vault mismatch target="" effective="openclaw" vault="agent"` and created no task file.

## Problem

The emit stage is the watcher's entire product: it clones each consenting repo, runs the repo's own vuln gates, extracts `GO-`/`CVE-` markers and publishes one `github-update-go` task per finding set. Every one of those steps now works on dev — the private clone succeeds, both gates run, and the marker set is extracted correctly. The task is then published to Kafka successfully and silently dropped one hop later.

The failure is invisible from the watcher's side: `published_total{status="create"}` increments, the cursor records the task identifier as emitted, and the poll cycle reports `success`. Nothing retries, because from the watcher's perspective the work is done. The finding set is now marked as emitted, so the per-repo dedup filter skips it forever — the repo reports zero vulns to the operator while `govulncheck` finds two.

## Why this is a bug

The vault is a **routing contract**, not an optional decoration. The controller compares the command's `TargetVault` against its own `VAULT_NAME` and refuses to materialise a task on mismatch; an empty value silently resolves to a legacy default that is wrong for every fleet deployment. Both halves of the contract are already written down — the producer side in the octopus manifests, the consumer side in the controller — and only the producer's implementation is missing. A missing implementation that fails *silently* (no error event, no metric, no retry) is the worst variant: the operator sees a healthy watcher and an empty task queue.

## Goal

Every `CreateTaskCommand` the watcher publishes carries the vault slug the operator configured, so the controller materialises the task.

Behavioral end-state:

1. A `TARGET_VAULT` setting exists on the binary, optional, empty by default.
2. When set to a valid slug, every emitted command carries it as `TargetVault`.
3. When unset, the emitted command marshals byte-identically to today's — the field stays empty and `omitempty` omits it from the wire.
4. The configured value is named in the startup log, so a deployed pod's configuration is observable without waiting for a publish.
5. A slug failing the `^[a-z][a-z0-9-]*$` rule is rejected by the existing `CreateCommand.Validate` before the send touches Kafka, exactly as it is for the sibling.
6. The stamping happens at exactly one site (`BuildCreateCommand`), so `TaskConfig` and the sender's `defaultVault` cannot disagree.

## Expected vs Actual

| Aspect | Expected | Actual |
|---|---|---|
| `CreateCommand.TargetVault` after `BuildCreateCommand` | the configured slug (e.g. `agent`) | always empty |
| Controller outcome | `create-task: created task file at tasks/…` | `create-task: skipped vault mismatch target="" effective="openclaw" vault="agent"` |
| Operator-visible signal on mismatch | an error, a metric, or a retry | none — `published_total{status="create"}` increments and the cycle reports `success` |
| Re-emit of the same finding set | not attempted (dedup) | not attempted — the cursor recorded the identifier of a task that never existed |

## Reproduction

Repo: any deployment of `github-vuln-watcher` against a controller whose `VAULT_NAME` is not the legacy default.

1. Configure the watcher with `OWNER`, `REPO_ALLOWLIST` and a repo whose own `make vulncheck` reports at least one `GO-` marker.
2. Do **not** rely on `TARGET_VAULT` having an effect — the binary ignores it.
3. Let one poll cycle run. The watcher logs `published CreateTaskCommand repo=… taskID=… stage=…` and the cycle completes `result=success`.
4. Observe the controller's log for that task identifier.

**Observed on dev, 2026-09-17 07:23Z** (`kubectldev -n agent`):

- `watcher-github-vuln-0`: `published CreateTaskCommand repo=github.com/Seibert-Data/test-dev taskID=8d91521b-f93b-5acb-bceb-2ba1ee6c5f42 stage=dev`
- `agent-task-controller-0`: `create-task: skipped vault mismatch target="" effective="openclaw" vault="agent" task=8d91521b-f93b-5acb-bceb-2ba1ee6c5f42`
- No `tasks/…` file for `8d91521b…` was created; the next cycle logged `repo skipped … reason=finding_set_unchanged`.

The finding set is independently confirmed: `DeriveVulnTaskID("Seibert-Data", "test-dev", ["GO-2021-0113", "GO-2022-1059"])` reproduces `8d91521b-f93b-5acb-bceb-2ba1ee6c5f42` exactly, so the dropped task carried precisely those two markers.

## Root cause

Three omissions, all in the producer:

1. `main.go` — the `application` config struct has no `TARGET_VAULT` field, so the env var the octopus unit sets is never read.
2. `pkg/factory/factory.go` — `CreateWatcher` takes no vault argument, and builds `pkg.TaskConfig{Stage: stage}`.
3. `pkg/taskbuilder.go` — `TaskConfig` has no `TargetVault` field and `BuildCreateCommand` returns a `task.CreateCommand` literal without `TargetVault`.

The sibling `github-release-watcher` closes all three: `main.go` declares `TargetVault string` with `env:"TARGET_VAULT"`, `CreateWatcher` accepts it, `TaskConfig` carries it, and `BuildCreateCommand` sets `TargetVault: cfg.TargetVault`.

## Constraints

- **One stamping site.** `CreateKafkaSender` continues to pass `""` to `task.NewCreateCommandSender`, mirroring the sibling. The vault is stamped in `BuildCreateCommand` from `TaskConfig` only. Stamping in both places would let them diverge silently.
- **Empty must stay byte-identical.** `CreateCommand.TargetVault` is `json:"targetVault,omitempty"`; an empty value must keep producing a payload with no `targetVault` key, so legacy producers and existing tests are unaffected.
- **Field shape mirrors the sibling** — `required:"false"`, `arg:"target-vault"`, `env:"TARGET_VAULT"`.
- **No new dependency, no new exported type.** `TaskConfig` gains one string field; `CreateWatcher` gains one string parameter.
- **Existing tests keep passing.** The 12-key frontmatter contract, the UUID5 identifier, the dash-form title and the body are all unchanged.
- The change touches three files (`main.go`, `pkg/factory/factory.go`, `pkg/taskbuilder.go`) plus tests and `CHANGELOG.md`; no other package changes.
- The vault slug reaches a file path on the controller side (`tasks/{title}.md`), so the existing `^[a-z][a-z0-9-]*$` validator is the security boundary that matters — it is already in place and must not be loosened.

## Failure Modes

| Trigger | Expected behavior | Recovery | Detection |
|---|---|---|---|
| `TARGET_VAULT` unset | `TargetVault` empty, key omitted from the wire, controller falls back to its legacy default exactly as today | None — unchanged behaviour | No regression vs today |
| `TARGET_VAULT` set to an invalid slug (`Agent!`, `agent_x`) | `SendCommand` returns a validation error before Kafka; `published_total{status="error"}` increments and the cursor does **not** advance, so the next cycle retries | Operator corrects `TARGET_VAULT` in the octopus values file, re-applies to dev and restarts the pod; recovery confirmed by a `created task file` line for a fresh identifier | `publish create-task failed … err=…targetVault … must match` in the watcher log |
| `TARGET_VAULT` set to a slug no controller owns | Command is skipped by that controller; with no matching consumer it is dropped as before | Operator sets `TARGET_VAULT` to the controller's own `VAULT_NAME` (`agent`), re-applies and restarts; recovery confirmed by a `created task file` line | Absence of a `created task file` line, plus a `skipped vault mismatch` line naming a non-empty `target` |
| Publish succeeds but the task still does not materialise | Out of this spec's scope — this spec guarantees the command *carries* the vault, not that the consumer accepts it | Operator inspects the controller log for the identifier | `skipped vault mismatch` line naming a non-empty `target` |

## Acceptance Criteria

**Scenario coverage:** none. This is a config-field plumbing change whose boundary (the `CreateCommand` validator and its JSON serialisation) is reachable from unit and dispatch integration tests; a scenario would add no signal.

- [ ] `BuildCreateCommand` stamps `TaskConfig.TargetVault` onto the command — evidence: `pkg/taskbuilder_test.go` carries a Ginkgo spec `stamps the target vault config from the task config` asserting `cmd.TargetVault` equals a non-default slug, and `make test` exits 0.
- [ ] An empty `TaskConfig.TargetVault` leaves the command's field empty **and** absent from the serialised wire form — evidence: a spec asserting `json.Marshal(cmd)` does not contain the substring `targetVault` when the config field is empty. (Guards the lazy "hardcode `agent`" implementation.)
- [ ] A populated `TargetVault` survives the real publish path — evidence: the dispatch integration test unmarshals the command object handed to the fake sender and asserts its `targetVault` equals the configured slug.
- [ ] The binary reads `TARGET_VAULT` — evidence: `grep -c 'env:"TARGET_VAULT"' main.go` returns `1`.
- [ ] The configured value reaches the publisher rather than being dropped at the wiring seam — evidence: a source-text guard test in `main_test.go` asserting the `factory.CreateWatcher(...)` call passes the config's vault field, and `make test` exits 0. (Guards the lazy "add the config field, pass nothing" implementation.)
- [ ] The startup log names the configured vault — evidence: `grep -c 'vault=%s' main.go` returns `1`, **and** `main_test.go` asserts that same source line's argument list names the config field — so a `vault=%s` fed an empty or hardcoded argument fails.
- [ ] A configured invalid slug is rejected before anything reaches Kafka — evidence: a spec asserting `BuildCreateCommand(candidate, TaskConfig{TargetVault: "Agent!"}).Validate(ctx)` returns a non-nil error, so the stamping cannot introduce a slug the validator would refuse.
- [ ] `TARGET_VAULT` unset is still a valid configuration — evidence: a spec asserting the watcher constructs with the field empty and `make test` exits 0.
- [ ] `make precommit` exits 0.
- [ ] **Post-Deploy (Rung-2):** the deployed dev watcher stamps the vault, and a task it emits materialises instead of being dropped — evidence: `kubectldev -n agent logs agent-task-controller-0 --since=30m | grep 'create-task: created task file'` prints a line naming a `tasks/Update Go …` file, where before this change the same log carried `create-task: skipped vault mismatch target="" effective="openclaw" vault="agent"`.
  - `deploy_check:` `kubectldev -n agent logs watcher-github-vuln-0 --since=24h 2>/dev/null | grep -q 'vault=agent' && echo vault-stamped`
  - `deploy_target:` `vault-stamped`
  - Prerequisite, owned jointly with the octopus rollout task: the mirror is re-pinned to the release cut from this merge and re-applied to dev; and a re-emit must be forced with the watcher's own forced-cycle endpoint `POST /trigger?force=true`, because the per-repo cursor already holds this finding set's task identifier, so an unchanged finding set is skipped as `finding_set_unchanged` and publishes no new command.
  - **Reachability caveat:** the forced-cycle handler exists in-process, but no ingress or admin route exposes it for this watcher — the webhook ingress routes only `github-pr` and `github-release`, and it is GitHub-IP-whitelisted. Reaching it therefore needs either a new route or a different re-emit lever (clearing the cursor PVC, or changing the fixture's finding set). Choosing that lever is an operator decision and is **not** part of this spec.

## Verification

### Container-executable (runs inside the YOLO container at prompt time)

- `make precommit` — format, lint, test and security checks clean
- `make test` — unit + integration suite passes
- `grep -n 'env:"TARGET_VAULT"' main.go` — the config field landed
- `grep -n 'vault=%s' main.go` — the startup log landed
- `grep -n 'TargetVault' pkg/taskbuilder.go pkg/factory/factory.go` — the stamping path landed

### Operator-executable (runs on the host after PR merge, spec verification ladder)

- `make build` — the release image builds
- Octopus rollout task: re-pin `images/watcher-github-vuln/Dockerfile` to the release, then `make apply` to dev (explicit in-the-moment approval required)
- Force a re-emit via `POST /trigger?force=true` (see the Post-Deploy AC's reachability caveat — no route exposes it yet), then `kubectldev -n agent logs agent-task-controller-0 --since=30m | grep 'create-task: created task file'`
- `kubectldev -n agent get pods | grep agent-task-controller` — controller healthy

## Security / Abuse Cases

`TARGET_VAULT` is operator-supplied configuration, read once at startup — not user input. Its value reaches a file path on the controller side (`tasks/{title}.md`), so the existing `^[a-z][a-z0-9-]*$` validator in `CreateCommand.Validate` is the boundary that matters; it already blocks path traversal and separator characters and must not be loosened. The value is not a credential and is safe to log.

## Suggested Decomposition

One prompt. This is a single-layer config-plumbing change, and splitting it would separate the field from the code that consumes it.

| # | Prompt focus | Covers DBs | Covers ACs | Depends on |
|---|---|---|---|---|
| 1 | `TARGET_VAULT` config field + startup log; thread through `CreateWatcher` → `TaskConfig` → `BuildCreateCommand`; tests + CHANGELOG | 1-6 | 1-9 | — |

Rationale: the field, its wiring and its stamping are indivisible — any subset leaves the binary in the state where the setting exists but does nothing, which is exactly the bug. The size-budget signal (6 DBs × 10 ACs = 60, above the 50 threshold) is a mechanical hit on a deliberately small change; the research load is one read of the sibling implementation next door.

## Out of Scope

- The controller's `LegacyDefaultVault` and `routing.ShouldProcess` semantics.
- Adding a `/trigger` route or any external lever to force a cycle. The re-emit problem is real and named in the Post-Deploy AC's prerequisite, but it is an operational concern for the rollout task, not this fix.
- Changing the octopus manifests, which already set `TARGET_VAULT=agent`.
- The watcher's task identifier, title, frontmatter or body contract.
- Any other watcher in the fleet — `github-release-watcher` and `github-pr-watcher` already implement this.

## Do-Nothing Option

Not tolerable. The watcher's only output is the emitted task; with the vault unstamped, every finding it produces is discarded, and the per-repo cursor marks each finding set as emitted so it is never retried. The system reports `success` on every cycle and zero vulns forever — strictly worse than not deploying it, because it manufactures the appearance of coverage. The fix is three files and mirrors an implementation that already exists next door.

## Related

- Live evidence: `agent-task-controller-0` log, 2026-09-17 07:23:54Z, `create-task: skipped vault mismatch target="" effective="openclaw" vault="agent"`.
- Consumer contract: `agent-task-controller` `pkg/command/task_create_task_executor.go` (`routing.ShouldProcess`), and `github.com/bborbe/agent/command/task/create-command.go` (`TargetVault`, `validateCreateTargetVault`).
- Producer contract, already implemented: `github-release-watcher` `main.go`, `pkg/factory/factory.go`, `pkg/taskbuilder.go`.
- Fleet configuration that assumes this works: octopus `maintainer/values-dev.yaml` (`TARGET_VAULT: agent`).
- Downstream task type: `github-update-go` (`github-update-go-watcher` consumes what this watcher emits).
