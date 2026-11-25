---
status: completed
spec: [004-vuln-tasks-route-to-vuln-fix-lane]
summary: 'Verified the end state: every emitted task is stamped assignee vuln-fix-agent with task_type github-update-go unchanged, both tests pin the value, README and changelog name the lane, and make precommit passes.'
execution_id: 4b4bb5f7-2ce2-569f-85ef-bf69a895a151-exec-011-spec-004-stamp-vuln-fix-agent
dark-factory-version: dev
created: "2026-11-25T18:33:54Z"
queued: "2026-11-25T18:42:07Z"
started: "2026-11-25T18:42:09Z"
completed: "2026-11-25T18:49:26Z"
branch: dark-factory/vuln-tasks-route-to-vuln-fix-lane
---

# Stamp vuln-fix-agent on every emitted vuln task

<summary>
- Every task the watcher publishes is addressed to the dedicated vulnerability-fix lane instead of the routine dependency-update lane.
- Vulnerability work stops queueing behind a bulk dependency update that shares a single concurrency slot.
- The task type stays the same, so the dedicated lane still claims the work.
- The task's frontmatter keeps exactly the same twelve keys; only the assignee value changes.
- The task title, body, identifier and dedup behavior are untouched, so no existing finding is re-emitted.
- The contract is pinned at both the builder level and the end-to-end publish path, so a future edit cannot silently revert the routing.
- The README describes the lane the watcher actually targets.
- The changelog records the routing change under an unreleased section.
- No new configuration setting, flag or metric is introduced; the routing target is a fixed, fleet-wide constant.
- Existing tests continue to pass unchanged in everything except the assignee assertion.
</summary>

<objective>
Point every emitted task at the `vuln-fix-agent` lane, so vuln findings are claimed by the lane built for them — with its own concurrency slot — instead of queueing behind routine dependency updates on `github-update-go-agent`'s single shared slot. This is a value change to one frozen frontmatter key, plus the two tests that pin it, the README line and the changelog bullet.
</objective>

<context>
Read `docs/dod.md` first — it is this repository's definition of done and is wired as the dark-factory validation prompt.

Read these coding plugin docs before writing code (in-container paths):
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-testing-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/changelog-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-precommit.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/definition-of-done.md`

Read these repo files before editing:
- `pkg/taskbuilder.go` — `buildFrontmatter` returns `agentlib.TaskFrontmatter` (a `map[string]any`) with exactly 12 keys; `"assignee"` is one of them.
- `pkg/taskbuilder_test.go` — the spec `stamps the 10 consumer keys byte-identical to the sibling` asserts `cmd.Frontmatter["assignee"]`, and `emits exactly the frozen 12-key frontmatter contract` asserts `HaveLen(12)`.
- `pkg/dispatch_integration_test.go` — the spec `publishes exactly one create-task per finding set and dedups the next cycle` asserts `cmd.Frontmatter["assignee"]` on the command a real `Poll` handed to the sender, and asserts `HaveLen(12)`.
- `README.md` — the first paragraph names the consumer that fixes the emitted task.
- `CHANGELOG.md` — note the `## Unreleased` section directly above the highest `## vX.Y.Z` heading.

**Why the value must be `vuln-fix-agent` (do not re-derive it).** The `vuln-fix-agent` lane on nuke dev declares `taskTypes: [github-update-go, healthcheck]` and its own values file states the producer contract: the scanner watcher must stamp `assignee: vuln-fix-agent`. The task controller routes on the `assignee` field alone; nothing downstream compares the literal string `github-update-go-agent`. So changing only the `assignee` value is sufficient — the lane matches on the unchanged `task_type: github-update-go`.

**Current-state note.** At prompt-generation time this repository already carried the target value in all five files (the spec was implemented ahead of prompt generation). Treat every requirement below as an *ensure-the-end-state* step: if a file already carries `vuln-fix-agent`, leave it unchanged and move on; if it carries `github-update-go-agent`, change it. Never revert a correct value.

**Out of scope (do not touch).** The `vuln-fix-agent` lane exists on nuke dev only; creating the prod lane and bumping the nuke dev/prod pins are owned by the consuming vault task. This repository only guarantees what the watcher stamps. There is no deployment, manifest or pin change in this prompt.
</context>

<requirements>
1. In `pkg/taskbuilder.go`, in `buildFrontmatter`, ensure the `assignee` key's value is exactly `vuln-fix-agent`. The current line is (or was before this change):

```go
		"task_type":       "github-update-go",
		"assignee":        "github-update-go-agent",
```

   Change only the value, keeping the surrounding spacing/alignment intact:

```go
		"task_type":       "github-update-go",
		"assignee":        "vuln-fix-agent",
```

   Do not add, remove, rename or reorder any key. The map must still contain exactly 12 keys.

2. Leave `"task_type"` exactly `"github-update-go"`. The `vuln-fix-agent` lane's `taskTypes` includes `github-update-go`; changing the task type would match no lane and the task would be claimed by nobody.

3. Leave every other frontmatter key and the body untouched: `title`, `phase`, `status`, `stage`, `task_identifier`, `repo`, `clone_url`, `ref`, `vuln_count` and `vulns`. Do not touch `ComputeTaskTitle`, `BuildCreateCommand`, `buildTaskBody`, or `DeriveVulnTaskID` — the UUID5 seed is `(repo, sorted vuln IDs)` and the cursor keys on it, so any upstream change would re-emit every finding set fleet-wide.

4. In `pkg/taskbuilder_test.go`, the spec `stamps the 10 consumer keys byte-identical to the sibling` must assert the new value:

```go
		Expect(cmd.Frontmatter["assignee"]).To(Equal("vuln-fix-agent"))
```

   If it currently asserts `github-update-go-agent`, update it. Keep the assertion exact (`Equal`, not `ContainSubstring` or `Or`). Leave the `HaveLen(12)` assertion in `emits exactly the frozen 12-key frontmatter contract` and the `builds the frozen body byte-identically` spec completely unedited.

5. In `pkg/dispatch_integration_test.go`, in `publishes exactly one create-task per finding set and dedups the next cycle`, ensure the publish assertion reads:

```go
		Expect(cmd.Frontmatter["assignee"]).To(Equal("vuln-fix-agent"))
```

   This is the end-to-end guard: the value is asserted on the command a real `Poll` handed to the sender, not only on the builder in isolation. Leave the `Expect(cmd.Frontmatter).To(HaveLen(12))` assertion unedited.

6. In `README.md`, the first paragraph must name `vuln-fix-agent` as the lane that fixes the emitted task. If it still says `github-update-go-agent`, replace that word only; keep the rest of the sentence and the `github-update-go` task-type reference unchanged.

7. In `CHANGELOG.md`, ensure the `## Unreleased` section (directly above the highest `## vX.Y.Z` heading) carries exactly one `fix:` bullet describing this routing change. The bullet must mention `vuln-fix-agent` and must not be duplicated. If the bullet already exists, leave it as-is. Do not move or edit the frozen preamble, and do not touch any released `## vX.Y.Z` section.

8. Self-check before finishing: re-run every command in `<verification>` and confirm each stated result; then walk the spec's acceptance criteria (12-key count, unchanged `task_type`, unedited body spec, no Go file naming the old lane, README names the lane, changelog bullet under `## Unreleased`) against your diff.
</requirements>

<constraints>
- **The frontmatter contract is frozen at 12 keys.** `pkg/taskbuilder_test.go` and `pkg/dispatch_integration_test.go` both assert `HaveLen(12)`; this change must not alter the count. A second assignee key is not acceptable.
- **`task_type` stays `github-update-go`.** The `vuln-fix-agent` lane claims that task type; changing it would match no lane.
- **No new config field, no new flag, no new metric.** The assignee is a fleet-wide routing constant, not per-deployment configuration. A configurable assignee would let dev and prod diverge silently — the exact bug class this change fixes.
- **No change to the task identifier, title, body or dedup cursor.** The UUID5 seed is `(repo, sorted vuln IDs)`; changing anything upstream of the identifier would re-emit every finding set fleet-wide.
- **Scope:** the change touches `pkg/taskbuilder.go`, `pkg/taskbuilder_test.go`, `pkg/dispatch_integration_test.go`, `README.md` and `CHANGELOG.md`. No other package or file.
- **Rollout is not part of this prompt.** The lane exists on dev only; do not add lanes, edit deployment manifests, or bump pins. Deploying this build to a stage without a `vuln-fix-agent` lane would publish tasks nothing claims — that ordering is owned by the consuming vault task.
- Existing tests must still pass; only the two assignee assertions may change value.
- Do NOT commit — dark-factory handles git.
- This repo uses the worktree workflow (`.git` is masked in the execution container). Do not run `git` commands; verify through the filesystem, tests and greps below.
- Do not run `go mod vendor`; this repo does not commit `vendor/`. Use `-mod=mod` for any direct `go` command.
- Keep lines under 100 characters and follow the existing Ginkgo/Gomega style.
- There is no scenario in scope: the spec's Acceptance Criteria state that unit and dispatch integration tests fully cover this boundary.
</constraints>

<verification>
Run from the repo root. Because `.git` is masked, pass `ROOTDIR=/workspace` on every `make` call.

```
ROOTDIR=/workspace make test
```

Must exit 0 — unit plus dispatch integration suite passes.

```
go test -mod=mod ./pkg/ -run TestSuite -count=1 -v -ginkgo.v > /tmp/df-004-verbose.log 2>&1
```

Then confirm both pinning specs actually ran (`-ginkgo.v` is required; without it Ginkgo prints only dots):

```
grep -q 'stamps the 10 consumer keys byte-identical to the sibling' /tmp/df-004-verbose.log
grep -q 'publishes exactly one create-task per finding set and dedups the next cycle' /tmp/df-004-verbose.log
```

Each must exit 0.

```
test "$(grep -c '"assignee".*"vuln-fix-agent"' pkg/taskbuilder.go)" = "1"
```

Must exit 0 — exactly one assignee line, stamped with the vuln lane.

```
test "$(grep -c '"task_type".*"github-update-go"' pkg/taskbuilder.go)" = "1"
```

Must exit 0 — the task type is unchanged.

```
test "$(grep -c 'HaveLen(12)' pkg/taskbuilder_test.go)" = "1"
test "$(grep -c 'HaveLen(12)' pkg/dispatch_integration_test.go)" = "1"
```

Each must exit 0 — the 12-key contract assertions are still present and unedited.

```
test "$(grep -c 'assignee.*vuln-fix-agent' pkg/taskbuilder_test.go)" = "1"
test "$(grep -c 'assignee.*vuln-fix-agent' pkg/dispatch_integration_test.go)" = "1"
```

Each must exit 0 — both tests assert the new value.

```
! grep -rn 'github-update-go-agent' --include='*.go' .
```

Must exit 0 — no Go file names the old lane.

```
grep -q 'vuln-fix-agent' README.md
! grep -q 'github-update-go-agent' README.md
```

Both must exit 0 — the README names the lane the watcher targets.

```
test "$(grep -c '^## Unreleased$' CHANGELOG.md)" = "1"
```

Must exit 0 — exactly one Unreleased heading.

```
awk '/^## /{sec=$0} sec=="## Unreleased" && /^- fix:.*vuln-fix-agent/{c++} END{exit !(c==1)}' CHANGELOG.md
```

Must exit 0 — exactly one `fix:` bullet naming the lane under `## Unreleased`.

```
test "$(awk '/^## /{sec=$0} /vuln-fix-agent/{print sec}' CHANGELOG.md | sort -u)" = "## Unreleased"
```

Must exit 0 — the only section mentioning the lane is `## Unreleased`.

```
ROOTDIR=/workspace make precommit
```

Must exit 0 (format, lint, test and security checks clean). Run it once, at the very end.
</verification>
