---
status: completed
spec: [003-bug-create-task-missing-target-vault]
summary: Threaded the optional TARGET_VAULT setting from main.go through factory.CreateWatcher and pkg.TaskConfig into BuildCreateCommand so every emitted create-task carries the configured vault slug, with empty values staying byte-identical on the wire via omitempty.
execution_id: github-vuln-watcher-targetvault-exec-009-spec-003-create-task-target-vault
dark-factory-version: dev
created: "2026-09-17T08:50:57Z"
queued: "2026-09-17T09:26:27Z"
started: "2026-09-17T09:26:29Z"
completed: "2026-09-17T09:29:33Z"
branch: dark-factory/bug-create-task-missing-target-vault
---

<summary>
- Every task the watcher publishes now carries the vault slug the operator configured, so the task controller stops discarding it.
- A new optional setting supplies that slug; leaving it unset keeps today's published payload byte-identical, so existing deployments are unaffected.
- The value is validated by the same rule the controller relies on, so a typo is refused at publish time instead of the task silently disappearing.
- A misconfigured slug now surfaces as a publish error the next cycle retries, instead of a healthy-looking watcher and an empty task queue.
- The configured slug is printed in the startup log, so a running pod's configuration is observable without waiting for a publish.
- The value is applied in exactly one place, so the setting and the sent task can never disagree.
- The published task's existing contract — its identifier, title, frontmatter keys and body — is unchanged.
- Nothing else in the fleet changes: this is the producer-side half of a contract the controller and the deploy manifests already implement.
</summary>

<objective>
Stamp the configured vault slug onto every `CreateTaskCommand` the watcher publishes, so the `agent-task-controller` materialises the task instead of skipping it as a vault mismatch. The optional `TARGET_VAULT` setting is threaded from the binary's config through the watcher factory and the task config into the command builder, and an unset value keeps today's wire form byte-identical.
</objective>

<context>
Read `docs/dod.md` first — it is this repo's definition of done and is wired as the dark-factory validation prompt.

Read these coding plugin docs before writing code (in-container paths):
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-patterns.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-factory-pattern.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-testing-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-precommit.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-k8s-binary-conventions.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/changelog-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/definition-of-done.md`

Read these repo files before writing code:
- `main.go` — the `application` config struct (every field carries `required:` / `arg:` / `env:` / `usage:` tags; the tag columns are hand-aligned) and `application.Run`, which calls `factory.CreateWatcher` and emits the startup log line.
- `pkg/factory/factory.go` — `CreateWatcher` (pure composition) and `CreateKafkaSender`.
- `pkg/taskbuilder.go` — `TaskConfig`, `BuildCreateCommand`, `buildFrontmatter`.
- `pkg/taskpublisher.go` — `NewTaskPublisher(sender, metrics, cfg TaskConfig)`; `PublishCreate` calls `BuildCreateCommand(candidate, p.cfg)` and only records the task identifier in the cursor when the send succeeds.
- `pkg/taskbuilder_test.go`, `pkg/dispatch_integration_test.go`, `pkg/factory/factory_test.go`, `main_test.go` — the four test files this prompt touches.
- `CHANGELOG.md` — note the existing `## Unreleased` section above `## v0.3.0`.

**Why this change exists (do not re-derive it).** The controller runs with `VAULT_NAME=agent` and its `routing.ShouldProcess` resolves an empty `TargetVault` to a legacy default (`openclaw`), which is not `agent` — so the command is skipped with no git write, no error event and no result event. Meanwhile the watcher reports `published_total{status="create"}` and `success`, and its cursor marks the finding set as emitted, so the finding is never retried. The fleet already sets `TARGET_VAULT=agent` on the pod; the binary simply has no field for it.

**The external contract, verified against the module source at `github.com/bborbe/agent v0.83.0` (`/home/node/go/pkg/mod/github.com/bborbe/agent@v0.83.0/command/task/create-command.go`).** Read that file if you want the full text; the load-bearing parts are:

```go
type CreateCommand struct {
	TaskIdentifier lib.TaskIdentifier  `json:"taskIdentifier"`
	Title          string              `json:"title"`
	Frontmatter    lib.TaskFrontmatter `json:"frontmatter"`
	Body           string              `json:"body,omitempty"`
	// TargetVault is the slug of the Obsidian vault this task belongs in.
	// Empty value means "use the controller's legacy default (openclaw)".
	// Wire format uses omitempty so legacy producers that never set it stay byte-compatible.
	TargetVault string `json:"targetVault,omitempty"`
}

func (cmd CreateCommand) Validate(ctx context.Context) error {
	return validation.All{
		validation.Name("Title", validateCreateTitle(cmd.Title)),
		validation.Name("Body", validateCreateBody(cmd.Body)),
		validation.Name("TargetVault", validateCreateTargetVault(cmd.TargetVault)),
	}.Validate(ctx)
}

var targetVaultSlugRegexp = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
```

`validateCreateTargetVault` accepts the empty string and otherwise requires `^[a-z][a-z0-9-]*$`.

Also verified, in `/home/node/go/pkg/mod/github.com/bborbe/agent@v0.83.0/command/task/create-command-sender.go`:

```go
func NewCreateCommandSender(
	commandObjectSender cdb.CommandObjectSender,
	defaultVault string,
) CreateCommandSender
```

Its `SendCommand` substitutes `defaultVault` into `cmd.TargetVault` only when `cmd.TargetVault` is empty, then calls `cmd.Validate(ctx)` before touching Kafka.

**The sibling implementation is NOT reachable from this container.** `github-release-watcher` is not mounted and not in the module cache — do not go looking for it, and do not write a path to it. Its field shape is inlined in requirement 3 below.

**Test-file layout, verified:** `pkg/taskbuilder_test.go` and `pkg/dispatch_integration_test.go` are `package pkg_test` (Ginkgo/Gomega, imported as `ginkgo` / `. "github.com/onsi/gomega"`). `pkg/factory/factory_test.go` is `package factory_test`. `main_test.go` is `package main_test` and already reads `main.go` from disk with `os.ReadFile("main.go")` for source-text guards (see the specs `does not declare the removed scaffold flags` and `wires the scan token source into the watcher`); each test package runs with its own directory as the working directory, so `os.ReadFile("main.go")` and `os.ReadFile("factory.go")` resolve inside their own package directories.

**Call-site inventory, verified:** `factory.CreateWatcher` has exactly two call sites — `main.go` in `application.Run`, and `pkg/factory/factory_test.go` in the spec `CreateWatcher wires the publisher/sender seam and returns a non-nil Watcher`. Both must be updated in this prompt: Go has no default parameters, so the package stops compiling otherwise.

**Test-run evidence, verified on this tree:** plain `go test -v` prints only dots for Ginkgo suites — spec titles appear only when Ginkgo's own verbose reporter is on, i.e. with the extra `-ginkgo.v` flag. Every spec-title grep in `<verification>` therefore reads a log captured with `-ginkgo.v`.
</context>

<requirements>
1. In `pkg/taskbuilder.go`, add one field to `TaskConfig` and stamp it in `BuildCreateCommand`:

```go
// TaskConfig groups per-task envelope settings.
type TaskConfig struct {
	Stage       string // "dev" or "prod" — emitted as the `stage` field
	TargetVault string // vault slug — emitted as the `targetVault` field; empty = controller legacy default
}
```

```go
	return task.CreateCommand{
		Title:          ComputeTaskTitle(c),
		TaskIdentifier: agentlib.TaskIdentifier(taskIDStr),
		Frontmatter:    buildFrontmatter(c, taskIDStr, cfg),
		Body:           buildTaskBody(c),
		TargetVault:    cfg.TargetVault,
	}
```

   This is the **only** stamping site. `buildFrontmatter` is unchanged — the vault is a top-level command field, not a frontmatter key, and the frontmatter must stay at exactly 12 keys.

2. In `pkg/factory/factory.go`, give `CreateWatcher` one new parameter named `targetVault string`, placed **immediately after `stage string`** (not appended at the end — `tokenSource` must remain the final argument), and thread it into the task config:

```go
	publisher := pkg.NewTaskPublisher(
		sender,
		metrics,
		pkg.TaskConfig{Stage: stage, TargetVault: targetVault},
	)
```

   Leave `CreateKafkaSender` exactly as it is — it keeps passing `""` to `task.NewCreateCommandSender(sender, "")`. That sender-level default is the sibling's shape and must not become a second stamping site; if both places stamped the vault they could diverge silently.

3. In `main.go`, add the config field to the `application` struct immediately after the `Stage` field, matching the block's existing hand-aligned tag columns:

```go
	TargetVault   string `required:"false" arg:"target-vault"   env:"TARGET_VAULT"   usage:"Vault slug stamped onto every emitted task; empty leaves the controller's legacy default"`
```

   Then, in `application.Run`, pass it to the factory — insert `a.TargetVault,` immediately after `a.Stage,` in the `factory.CreateWatcher(...)` call — and name it in the startup log by adding `vault=%s` to the format string with `a.TargetVault` as the matching argument, immediately after `a.Stage`:

```go
	glog.V(2).
		Infof("%s starting stage=%s vault=%s owner=%s interval=%s cursor=%s listen=%s", serviceName, a.Stage, a.TargetVault, a.Owner, a.PollInterval, a.CursorPath, a.Listen)
```

   `a.TargetVault` must appear inside that same `Infof(...)` call: the guard spec in requirement 7b asserts exactly that, so a `vault=%s` fed a hardcoded or empty argument fails.

4. In `pkg/factory/factory_test.go`, update the existing `CreateWatcher` call for the new parameter — insert `""` immediately after `"dev"`. Keep the existing assertions untouched: constructing the watcher with an empty vault is the evidence that `TARGET_VAULT` unset remains a valid configuration.

5. In `pkg/taskbuilder_test.go` (add `"encoding/json"` to the import block), add three specs inside the existing `ginkgo.Describe("BuildCreateCommand", ...)` block, reusing its `fixedCandidate()` helper:

   a. The stamping spec, titled exactly `stamps the target vault config from the task config`:

```go
	ginkgo.It("stamps the target vault config from the task config", func() {
		cmd := pkg.BuildCreateCommand(
			fixedCandidate(),
			pkg.TaskConfig{Stage: "dev", TargetVault: "agent"},
		)
		Expect(cmd.TargetVault).To(Equal("agent"))
	})
```

   b. The empty-value wire spec, titled `omits the target vault from the wire form when the config leaves it empty`. It must assert both that the field is empty **and** that the serialised form has no `targetVault` key — this is what stops a lazy "hardcode `agent`" implementation:

```go
	ginkgo.It("omits the target vault from the wire form when the config leaves it empty", func() {
		cmd := pkg.BuildCreateCommand(fixedCandidate(), pkg.TaskConfig{Stage: "dev"})
		Expect(cmd.TargetVault).To(BeEmpty())
		raw, err := json.Marshal(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(raw)).NotTo(ContainSubstring("targetVault"))
	})
```

   c. A `ginkgo.DescribeTable` (the Ginkgo table DSL is this project's prescribed table-test form — see `go-testing-guide.md`) titled `rejects a target vault the CreateCommand validator refuses`, driving the real validator through `BuildCreateCommand`. `Agent!` and `agent_x` are the two values named in the spec's failure-modes table; `agent/../etc` covers the path-traversal case the spec's security section calls the boundary that matters:

```go
	ginkgo.DescribeTable("rejects a target vault the CreateCommand validator refuses",
		func(targetVault string) {
			cmd := pkg.BuildCreateCommand(
				fixedCandidate(),
				pkg.TaskConfig{Stage: "dev", TargetVault: targetVault},
			)
			Expect(cmd.Validate(context.Background())).To(HaveOccurred())
		},
		ginkgo.Entry("uppercase and punctuation", "Agent!"),
		ginkgo.Entry("underscore", "agent_x"),
		ginkgo.Entry("path traversal", "agent/../etc"),
	)
```

6. In `pkg/dispatch_integration_test.go` (add `"encoding/json"` to the import block), make the real dispatch path carry a configured vault. In `newDispatchHarness`, change the publisher construction to `pkg.NewTaskPublisher(sender, metrics, pkg.TaskConfig{Stage: "dev", TargetVault: "agent"})`. Do not change the harness signature — both call sites keep working, and every existing assertion in that file stays as it is.

   Then, in the spec `publishes exactly one create-task per finding set and dedups the next cycle`, immediately after the existing `Expect(cmd.Validate(context.Background())).To(Succeed())` line, assert that the vault survives onto the wire form of the command the sender received:

```go
		raw, err := json.Marshal(cmd)
		Expect(err).NotTo(HaveOccurred())
		var wire map[string]any
		Expect(json.Unmarshal(raw, &wire)).To(Succeed())
		Expect(wire["targetVault"]).To(Equal("agent"))
```

   `cmd` is the captured `task.CreateCommand` the fake sender was handed. This test marshals that struct itself rather than observing the real sender's output — the fake performs no serialisation. That is sound because the struct tag **is** the wire contract: the real sender ends in `json.Marshal` of this same struct, so marshalling it with the same tag reproduces the wire form. Do not claim in a comment that this exercises the real sender.

7. In `main_test.go`, add two source-text guard specs to the existing `Describe("Main", ...)` block, using the `os.ReadFile("main.go")` pattern already established in that file. `os` and the dot-imported Gomega matchers are already imported; do not add new imports.

   a. The wiring guard, titled `passes the configured target vault into the watcher factory`:

```go
	It("passes the configured target vault into the watcher factory", func() {
		source, err := os.ReadFile("main.go")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(source)).
			To(MatchRegexp(`(?s)CreateWatcher\(.*?a\.TargetVault.*?tokenSource,\s*\)`))
	})
```

   This guards the lazy "add the config field, pass nothing" implementation. The trailing `tokenSource,\s*\)` anchor is deliberate: that sequence occurs exactly once in the file, at the end of the `CreateWatcher` argument list, so the regex cannot be satisfied by an `a.TargetVault` mention elsewhere in the file (for example in the startup log line). Keep `tokenSource` as the final argument.

   b. The startup-log guard, titled `names the configured target vault in the startup log`:

```go
	It("names the configured target vault in the startup log", func() {
		source, err := os.ReadFile("main.go")
		Expect(err).NotTo(HaveOccurred())
		text := string(source)
		Expect(text).To(ContainSubstring("vault=%s"))
		Expect(text).To(MatchRegexp(`(?s)Infof\([^)]*vault=%s[^)]*a\.TargetVault[^)]*\)`))
	})
```

   Both tokens must sit inside one `Infof(...)` call, so a `vault=%s` fed an empty or hardcoded argument fails.

8. In `pkg/factory/factory_test.go`, add one source-text guard spec (add `os` to the import block) titled `threads the target vault into the task config`:

```go
	It("threads the target vault into the task config", func() {
		source, err := os.ReadFile("factory.go")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(source)).To(MatchRegexp(`TaskConfig\{[^}]*TargetVault:\s*targetVault`))
	})
```

   `CreateWatcher` returns a `pkg.Watcher` interface, so the factory-to-task-config seam cannot be observed behaviourally without widening production API — which this change must not do. This guard is the cheap way to pin it, and it is the same source-text pattern `main_test.go` already uses. It closes the seam that requirement 7a cannot see: without it, `CreateWatcher` could accept the parameter and never put it in `TaskConfig`, leaving the original bug in place one layer up.

   The regex pins the **argument expression** (`TargetVault: targetVault`), not just the key name. A key-only pattern would also be satisfied by `TargetVault: ""` — which drops the operator's configured vault and leaves the original silent-skip bug in place — or by a hardcoded `TargetVault: "agent"`. Neither may pass.

9. Append one bullet to the existing `## Unreleased` section of `CHANGELOG.md` (do not replace it, do not add a new section). Follow the file's `- <prefix>: <what> [context]` style; the prefix is `fix:`. Name the setting, the wiring path and the empty-value guarantee. For example: `- fix: the watcher stamps the configured `TARGET_VAULT` onto every emitted create-task command (`main.go` → `factory.CreateWatcher` → `pkg.TaskConfig` → `BuildCreateCommand`), so the controller materialises the task instead of skipping it as a vault mismatch; an unset value stays byte-identical on the wire via `omitempty``.

10. Self-check before finishing: re-run every command in `<verification>` and confirm each one's stated result; then walk each requirement above against your diff and confirm the frontmatter key set, the title form, the body and the task identifier are untouched.
</requirements>

<constraints>
- **One stamping site.** `CreateKafkaSender` continues to pass `""` to `task.NewCreateCommandSender`. The vault is stamped in `BuildCreateCommand` from `TaskConfig` only. Stamping in both places would let them diverge silently.
- **Empty must stay byte-identical.** `CreateCommand.TargetVault` is `json:"targetVault,omitempty"`; an empty value must keep producing a payload with no `targetVault` key, so legacy producers and existing tests are unaffected.
- **Field shape mirrors the sibling** — `required:"false"`, `arg:"target-vault"`, `env:"TARGET_VAULT"`.
- **No new dependency, no new exported type.** `TaskConfig` gains one string field; `CreateWatcher` gains one string parameter. Do not add an accessor or any other new exported symbol.
- **Existing tests keep passing.** The 12-key frontmatter contract, the UUID5 identifier, the dash-form title and the body are all unchanged. Do not add a frontmatter key for the vault.
- **Scope:** the change touches `main.go`, `pkg/factory/factory.go`, `pkg/taskbuilder.go`, their four test files (`main_test.go`, `pkg/factory/factory_test.go`, `pkg/taskbuilder_test.go`, `pkg/dispatch_integration_test.go`) and `CHANGELOG.md`. No other package changes, no other file changes.
- **Do not loosen the validator.** `^[a-z][a-z0-9-]*$` in `CreateCommand.Validate` is the security boundary — the value reaches a file path on the controller side. It is already correct; this prompt only feeds it.
- Module path is `github.com/bborbe/github-vuln-watcher`. Use `-mod=mod` in every `go` command — this repo does not commit `vendor/`, so `-mod=vendor` fails.
- Do not run `go mod vendor`, do not add or bump dependencies, do not hand-edit anything under `mocks/`.
- Tests use Ginkgo/Gomega in external test packages (`package pkg_test`, `package factory_test`, `package main_test`); counterfeiter fakes come from `//counterfeiter:generate` directives.
- Keep every line under 100 characters and every function under 80 lines / 50 statements (`funlen`). The pre-existing `Infof` startup-log line in `main.go` is the one exception — it is already over 100 characters and `golines` leaves it as-is; extend it in place rather than wrapping it.
- Do NOT commit — dark-factory handles git.
- No cluster or deployment verification: this container has no `kubectl` and no cluster access. The deployed-pod check belongs to the spec's operator-executable verification ladder, not to this prompt.
</constraints>

<verification>
Run from the repo root.

```
make test
```

Must exit 0. Run this iteratively while implementing — it is the fast feedback loop.

```
go test -mod=mod ./... -count=1 -v -ginkgo.v -ginkgo.fail-on-pending > /tmp/df-003-verbose.log 2>&1
```

Must exit 0 (the redirect keeps the exit status as `go test`'s own). This log is the evidence source for the spec-name greps below — `-ginkgo.v` is required: without it Ginkgo prints only dots, and every one of those greps would print `0` on a green run.

```
grep -ic 'stamps the target vault config' /tmp/df-003-verbose.log
```

Must print at least `1` — the stamping spec ran.

```
grep -ic 'omits the target vault from the wire form' /tmp/df-003-verbose.log
```

Must print at least `1` — the empty-value wire spec ran.

```
grep -ic 'the CreateCommand validator refuses' /tmp/df-003-verbose.log
```

Must print at least `1` — the invalid-slug table ran.

```
grep -ic 'into the watcher factory' /tmp/df-003-verbose.log
```

Must print at least `1` — the wiring guard ran.

```
grep -ic 'into the task config' /tmp/df-003-verbose.log
```

Must print at least `1` — the factory-seam guard ran.

```
grep -ic 'in the startup log' /tmp/df-003-verbose.log
```

Must print at least `1` — the startup-log guard ran.

```
grep -c 'env:"TARGET_VAULT"' main.go
```

Must print `1`.

```
grep -c 'vault=%s' main.go
```

Must print `1`.

```
grep -n 'TargetVault' pkg/taskbuilder.go pkg/factory/factory.go
```

Must return at least one line for each file — the stamping path landed on both sides.

```
grep -nE 'TargetVault:[[:space:]]*targetVault' pkg/factory/factory.go
```

Must return at least one line — the factory passes the parameter through, not a literal.

```
grep -n 'TargetVault' main_test.go
```

Must return at least one line — the wiring guard exists. (The guard spells the field `a\.TargetVault` inside its regex literal, so a literal `a.TargetVault` search cannot match it; search for the field name alone.)

```
! grep -q 'target_vault' pkg/taskbuilder.go
```

Must exit 0 — no frontmatter key was added; the frontmatter stays at exactly 12 keys.

```
grep -n 'Unreleased' CHANGELOG.md
```

Must return at least one line.

```
make precommit
```

Must exit 0. Run it once, at the very end. If it fails, fix the failure and re-run only the failing target (`make lint`, `make gosec`, ...) before running `make precommit` again.
</verification>
