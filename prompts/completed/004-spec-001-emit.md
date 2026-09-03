---
status: completed
spec: [001-vuln-drift-watcher]
summary: 'Added the vuln-fork emit layer: deterministic UUID5 task identifier (frozen namespace + vuln-drift seed), frozen 12-key create-task builder (vuln_count + sorted vulns, dash title, byte-frozen body), TaskPublisher with published_total{create|error} accounting, vulns_detected_total counter, cqrs Kafka sender + watcher/factory/main wiring, plus k8s.io v0.36.4 replace directives to keep go mod tidy resolvable'
execution_id: github-vuln-watcher-vuln-drift-watcher-exec-004-spec-001-emit
dark-factory-version: dev
created: "2026-09-03T20:30:00Z"
queued: "2026-09-03T18:43:31Z"
started: "2026-09-03T19:04:32Z"
completed: "2026-09-03T19:15:54Z"
---

<summary>
- Repos with a non-empty vuln marker list now produce exactly one `github-update-go` create-task command under the frozen 12-key emit contract, carrying the vuln payload (`vuln_count` + sorted `vulns` list).
- The task title is frozen dash-form (`Update Go <owner>-<repo> <sha[:7]>`, never a `/`), so every title passes the CreateCommand validator; the body keeps the frozen header, the two-space-middot vuln line, the HEAD line and the Repo line.
- Each task's identifier is a deterministic UUID5 seeded only from (repo, sorted vuln IDs) — never from the HEAD SHA or a timestamp — so an unchanged finding set always yields the same identifier and any re-emit is a downstream no-op.
- The emit step goes through a typed `CreateCommandSender` over the cqrs `cdb` layer backed by a Kafka sync producer, so the topic (`agent-task-v1-request`, optional `TOPIC_PREFIX`) is constructed by the frozen schema, not hand-wired.
- Publish outcomes are counted on `published_total{status="create|error"}`; a failed publish returns false so the caller never advances dedup state and the repo retries next cycle.
- A new `vulns_detected_total` counter records the number of markers found per scanned repo, and the watcher now routes repos with markers into the publisher.
- The frozen contract is locked by golden-master unit tests asserting every one of the 12 frontmatter keys and the exact body string.
</summary>

<objective>
Add the emit layer: the vuln-fork task builder (frozen 12-key contract with `vuln_count`/`vulns`, dash-form title, frozen body shape), the deterministic UUID5 task identifier seeded from (repo, sorted vuln IDs), the publisher + Kafka wiring through the typed create-task command sender, and the `vulns_detected_total` counter. Repos with markers now get exactly one create-task command each cycle.
</objective>

<context>
Read `docs/dod.md`.

Read these coding plugin docs before writing code (paths are inside the container):
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-patterns.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-factory-pattern.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-error-wrapping-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-testing-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-mocking-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-cqrs.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-prometheus-metrics-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/definition-of-done.md`

Read these repo files before writing code:
- `pkg/watcher.go` — `processRepos` (this prompt inserts the emit step after the scan) and `NewWatcher` (this prompt adds the publisher collaborator).
- `pkg/candidate.go` — `Candidate` (this prompt adds the `TaskIdentifier()` method and populates `FilterCandidate`'s `TaskIdentifier`).
- `pkg/metrics.go` — `Metrics` interface (this prompt adds `IncVulnsDetected` and the `vulns_detected_total` counter).
- `pkg/factory/factory.go` — `CreateWatcher` (this prompt changes its signature to add the sender + stage) and `CreateRouter` (unchanged).
- `main.go` — `Run` (this prompt adds the Kafka sync producer + sender and updates the `CreateWatcher` call).

**Sibling entry-point check (already run):** one binary entry point (`main.go`). Run `grep -rn "factory.Create" --include=*.go .` before you start; the only `CreateWatcher` call site is `main.go`. Update it in step 7.

The emit contract is a FORK of the frozen `github-update-go-watcher` taskbuilder (the source of truth). The fork replaces `current_go`/`latest_go` with `vuln_count` + `vulns`, and replaces the `**Current Go:** ... **Latest Go:** ...` body line with the vuln line; the header `# Update Go: <owner>/<repo>`, the two-space-middot separation, the `**HEAD:** <sha[:7]>` line, and the `**Repo:** [...]` line stay byte-identical (spec Constraints).

Library API facts (verified against the module cache — do not re-derive from memory):
- `github.com/bborbe/agent` (import `agentlib`) — `type TaskIdentifier string`; `type TaskFrontmatter map[string]interface{}`; `var TaskV1SchemaID = cdb.SchemaID{Group: "agent", Kind: "task", Version: "v1"}` (topic `agent-task-v1-request` derives from this + the prefix).
- `github.com/bborbe/agent/command/task` (import `task`) — `type CreateCommand struct { TaskIdentifier agentlib.TaskIdentifier; Title string; Frontmatter agentlib.TaskFrontmatter; Body string; TargetVault string }`; interface `CreateCommandSender { SendCommand(ctx context.Context, cmd CreateCommand) error }`; `NewCreateCommandSender(commandObjectSender cdb.CommandObjectSender, defaultVault string) CreateCommandSender`. `SendCommand` calls `cmd.Validate(ctx)` before publishing and returns the validation error without touching Kafka — the dash title is what keeps every publish valid.
- `github.com/bborbe/cqrs/cdb` (import `cdb`) — `cdb.NewCommandObjectSender(syncProducer, prefix base.TopicPrefix, logSamplerFactory log.SamplerFactory) cdb.CommandObjectSender`.
- `github.com/bborbe/kafka` (import `libkafka`) — `libkafka.ParseBrokersFromString(value string) libkafka.Brokers`; `libkafka.NewSyncProducerWithName(ctx, brokers, name)`.
- `github.com/bborbe/log` — `log.DefaultSamplerFactory`.
- `github.com/google/uuid` — `uuid.MustParse(string) uuid.UUID`; `uuid.NewSHA1(space uuid.UUID, data []byte) uuid.UUID` (version 5 — do NOT use `NewMD5` or `New`).
- `github.com/prometheus/client_golang/prometheus` — `prometheus.NewCounter(prometheus.CounterOpts{...})`.
</context>

<requirements>

### 1. go.mod: add agent

```
go get github.com/bborbe/agent@v0.86.0
```

Then `go mod tidy` (also runs in `make precommit`). The agent module brings `github.com/bborbe/cqrs` (already present), `github.com/bborbe/collection`, `github.com/bborbe/validation`, and `github.com/bborbe/vault-cli` as needed. Do NOT add any other new module in this prompt.

### 2. `pkg/taskid.go` — deterministic UUID5 identifier

Package `pkg`. The namespace is frozen and must never change:

```go
// vulnTaskIDNamespace is the UUID5 namespace for github-update-go vuln-drift
// tasks. Frozen: changing it would break the task controller's dedup and
// re-file every open work item.
var vulnTaskIDNamespace = uuid.MustParse("5c3bcb6b-fb0f-4c61-a4c3-8a17fd037f52")

// DeriveVulnTaskID returns a UUID5 derived deterministically from
// (owner, repo, sorted deduped vuln IDs) via the seed
// "vuln-drift-<owner>-<repo>-<comma-joined-sorted-ids>" (spec Constraints).
// The vuln ID list is canonicalised (deduped + sorted) inside this function,
// so the identifier never depends on caller discipline. It deliberately
// excludes any HEAD SHA or timestamp — an unchanged finding set must always
// yield the same identifier.
func DeriveVulnTaskID(owner, repo string, vulnIDs []string) uuid.UUID {
	seed := fmt.Sprintf(
		"vuln-drift-%s-%s-%s",
		owner,
		repo,
		strings.Join(canonicalVulnIDs(vulnIDs), ","),
	)
	return uuid.NewSHA1(vulnTaskIDNamespace, []byte(seed))
}

// canonicalVulnIDs returns a deduped, lexicographically-sorted copy of ids.
func canonicalVulnIDs(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		seen[id] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
```

`pkg/taskid_test.go` (`package pkg_test`):
- Same `(owner, repo, ids)` twice → identical UUID.
- Reordered ids → identical UUID.
- Duplicate ids → identical UUID (same as the deduped list).
- A different id in the list → different UUID.
- Different repo or owner → different UUID.
- `DeriveVulnTaskID(...).Version().String()` equals `"VERSION_5"`.
- The seed does not involve the HEAD SHA: two calls that differ only in an unused sha argument (pass the same ids) → identical UUID.

### 3. `pkg/taskbuilder.go` — the vuln-fork emit contract

Package `pkg`:

```go
// TaskConfig groups per-task envelope settings.
type TaskConfig struct {
	Stage string // "dev" or "prod" — emitted as the `stage` field
}

// ComputeTaskTitle returns the frozen title form:
// "Update Go <owner>-<repo> <sha[:7]>".
//
// Dash, not slash: CreateCommand.Validate rejects any '/' in a title, and
// SendCommand validates before publishing — a slash form would make every
// publish fail.
func ComputeTaskTitle(c Candidate) string {
	return fmt.Sprintf(
		"Update Go %s-%s %s",
		c.Repo.Owner,
		c.Repo.Name,
		c.ShortSHA(),
	)
}

// BuildCreateCommand assembles the CreateTaskCommand for a Candidate carrying
// a non-empty VulnIDs list (the frozen 12-key contract — the 10 consumer keys
// keep their semantics byte-identical to github-update-go-watcher, plus the
// vuln payload vuln_count and vulns).
func BuildCreateCommand(c Candidate, cfg TaskConfig) task.CreateCommand {
	taskIDStr := DeriveVulnTaskID(c.Repo.Owner, c.Repo.Name, c.VulnIDs).String()
	return task.CreateCommand{
		Title:          ComputeTaskTitle(c),
		TaskIdentifier: agentlib.TaskIdentifier(taskIDStr),
		Frontmatter:    buildFrontmatter(c, taskIDStr, cfg),
		Body:           buildTaskBody(c),
	}
}

func buildFrontmatter(
	c Candidate,
	taskIDStr string,
	cfg TaskConfig,
) agentlib.TaskFrontmatter {
	return agentlib.TaskFrontmatter{
		"task_type":       "github-update-go",
		"assignee":        "github-update-go-agent",
		"phase":           "planning",
		"status":          "in_progress",
		"stage":           cfg.Stage,
		"task_identifier": taskIDStr,
		"title":           ComputeTaskTitle(c),
		"repo":            c.Repo.String(),
		"clone_url": fmt.Sprintf(
			"git@github.com:%s/%s.git",
			c.Repo.Owner,
			c.Repo.Name,
		),
		"ref":        c.HeadSHA,
		"vuln_count": len(c.VulnIDs),
		"vulns":      c.VulnIDs,
	}
}

func buildTaskBody(c Candidate) string {
	owner := c.Repo.Owner
	name := c.Repo.Name
	return fmt.Sprintf(
		"# Update Go: %s/%s\n\n"+
			"**Vulnerabilities:** %s\n"+
			"**HEAD:** %s\n"+
			"**Repo:** [%s/%s](https://github.com/%s/%s)\n",
		owner, name,
		strings.Join(c.VulnIDs, "  ·  "),
		c.ShortSHA(),
		owner, name, owner, name,
	)
}
```

`vulns` is the canonical sorted `[]string` (JSON array on the wire); `vuln_count` is its length. The body's vuln line joins the ids with two-space middots (`"  ·  "`), replacing the sibling's `**Current Go:** ...  ·  **Latest Go:** ...` line; the header, the HEAD line, and the Repo line are byte-identical to the sibling. The `clone_url` field is ALWAYS the frozen SSH form — never `c.Repo.CloneURL`.

`pkg/taskbuilder_test.go` (`package pkg_test`) — the golden-master contract test. Build a fixed candidate:

```go
headSHA := "0123456789abcdef0123456789abcdef01234567"
c := pkg.Candidate{
	Repo:    pkg.Repo{Owner: "bborbe", Name: "demo", DefaultBranch: "master"},
	HeadSHA: headSHA,
	VulnIDs: []string{"GO-2024-1234", "GO-2024-5678"},
}
cmd := pkg.BuildCreateCommand(c, pkg.TaskConfig{Stage: "dev"})
```

Assert ALL of:
- `cmd.Frontmatter` has exactly 12 keys.
- `cmd.Validate(context.Background())` returns nil — the CreateCommand validator (title forbidden-chars/edges, body length, TargetVault) is the actual boundary the production publish path checks before touching Kafka; mirror the sibling's `returns nil from Validate` spec.
- `cmd.Frontmatter["task_type"] == "github-update-go"`, `["assignee"] == "github-update-go-agent"`, `["phase"] == "planning"`, `["status"] == "in_progress"`, `["stage"] == "dev"`, `["repo"] == "bborbe/demo"`, `["clone_url"] == "git@github.com:bborbe/demo.git"`, `["ref"] == headSHA`, `["vuln_count"] == 2`, `["vulns"] == []string{"GO-2024-1234", "GO-2024-5678"}`.
- `cmd.Frontmatter["task_identifier"]` is a valid UUID whose `.Version()` is `"VERSION_5"`.
- `cmd.Frontmatter["title"] == "Update Go bborbe-demo 0123456"` and `cmd.Frontmatter["title"] == cmd.Title`.
- `cmd.Title` contains no `/` (equivalent of `grep -c '/'` == 0).
- `cmd.Body` equals EXACTLY:
  `"# Update Go: bborbe/demo\n\n**Vulnerabilities:** GO-2024-1234  ·  GO-2024-5678\n**HEAD:** 0123456\n**Repo:** [bborbe/demo](https://github.com/bborbe/demo)\n"`
- A candidate with `VulnIDs: []string{"GO-2024-1234"}` (single marker) produces a body vuln line `"**Vulnerabilities:** GO-2024-1234\n"` (no middot).
- Determinism: building twice yields byte-identical commands.
- The stage config is stamped: `TaskConfig{Stage: "prod"}` → `["stage"] == "prod"`.

### 4. `pkg/taskpublisher.go` — publish with outcome accounting

Package `pkg`:

```go
//counterfeiter:generate -o ../mocks/task_publisher.go --fake-name TaskPublisher . TaskPublisher
//counterfeiter:generate -o ../mocks/create_command_sender.go --fake-name CreateCommandSender github.com/bborbe/agent/command/task.CreateCommandSender

// TaskPublisher builds the CreateTaskCommand for a Candidate and sends it via
// the supplied CreateCommandSender. Returns true only on a successful send —
// the caller records the task identifier in the cursor only on true, so a
// failed publish retries next cycle (spec Failure Modes).
type TaskPublisher interface {
	PublishCreate(ctx context.Context, candidate Candidate) bool
}

// NewTaskPublisher returns a TaskPublisher wrapping the given sender + metrics.
func NewTaskPublisher(
	sender task.CreateCommandSender,
	metrics Metrics,
	cfg TaskConfig,
) TaskPublisher {
	return &taskPublisher{
		sender:  sender,
		metrics: metrics,
		cfg:     cfg,
	}
}

type taskPublisher struct {
	sender  task.CreateCommandSender
	metrics Metrics
	cfg     TaskConfig
}

func (p *taskPublisher) PublishCreate(
	ctx context.Context,
	candidate Candidate,
) bool {
	cmd := BuildCreateCommand(candidate, p.cfg)
	if err := p.sender.SendCommand(ctx, cmd); err != nil {
		glog.Errorf(
			"publish create-task failed repo=%s taskID=%s err=%v",
			candidate.Repo.Key(),
			string(cmd.TaskIdentifier),
			err,
		)
		p.metrics.IncPublished("error")
		return false
	}
	glog.V(2).Infof(
		"published CreateTaskCommand repo=%s taskID=%s stage=%s",
		candidate.Repo.Key(),
		string(cmd.TaskIdentifier),
		p.cfg.Stage,
	)
	p.metrics.IncPublished("create")
	return true
}
```

The second `//counterfeiter:generate` directive generates a fake for the EXTERNAL `task.CreateCommandSender` interface — counterfeiter v6.12.2 supports fully-qualified targets (it splits on the last `.`), so `make precommit`'s `generate` target produces `mocks/create_command_sender.go` with `--fake-name CreateCommandSender`.

`pkg/taskpublisher_test.go` (`package pkg_test`) using `mocks.CreateCommandSender` + `pkg.NewMetrics(prometheus.NewRegistry())`:
- `SendCommand` returns nil → `PublishCreate` returns true and `published_total{status="create"}` == 1; the captured command's `Frontmatter["task_type"]` == "github-update-go" and `Frontmatter["vulns"]` is the candidate's list (spot-check the fork).
- `SendCommand` returns a wrapped error → `PublishCreate` returns false and `published_total{status="error"}` == 1, `{status="create"}` stays 0.

### 5. `pkg/metrics.go` — add `vulns_detected_total`

Package `pkg`. Extend the `Metrics` interface with one method and add a plain (unlabelled) counter:

```go
	// IncVulnsDetected adds n vuln markers found across a cycle (no labels).
	IncVulnsDetected(n int)
```

Add to `metricsImpl` a `vulnsDetected prometheus.Counter` created with `prometheus.NewCounter(prometheus.CounterOpts{Namespace: metricNamespace, Name: "vulns_detected_total", Help: "Total number of vuln markers detected"})`, register it in `NewMetrics`, and implement `IncVulnsDetected(n int) { m.vulnsDetected.Add(float64(n)) }`. Do NOT add a label set for it — it is unlabelled (spec DB 6).

Extend `pkg/metrics_test.go`: after `IncVulnsDetected(3)`, `github_vuln_watcher_vulns_detected_total` == 3.

### 6. `pkg/candidate.go` — the task identifier

Package `pkg`. Add the method and populate the filter projection:

```go
// TaskIdentifier returns the deterministic UUID5 of the candidate's finding
// set, or "" when no vulns are known yet. Seeded from (repo, sorted vuln IDs)
// only — never from the HEAD SHA or a timestamp (spec Constraints).
func (c Candidate) TaskIdentifier() string {
	if len(c.VulnIDs) == 0 {
		return ""
	}
	return DeriveVulnTaskID(c.Repo.Owner, c.Repo.Name, c.VulnIDs).String()
}
```

In `FilterCandidate`, replace the line `TaskIdentifier: "", // populated by the emit layer once the vuln list is known` with:

```go
		TaskIdentifier:  c.TaskIdentifier(),
```

### 7. `pkg/watcher.go` — emit into the per-repo loop

Package `pkg`.

- `NewWatcher` and the `watcher` struct gain the publisher (after the scanner):

```go
func NewWatcher(
	ghClient GitHubClient,
	scanner Scanner,
	publisher TaskPublisher,
	metrics Metrics,
	cursorPath string,
	owner string,
	taskCreationFilter filter.TaskCreationFilter,
) Watcher {
	return &watcher{
		ghClient:           ghClient,
		scanner:            scanner,
		publisher:          publisher,
		metrics:            metrics,
		cursorPath:         cursorPath,
		owner:              owner,
		taskCreationFilter: taskCreationFilter,
	}
}

type watcher struct {
	ghClient           GitHubClient
	scanner            Scanner
	publisher          TaskPublisher
	metrics            Metrics
	cursorPath         string
	owner              string
	taskCreationFilter filter.TaskCreationFilter
}
```

- Extend `processRepos` — replace from `candidate.VulnIDs = scanResult.VulnIDs` through the trailing comment line `// Emit and dedup are added by the remaining spec layers.` (prompt 3's tail ends at that comment; the anchor line stays once) with:

```go
		candidate.VulnIDs = scanResult.VulnIDs
		w.metrics.IncVulnsDetected(len(scanResult.VulnIDs))

		if w.publisher.PublishCreate(ctx, candidate) {
			// The dedup layer (next prompt) records the emitted task
			// identifier in the cursor here, only on a successful publish.
		}
```

Keep `candidate.HeadSHA = scanResult.HeadSHA` exactly where it is (before the `IncVulnsDetected` line). A failed publish returns false and simply does not advance cursor state (next cycle re-emits; the deterministic identifier absorbs the repeat downstream).

Extend `pkg/watcher_test.go` (`package pkg_test`, `mocks.Scanner` + `mocks.TaskPublisher`):
- A consenting repo whose `ScanStub` returns one marker → `PublishCreate` is called exactly once with a candidate carrying that `VulnIDs` list; `vulns_detected_total` == 1 and `poll_cycle_total{result="success"}` == 1.
- A repo with zero markers (`already_clean`) → `PublishCreateCallCount()` stays 0 and `vulns_detected_total` stays 0.
- `PublishCreate` returns false → no cursor advance is observable yet; assert the cycle still counts `success` (a failed publish does not abort the cycle).
- `IncVulnsDetected` receives the marker count (not 1) when a repo has 2 markers.

### 8. `pkg/factory/factory.go` — Kafka sender + full watcher wiring

Package `factory`. Keep `CreateTriggerHandler`, `CreateRouter`, `CreateStaticFilters` from previous prompts. Add `CreateKafkaSender` and replace `CreateWatcher`:

```go
// CreateKafkaSender constructs the typed create-task command sender backed by
// a Kafka sync producer.
func CreateKafkaSender(
	syncProducer libkafka.SyncProducer,
	topicPrefix base.TopicPrefix,
) task.CreateCommandSender {
	sender := cdb.NewCommandObjectSender(syncProducer, topicPrefix, log.DefaultSamplerFactory)
	return task.NewCreateCommandSender(sender, "")
}

// CreateWatcher wires all watcher dependencies. Pure composition — no I/O.
func CreateWatcher(
	githubHTTPClient *http.Client,
	sender task.CreateCommandSender,
	metrics pkg.Metrics,
	cursorPath string,
	owner string,
	stage string,
	taskCreationFilter filter.TaskCreationFilter,
) pkg.Watcher {
	ghClient := pkg.NewGitHubClient(githubHTTPClient)
	scanner := pkg.NewScanner(scanTimeout, "")
	publisher := pkg.NewTaskPublisher(sender, metrics, pkg.TaskConfig{Stage: stage})
	return pkg.NewWatcher(
		ghClient,
		scanner,
		publisher,
		metrics,
		cursorPath,
		owner,
		taskCreationFilter,
	)
}
```

New imports in `factory.go`: `github.com/bborbe/agent/command/task`, `github.com/bborbe/cqrs/base`, `github.com/bborbe/cqrs/cdb`, `libkafka "github.com/bborbe/kafka"`. Keep `scanTimeout` from the previous prompt.

Extend `pkg/factory/factory_test.go` (`package factory_test`, using `mocks.CreateCommandSender`):
- `CreateKafkaSender` cannot be exercised directly in a unit test (building a real `libkafka.SyncProducer` needs a Kafka broker), so assert the WIRING instead: `CreateWatcher(httptest.NewServer(...).Client(), sender, pkg.NewMetrics(prometheus.NewRegistry()), "/tmp/c.json", "bborbe", "dev", factory.CreateStaticFilters(nil))` returns a non-nil `pkg.Watcher`. The publisher/sender seam is covered by `pkg.NewTaskPublisher`'s own tests. Keep the existing `CreateStaticFilters` specs.

### 9. `main.go` — Kafka wiring into Run

Keep the previous prompt's `application` struct, `pollLoop`, `createHTTPServer`, allowlist parse/validate, and `ResolveGitHubClient` steps exactly as they are. Extend `Run`:

- After the `defer httpClient.CloseIdleConnections()` line, add:
  ```go
  syncProducer, err := libkafka.NewSyncProducerWithName(
      ctx,
      libkafka.ParseBrokersFromString(a.KafkaBrokers),
      serviceName,
  )
  if err != nil {
      return errors.Wrapf(ctx, err, "create kafka sync producer")
  }
  defer func() {
      if cerr := syncProducer.Close(); cerr != nil {
          glog.Warningf("close kafka sync producer: %v", cerr)
      }
  }()
  ```
- After `metrics := pkg.NewMetrics(nil)`, add:
  ```go
  sender := factory.CreateKafkaSender(syncProducer, a.TopicPrefix)
  ```
- Replace the `CreateWatcher` call with:
  ```go
  w := factory.CreateWatcher(
      httpClient,
      sender,
      metrics,
      a.CursorPath,
      a.Owner,
      a.Stage,
      factory.CreateStaticFilters(allowlist),
  )
  ```

New import in `main.go`: `libkafka "github.com/bborbe/kafka"`. Keep `base` (for `a.TopicPrefix`).

### 10. CHANGELOG

Append to the `## Unreleased` section in `CHANGELOG.md`:

```
- feat: Emit one github-update-go create-task per finding set under the frozen 12-key contract (vuln_count + sorted vulns payload, dash-form title, deterministic UUID5 task id) via the cqrs create-task command sender, and count publishes on published_total{status=create|error}
```

</requirements>

<constraints>
- Module path is `github.com/bborbe/github-vuln-watcher`.
- **Do NOT touch `k8s/*.yaml`** (deploy-step concern, per spec Non-goal).
- The emit contract is FROZEN (spec Constraints): the 10 consumer keys (`task_type`, `assignee`, `phase`, `status`, `stage`, `task_identifier`, `title`, `repo`, `clone_url`, `ref`) keep their semantics byte-identical to `github-update-go-watcher`; the fork adds `vuln_count` + `vulns` and replaces the `Current Go/Latest Go` body line with the vuln line. The header `# Update Go: <owner>/<repo>`, the two-space middots, the `**HEAD:** <sha[:7]>` line, and the `**Repo:** [...]` line stay byte-identical.
- Title form is frozen dash-form: `Update Go <owner>-<repo> <sha[:7]>` — never a `/` (the CreateCommand validator rejects `/`).
- Task identifier is a deterministic UUID5 from the FROZEN namespace `5c3bcb6b-fb0f-4c61-a4c3-8a17fd037f52`, seeded `vuln-drift-<owner>-<repo>-<sorted-vuln-ids>` — over (repo, sorted vuln IDs) only, never over HEAD SHA or timestamp.
- The `clone_url` frontmatter field is always the frozen SSH form `git@github.com:<owner>/<repo>.git` — never `Repo.CloneURL`.
- Do NOT modify `pkg/metrics.go` label sets or any existing counter — only ADD `IncVulnsDetected` + `vulns_detected_total`.
- Do NOT add a decision-task, completion, or update-scope path — this service is publish-only create-task.
- Never use `fmt.Errorf`; all errors go through `github.com/bborbe/errors` and carry `ctx`.
- Never hand-edit anything under `mocks/`; tests use Ginkgo/Gomega; counterfeiter fakes come from `//counterfeiter:generate` directives.
- Keep every line under 100 characters and every function under 80 lines / 50 statements (`funlen`).
- Every new `.go` file starts with the BSD license header block used by the existing files.
- Do NOT commit — dark-factory handles git.
- Existing tests must still pass.
</constraints>

<verification>
Run from the repo root:

```
make precommit
```

Must exit 0 (this regenerates `mocks/` including `mocks/create_command_sender.go` from the external-interface directive).

```
grep -n 'vulns' pkg/taskbuilder.go
```
Expect at least one hit (the vuln payload fork — spec Verification).

```
grep -n '5c3bcb6b-fb0f-4c61-a4c3-8a17fd037f52' pkg/taskid.go
grep -n 'vuln-drift-' pkg/taskid.go
grep -n 'vulns_detected_total' pkg/metrics.go
```
Each expects at least one line.

```
grep -rn 'task_type.*github-update-go\|"github-update-go"' pkg/taskbuilder.go
grep -n 'NewCreateCommandSender' pkg/factory/factory.go
grep -n 'NewSyncProducerWithName' main.go
```
Each expects at least one hit.

```
ls mocks/create_command_sender.go mocks/task_publisher.go
```
Both must exist after `make precommit`.

```
go test -mod=mod ./pkg/...
```
Must exit 0.
</verification>
