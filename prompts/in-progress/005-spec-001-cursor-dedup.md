---
status: approved
spec: ["001"]
created: "2026-09-03T20:30:00Z"
queued: "2026-09-03T18:43:31Z"
---

<summary>
- The service now persists per-repo dedup state in a JSON cursor file: each repo records the task identifier of its last emitted finding set, and a repo whose computed identifier matches is skipped with reason `finding_set_unchanged`.
- Cursor writes are atomic (temp file + rename, 0600); a missing file is a valid cold start; a corrupt file is renamed `<path>.corrupt` and the cycle cold-starts instead of wedging forever.
- The dedup filter is evaluated AFTER the scan (it needs the computed identifier) and is bypassed entirely on a forced `/trigger` cycle — so `force=true` re-files unchanged finding sets, every other gate still applies.
- A fixture-repo dispatch integration test proves the whole path end-to-end with a real `git` clone and a real `make` invocation: the frozen 12-key contract, the vuln payload, the skip-reason metric deltas, the dedup-on-second-cycle behaviour, and corrupt-cursor recovery.
- The integration test asserts no clone happens for repos skipped by the pre-clone gates, and that clone directories never survive a scan.
- The cursor is single-writer (one cycle at a time, one instance), so no locking is needed beyond the existing CycleGate.
</summary>

<objective>
Close the dedup loop: the JSON cursor (atomic persist, corrupt-file recovery), the `finding_set_unchanged` filter, and the fixture-repo dispatch integration test that proves the acceptance criteria end-to-end (skip-reason deltas, the frozen emit contract, dedup + cursor persistence).
</objective>

<context>
Read `docs/dod.md`.

Read these coding plugin docs before writing code (paths are inside the container):
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-patterns.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-filter-pattern.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-error-wrapping-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-testing-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-mocking-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-test-types-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-security-linting.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/definition-of-done.md`

Read these repo files before writing code:
- `pkg/watcher.go` — `Poll` (this prompt adds the cursor load/save and the force-aware dedup filter) and `processRepos` (this prompt adds the cursor write).
- `pkg/cursor.go` — currently carries only `const DefaultCursorPath`; this prompt adds the full cursor implementation.
- `pkg/candidate.go` — `TaskIdentifier()` and `FilterCandidate()` (populated by the previous prompt; the dedup filter reads `filter.Candidate.TaskIdentifier`).
- `pkg/filter/filter.go` — `TaskCreationFilter`, `TaskCreationFilterList`, `Candidate` (has the `TaskIdentifier` field).
- `pkg/factory/factory.go` — `CreateStaticFilters` and `CreateWatcher` (both unchanged in this prompt — the cursor is file-based and the dedup filter is composed per-cycle).
- `main.go` — unchanged in this prompt.

**Sibling entry-point check (already run):** one binary entry point (`main.go`). No factory or `main.go` signature changes in this prompt.

Spec context you must honor (spec DB 5 + Failure Modes):
- Per-repo state stores `last_emitted_task_identifier`. On each cycle, a repo whose computed task identifier equals the stored one is skipped with reason `finding_set_unchanged` — unchanged finding sets (including unfixable findings) are emitted exactly once.
- Forced `/trigger` cycles bypass ONLY this filter (spec DB 5). Every other gate still applies.
- Cursor writes are atomic (tmp file + rename, 0600); a corrupt cursor is renamed `<path>.corrupt` and the cycle cold-starts; the cursor is single-writer (one cycle at a time, one instance).
- The cursor lives at `CURSOR_PATH` (default `/data/cursor.json`); missing file = fresh empty; unreadable file (permissions) = error → `poll_cycle_total{result="scan_error"}` (spec Failure Modes).
- A failed publish does not advance the repo's cursor entry, so it retries next cycle.

Library API facts (verified — do not re-derive from memory):
- `encoding/json` — `json.Marshal`, `json.Unmarshal`. `os` — `os.ReadFile`, `os.WriteFile`, `os.Rename`, `os.Remove`, `os.IsNotExist`. Sentinel pattern: `stderrors "errors"` + `stderrors.Is`.
- `github.com/bborbe/errors` — `errors.Wrapf(ctx, err, fmt, args...)`.
- `github.com/prometheus/client_golang/prometheus` — `prometheus.NewRegistry()`, `registry.Gather()`; `github.com/prometheus/client_golang/prometheus/testutil` — `testutil.ToFloat64(prometheus.Collector)`.
- Ginkgo v2 — `GinkgoT().TempDir()`, `GinkgoWriter.Printf(...)`, `GinkgoT().Setenv(...)`.
- The `pkg` suite (`pkg/pkg_suite_test.go`) has `suiteConfig.Timeout = 60 * time.Second` — keep the integration fixtures small (echo-only gates, tiny repos) so the whole suite stays under it.
</context>

<requirements>

### 1. `pkg/cursor.go` — the JSON cursor

Package `pkg`. Extend the existing file (which already has `DefaultCursorPath`) with:

```go
// Cursor is the per-repo finding-set dedup state.
//
// Concurrency: not safe for concurrent use. Exactly one cycle runs at a time
// (CycleGate), so the file has a single writer — the cycle loads at start and
// saves at end.
type Cursor struct {
	Repos map[string]*RepoState `json:"repos"` // key: Repo.Key(), "github.com/owner/name"
}

// RepoState is the cursor entry per repo.
type RepoState struct {
	// LastEmittedTaskIdentifier is the deterministic task identifier of the
	// last finding set emitted for this repo. A repo whose computed
	// identifier equals this is skipped with reason "finding_set_unchanged".
	LastEmittedTaskIdentifier string `json:"last_emitted_task_identifier"`
}

// LoadCursor reads cursor state from path.
//
//   - Missing file -> fresh empty cursor, nil error (cold start is valid and
//     re-publishes; downstream dedup by deterministic identifier absorbs it).
//   - Corrupt JSON -> the file is renamed to <path>.corrupt and the cycle
//     cold-starts. This re-files repos already reported, which deterministic
//     UUID5 task identifiers dedup downstream; returning an error here would
//     wedge every cycle indefinitely because nothing rewrites a file that
//     fails to load.
//   - Unreadable file (permissions, I/O) -> error. That is an environment
//     fault, not bad content, and the caller counts poll_cycle_total
//     {result="scan_error"}.
func LoadCursor(ctx context.Context, path string) (*Cursor, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is config-controlled
	if os.IsNotExist(err) {
		glog.V(2).Infof("cursor file not found, cold-start path=%s", path)
		return &Cursor{Repos: make(map[string]*RepoState)}, nil
	}
	if err != nil {
		return nil, errors.Wrapf(ctx, err, "read cursor file path=%s", path)
	}
	c := &Cursor{}
	if err := json.Unmarshal(data, c); err != nil {
		bad := path + ".corrupt"
		if rerr := os.Rename(path, bad); rerr != nil {
			glog.Warningf("preserve corrupt cursor failed path=%s err=%v", path, rerr)
		}
		glog.Warningf("cursor corrupt, cold-starting path=%s saved=%s err=%v", path, bad, err)
		return &Cursor{Repos: make(map[string]*RepoState)}, nil
	}
	if c.Repos == nil {
		c.Repos = make(map[string]*RepoState)
	}
	return c, nil
}

// SaveCursor persists cursor state atomically via temp file + rename, so a
// crash mid-write can never leave a half-written file and no .tmp file
// survives a successful save.
func SaveCursor(ctx context.Context, path string, c *Cursor) error {
	data, err := json.Marshal(c)
	if err != nil {
		return errors.Wrapf(ctx, err, "marshal cursor state path=%s", path)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil { // #nosec G306 -- intentional 0600
		return errors.Wrapf(ctx, err, "write cursor tmp path=%s", tmp)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return errors.Wrapf(ctx, err, "rename cursor tmp path=%s", tmp)
	}
	return nil
}
```

`pkg/cursor_test.go` (`package pkg_test`):
- Save then Load round-trips the `Repos` map (write a `RepoState{LastEmittedTaskIdentifier: "uuid"}` for one key).
- Missing file → fresh cursor with a non-nil `Repos` map, nil error.
- Corrupt JSON (write `"{not json"`) → nil error, the file is renamed to `<path>.corrupt`, and the returned cursor is fresh.
- A path that is a directory → error (robust "unreadable" case regardless of running as root).
- After a successful `SaveCursor`, no `<path>.tmp` file exists.

### 2. `pkg/filter/finding_set_unchanged_filter.go` — the dedup filter

Package `filter`:

```go
//counterfeiter:generate -o ../../mocks/cursor_reader.go --fake-name CursorReader . CursorReader

// CursorReader is the minimal read surface FindingSetUnchangedFilter needs.
// Declared locally (Hollywood principle) so this package never imports
// pkg.Cursor.
type CursorReader interface {
	// LastEmittedTaskIdentifier returns the recorded task identifier for
	// repoKey, or "" if unseen.
	LastEmittedTaskIdentifier(repoKey string) string
}

// NewFindingSetUnchangedFilter returns "finding_set_unchanged" when the
// Candidate's computed task identifier equals the recorded one for the same
// repo. A cold cursor always passes. This filter is evaluated POST-scan (it
// needs the computed identifier) and is omitted entirely on a forced cycle
// (spec DB 5).
func NewFindingSetUnchangedFilter(cursor CursorReader) TaskCreationFilter {
	return TaskCreationFilterFunc(func(candidate Candidate) string {
		if candidate.TaskIdentifier != "" &&
			candidate.TaskIdentifier == cursor.LastEmittedTaskIdentifier(candidate.RepoKey) {
			return "finding_set_unchanged"
		}
		return ""
	})
}
```

Add to `pkg/filter/filter_test.go` (`package filter_test`) using a hand-written stub of `CursorReader`:
- Candidate with `TaskIdentifier` equal to the stored value → `"finding_set_unchanged"`.
- Candidate with a different `TaskIdentifier` → `""`.
- Candidate with empty `TaskIdentifier` → `""` (never skip on an unknown identifier).
- CursorReader returns `""` (unseen repo) → `""`.

### 3. `pkg/cursorreader.go` — filter-compatible cursor view

Package `pkg`:

```go
// NewCursorReader exposes a filter-compatible read view over a Cursor.
func NewCursorReader(c *Cursor) filter.CursorReader {
	return &cursorReader{c: c}
}

type cursorReader struct{ c *Cursor }

func (r *cursorReader) LastEmittedTaskIdentifier(repoKey string) string {
	if r.c == nil || r.c.Repos == nil {
		return ""
	}
	entry := r.c.Repos[repoKey]
	if entry == nil {
		return ""
	}
	return entry.LastEmittedTaskIdentifier
}
```

### 4. `pkg/watcher.go` — cursor + dedup into the cycle

Package `pkg`.

- Replace the `Poll` body so it loads the cursor, composes the force-aware dedup filter, saves the cursor, and routes cursor faults to `scan_error`:

```go
func (w *watcher) Poll(ctx context.Context, force bool) error {
	cursorState, err := LoadCursor(ctx, w.cursorPath)
	if err != nil {
		w.metrics.IncPollCycle("scan_error")
		glog.Errorf(
			"poll cycle aborted: load cursor path=%s err=%v",
			w.cursorPath,
			err,
		)
		return nil
	}

	repos, err := w.ghClient.ListRepos(ctx, w.owner)
	if err != nil {
		if stderrors.Is(err, ErrRateLimited) {
			w.metrics.IncPollCycle("rate_limited")
			glog.Warningf(
				"poll cycle aborted: rate limited during ListRepos owner=%s",
				w.owner,
			)
		} else {
			w.metrics.IncPollCycle("github_error")
			glog.Warningf(
				"poll cycle aborted: ListRepos owner=%s err=%v",
				w.owner,
				err,
			)
		}
		return nil
	}

	w.metrics.IncReposScanned(len(repos))

	// The finding-set dedup filter is evaluated post-scan (it needs the
	// computed task identifier) and is omitted entirely on a forced cycle
	// (spec DB 5). An empty dedupFilter never skips.
	dedupFilter := filter.TaskCreationFilterList{}
	if !force {
		dedupFilter = append(
			dedupFilter,
			filter.NewFindingSetUnchangedFilter(NewCursorReader(cursorState)),
		)
	}

	if abortReason := w.processRepos(
		ctx,
		cursorState,
		repos,
		w.taskCreationFilter,
		dedupFilter,
	); abortReason != "" {
		w.metrics.IncPollCycle(abortReason)
		return nil
	}

	if err := SaveCursor(ctx, w.cursorPath, cursorState); err != nil {
		w.metrics.IncPollCycle("scan_error")
		glog.Errorf(
			"poll cycle aborted: save cursor path=%s err=%v",
			w.cursorPath,
			err,
		)
		return nil
	}

	w.metrics.IncPollCycle("success")
	glog.V(2).Infof("poll cycle complete result=success")
	return nil
}
```

- Extend `processRepos`: change the signature to add `cursorState *Cursor` and `dedupFilter filter.TaskCreationFilter`, insert the post-scan dedup check, and record the cursor entry only on a successful publish:

```go
func (w *watcher) processRepos(
	ctx context.Context,
	cursorState *Cursor,
	repos []Repo,
	cycleFilter filter.TaskCreationFilter,
	dedupFilter filter.TaskCreationFilter,
) string {
```

Inside the loop, after `w.metrics.IncVulnsDetected(len(scanResult.VulnIDs))` and before the publish, insert:

```go
		// Finding-set dedup: evaluated post-scan because it needs the
		// computed task identifier. An empty dedupFilter (forced cycle)
		// never skips.
		if reason := dedupFilter.Skip(candidate.FilterCandidate()); reason != "" {
			w.metrics.IncFilterSkipped(reason)
			glog.V(2).Infof(
				"repo skipped repo=%s reason=%s",
				repo.Key(),
				reason,
			)
			continue
		}
```

Replace the publish block:

```go
		if w.publisher.PublishCreate(ctx, candidate) {
			if cursorState.Repos == nil {
				cursorState.Repos = make(map[string]*RepoState)
			}
			cursorState.Repos[repo.Key()] = &RepoState{
				LastEmittedTaskIdentifier: candidate.TaskIdentifier(),
			}
		}
```

`pkg/watcher_test.go` (`package pkg_test`, `mocks.Scanner` + `mocks.TaskPublisher` + `mocks.GitHubClient`), new specs:
- First `Poll` with a marker → the cursor file exists and contains `last_emitted_task_identifier`; second `Poll` → `filter_skipped_total{reason="finding_set_unchanged"}` == 1 and the publisher is NOT called again.
- `Poll(ctx, true)` (forced) on the same state → the publisher IS called again (dedup bypassed), `finding_set_unchanged` stays 0.
- A corrupt cursor file → `Poll` completes (success), `<path>.corrupt` exists.
- A `LoadCursor` fault: make `cursorPath` point at a directory → `Poll` counts `poll_cycle_total{result="scan_error"}` and returns nil.
- Publish fails (`TaskPublisherStub` returns false) → `published_total{status="error"}` == 1, the repo's cursor entry is absent (not advanced), and a second `Poll` calls the publisher again (re-emitted next cycle — spec DB 5 failure mode).
- `SaveCursor` fault → `poll_cycle_total{result="scan_error"}`: point `cursorPath` at a non-existent parent directory (e.g. `<tmp>/nonexistent-dir/cursor.json`) — `LoadCursor` cold-starts on `IsNotExist`, then `SaveCursor` fails on the tmp-file write.

### 5. `pkg/dispatch_integration_test.go` — the fixture-repo dispatch round-trip

`package pkg_test`. This is the evidence for acceptance criteria 2, 3, 4, and 5. It uses a REAL `git` clone, a REAL `make` invocation, a fake GitHub client, and a mock Kafka sender.

Fixture helper (same `git`-commit technique as the scanner tests — env-overridden author/committer, no global git config needed):

```go
// writeDispatchFixtureRepo creates a real git repo at a temp path.
// maintainer is written to .maintainer.yaml (skip by passing ""); markers is
// the vuln-marker list the repo's own `make vulncheck` gate prints before
// exiting 1 (empty list = gate exits 0).
func writeDispatchFixtureRepo(
	name string,
	maintainer string,
	markers []string,
) string {
	dir := filepath.Join(GinkgoT().TempDir(), name)
	Expect(os.MkdirAll(dir, 0o755)).To(Succeed())
	if maintainer != "" {
		Expect(os.WriteFile(
			filepath.Join(dir, ".maintainer.yaml"),
			[]byte(maintainer), 0o644,
		)).To(Succeed())
	}
	Expect(os.WriteFile(
		filepath.Join(dir, "go.mod"),
		[]byte("module example.com/fixture\n\ngo 1.24.0\n"), 0o644,
	)).To(Succeed())
	var vulncheck string
	if len(markers) == 0 {
		vulncheck = "vulncheck:\n\t@echo \"no vulns\"\n"
	} else {
		var b strings.Builder
		b.WriteString("vulncheck:\n")
		for _, m := range markers {
			fmt.Fprintf(&b,
				"\t@echo \"%s\\tgithub.com/example/mod@v1.0.0 -> v1.0.1\\tsummary\"\n",
				m)
		}
		b.WriteString("\t@exit 1\n")
		vulncheck = b.String()
	}
	makefile := vulncheck + "check:\n\t@echo \"check ok\"\n"
	Expect(os.WriteFile(
		filepath.Join(dir, "Makefile"),
		[]byte(makefile), 0o644,
	)).To(Succeed())
	runGit := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
		out, err := cmd.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), "git %v: %s", args, out)
	}
	runGit("init", "-b", "master")
	runGit("add", ".")
	runGit("commit", "-m", "init")
	return dir
}
```

Metric read helper (same file):

```go
func metricValue(reg *prometheus.Registry, name string, labels map[string]string) float64 {
	mfs, err := reg.Gather()
	Expect(err).NotTo(HaveOccurred())
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			match := true
			for _, lp := range m.GetLabel() {
				if labels[lp.GetName()] != lp.GetValue() {
					match = false
				}
			}
			if match {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}
```

A setup helper shared by the two `Describe` blocks:

```go
type dispatchHarness struct {
	watcher    pkg.Watcher
	scanner    *mocks.Scanner
	sent       []task.CreateCommand
	cursorPath string
	scanRoot   string
	registry   *prometheus.Registry
	metrics    pkg.Metrics
}

func newDispatchHarness(repos []pkg.Repo, allowlist []string) *dispatchHarness {
	registry := prometheus.NewRegistry()
	metrics := pkg.NewMetrics(registry)
	h := &dispatchHarness{
		cursorPath: filepath.Join(GinkgoT().TempDir(), "cursor.json"),
		scanRoot:   filepath.Join(GinkgoT().TempDir(), "scans"),
		registry:   registry,
		metrics:    metrics,
	}

	ghClient := &mocks.GitHubClient{}
	ghClient.ListReposReturns(repos, nil)
	ghClient.GetGoModStub = func(_ context.Context, _ pkg.Repo) ([]byte, error) {
		return []byte("module example.com/fixture\n\ngo 1.24.0\n"), nil
	}
	ghClient.GetMaintainerConfigStub = func(
		_ context.Context,
		repo pkg.Repo,
	) (filter.Consent, error) {
		switch repo.Name {
		case "fixture-repo":
			return filter.GrantedConsent, nil
		case "opted-out-repo":
			return filter.RefusedConsent, nil
		default:
			return filter.UndecidedConsent, nil
		}
	}

	realScanner := pkg.NewScanner(time.Minute, h.scanRoot)
	h.scanner = &mocks.Scanner{}
	h.scanner.ScanStub = realScanner.Scan // real clone + real make, call-counted

	sender := &mocks.CreateCommandSender{}
	sender.SendCommandStub = func(_ context.Context, cmd task.CreateCommand) error {
		h.sent = append(h.sent, cmd)
		return nil
	}
	publisher := pkg.NewTaskPublisher(sender, metrics, pkg.TaskConfig{Stage: "dev"})

	h.watcher = pkg.NewWatcher(
		ghClient,
		h.scanner,
		publisher,
		metrics,
		h.cursorPath,
		"fixture-owner",
		factory.CreateStaticFilters(allowlist),
	)
	return h
}
```

**`Describe("dispatch round-trip", ...)`** — evidence for ACs 3, 4, 5. `BeforeEach`: build the harness with ONE repo — the consenting fixture — and `allowlist == nil` (allow-all):

```go
fixtureDir := writeDispatchFixtureRepo(
	"fixture-repo",
	"goUpdate:\n  autoUpdate: true\n",
	[]string{"GO-2024-1234", "GO-2024-5678"},
)
repo := pkg.Repo{
	Owner: "fixture-owner", Name: "fixture-repo", DefaultBranch: "master",
	CloneURL: fixtureDir,
}
```

`It("publishes exactly one create-task per finding set and dedups the next cycle", ...)`:
1. `Expect(h.watcher.Poll(ctx, false)).To(Succeed())`.
2. `Expect(h.sent).To(HaveLen(1))` — take `cmd := h.sent[0]` and assert the FULL frozen contract:
   - `cmd.Frontmatter` has 12 keys.
   - `cmd.Frontmatter["task_type"] == "github-update-go"`, `["assignee"] == "github-update-go-agent"`, `["phase"] == "planning"`, `["status"] == "in_progress"`, `["stage"] == "dev"`, `["repo"] == "fixture-owner/fixture-repo"`, `["clone_url"] == "git@github.com:fixture-owner/fixture-repo.git"`, `["vuln_count"] == 2`.
   - `cmd.Frontmatter["ref"]` matches `^[0-9a-f]{40}$` and equals the fixture's HEAD (run `git rev-parse HEAD` in `fixtureDir` via `exec.Command`).
   - `cmd.Frontmatter["vulns"]` equals `[]string{"GO-2024-1234", "GO-2024-5678"}` (contains `GO-2024-1234` — AC 3 evidence).
   - `cmd.Frontmatter["task_identifier"]` is a UUID v5.
   - `cmd.Validate(context.Background())` returns nil — traverses the real CreateCommand validator boundary (title forbidden-chars, edges, body length) that the production publish path checks before Kafka; the mock sender bypasses `NewCreateCommandSender`, so this assertion is the only place the validator sees the real values.
   - `cmd.Title == "Update Go fixture-owner-fixture-repo " + cmd.Frontmatter["ref"].(string)[:7]` and `cmd.Title` contains no `/` (AC 4 — `grep -c '/'` == 0 equivalent).
   - `cmd.Body` contains `"# Update Go: fixture-owner/fixture-repo"`, the vuln line `"**Vulnerabilities:** GO-2024-1234  ·  GO-2024-5678"`, `"**HEAD:** " + ref[:7]`, and `"**Repo:** [fixture-owner/fixture-repo](https://github.com/fixture-owner/fixture-repo)"`.
3. Metrics after the first cycle: `metricValue(registry, "github_vuln_watcher_published_total", {"status":"create"})` == 1; `..._vulns_detected_total` (empty labels) == 2; `..._poll_cycle_total` `{"result":"success"}` == 1.
4. Cursor persistence: read `h.cursorPath` and `Expect(string(data)).To(ContainSubstring("last_emitted_task_identifier"))` (AC 5 evidence).
5. Clone cleanup: `entries, _ := os.ReadDir(h.scanRoot)`; `Expect(entries).To(BeEmpty())` (clone dir removed after the scan).
6. Second `Poll` (unchanged finding set): `Expect(h.sent).To(HaveLen(1))` (no new command — negative kafka evidence, AC 5); `metricValue(..., "filter_skipped_total", {"reason":"finding_set_unchanged"})` == 1; `metricValue(..., "published_total", {"status":"create"})` still == 1.
7. Corrupt-cursor recovery: `os.WriteFile(h.cursorPath, []byte("{not json"), 0o600)`; third `Poll` succeeds; `Expect(h.cursorPath + ".corrupt").To(BeAnExistingFile())`; `metricValue(..., "poll_cycle_total", {"result":"success"})` == 3.
8. Evidence printing for the spec's Verification requirement: `GinkgoWriter.Printf("fixture vuln marker: %v\n", cmd.Frontmatter["vulns"])` and `GinkgoWriter.Printf("filter_skipped_total finding_set_unchanged=%v\n", metricValue(...))`.

`It("re-files an unchanged finding set on a forced cycle", ...)` (spec DB 5 — `force` bypasses only the dedup filter):
1. First `Poll(ctx, false)` → `h.sent` has 1 command.
2. `Poll(ctx, true)` → `h.sent` has 2 commands (the dedup filter was omitted), and `filter_skipped_total{reason="finding_set_unchanged"}` stays 0.

**`Describe("pre-clone inventory gates", ...)`** — evidence for AC 2. `BeforeEach`: build the harness with FOUR fixture repos and an allowlist that admits the consenting repo plus the two consent-failing repos, excluding only the out-of-scope one (the frozen chain is allowlist → consent → go.mod, and `repoallowlist.IsAllowed` matches exactly, so a non-admitted repo skips with `scope` before consent is ever consulted):

```go
allowlist := filter.ParseRepoAllowlist("github.com/fixture-owner/fixture-repo,github.com/fixture-owner/no-maintainer-repo,github.com/fixture-owner/opted-out-repo")
```

- `fixture-repo` (consenting): maintainer `"goUpdate:\n  autoUpdate: true\n"`, markers `[]string{"GO-2024-1234", "GO-2024-5678"}`, CloneURL set.
- `no-maintainer-repo`: maintainer `""` (no `.maintainer.yaml`), markers `[]string{}`.
- `opted-out-repo`: maintainer `"goUpdate:\n  autoUpdate: false\n"`, markers `[]string{}`.
- `out-of-scope-repo`: maintainer `"goUpdate:\n  autoUpdate: true\n"`, markers `[]string{}`.

`It("skips ineligible repos before any clone with the named reasons", ...)`:
1. `Expect(h.watcher.Poll(ctx, false)).To(Succeed())`.
2. `metricValue(registry, "github_vuln_watcher_filter_skipped_total", {"reason":"auto_update_disabled"})` == 2 (AC 2 — the no-maintainer and the opted-out repos).
3. `metricValue(registry, "github_vuln_watcher_filter_skipped_total", {"reason":"scope"})` == 1 (AC 2 — the out-of-scope repo).
4. `metricValue(registry, "github_vuln_watcher_filter_skipped_total", {"reason":"no_gomod"})` == 0.
5. **No clone for skipped repos (negative clone-dir check, AC 2):** `Expect(h.scanner.ScanCallCount()).To(Equal(1))` and `Expect(h.scanner.ScanArgsForCall(0).Key()).To(Equal("github.com/fixture-owner/fixture-repo"))` — the real scanner (which clones) was invoked only for the consenting repo; the three ineligible repos never reached it.
6. The consenting repo still emitted: `Expect(h.sent).To(HaveLen(1))` and `metricValue(..., "published_total", {"status":"create"})` == 1.
7. Evidence printing: `GinkgoWriter.Printf("filter_skipped_total auto_update_disabled=%v scope=%v\n", ...)`.

### 6. CHANGELOG

Append to the `## Unreleased` section in `CHANGELOG.md`:

```
- feat: Add the JSON cursor (atomic tmp+rename persist, corrupt -> .corrupt recovery) and the finding_set_unchanged dedup filter, with a fixture-repo dispatch integration test proving the emit contract, skip-reason deltas and dedup end-to-end
```

</requirements>

<constraints>
- Module path is `github.com/bborbe/github-vuln-watcher`.
- **Do NOT touch `k8s/*.yaml`** (deploy-step concern, per spec Non-goal).
- No factory or `main.go` changes in this prompt — the cursor is file-based (path already wired) and the dedup filter is composed per-cycle inside `Poll`.
- The cursor JSON key is frozen: `last_emitted_task_identifier` (spec DB 5 / AC 5 evidence). Do not rename it.
- The dedup filter bypass applies ONLY on a forced cycle; every other gate (allowlist, consent, go.mod presence, scan outcomes) still applies when `force=true`.
- Do NOT add cursor-editing admin endpoints (`/resetcursor`, `/setcursor`) — spec Non-goal.
- The integration test must use the REAL `pkg.NewScanner` (real `git` + real `make`) with a real publisher and mock `task.CreateCommandSender` — do not substitute a fake scanner or a fake task builder, or the round-trip evidence is void.
- Never use `fmt.Errorf`; all errors go through `github.com/bborbe/errors` and carry `ctx`.
- Never hand-edit anything under `mocks/`; tests use Ginkgo/Gomega; counterfeiter fakes come from `//counterfeiter:generate` directives.
- Keep every line under 100 characters and every function under 80 lines / 50 statements (`funlen`). The integration file's helper functions are exempt from `funlen` only if unavoidable — prefer extracting small helpers.
- Every new `.go` file starts with the BSD license header block used by the existing files.
- Do NOT commit — dark-factory handles git.
- Existing tests must still pass.
</constraints>

<verification>
Run from the repo root:

```
make precommit
```

Must exit 0.

```
grep -n 'last_emitted_task_identifier' pkg/cursor.go
grep -n 'finding_set_unchanged' pkg/filter/finding_set_unchanged_filter.go
grep -n 'NewFindingSetUnchangedFilter' pkg/watcher.go
```
Each expects at least one line (spec Verification for the cursor key).

```
grep -rn 'GO-2024-1234\|GO-2024-5678' pkg/dispatch_integration_test.go
grep -rn 'finding_set_unchanged' pkg/dispatch_integration_test.go
grep -rn 'ScanCallCount' pkg/dispatch_integration_test.go
```
Each expects at least one hit (the fixture markers, the dedup assertion, and the no-clone-for-skipped assertion).

```
go test -mod=mod -v ./pkg/... 2>&1 | grep -E 'GO-2024-|filter_skipped_total'
```
Must produce output containing the fixture's `GO-2024-` marker id and the `filter_skipped_total` deltas (spec Verification: "its stdout must contain the fixture's GO-2024-XXXX id and the filter_skipped_total deltas from AC 2").

```
go test -mod=mod ./pkg/...
```
Must exit 0.
</verification>
