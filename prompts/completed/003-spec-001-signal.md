---
status: completed
spec: ["001"]
summary: 'Added the signal stage: a Scanner that full-clones each consenting repo (env allowlist HOME+PATH), runs the repo''s own make vulncheck + make check under a hard timeout, and classifies GO-/CVE- markers into a canonical list; wired it into the watcher per-repo loop and the factory with clone_failed / gate_timeout / scan_failed / already_clean outcomes'
execution_id: github-vuln-watcher-vuln-drift-watcher-exec-003-spec-001-signal
dark-factory-version: dev
created: "2026-09-03T20:30:00Z"
queued: "2026-09-03T18:43:31Z"
started: "2026-09-03T18:56:48Z"
completed: "2026-09-03T19:04:31Z"
---

<summary>
- For each consenting repo the service now clones it fresh (full clone via the real `git` binary, never shallow) into an ephemeral directory and runs the repo's OWN `make vulncheck` and `make check`, capturing combined output.
- The scan stage is NOT a vuln scanner: it never invokes govulncheck/trivy/osv-scanner directly and never parses `VULNCHECK_IGNORE`, `.trivyignore`, or `.osv-scanner.toml` — the repo's own gates apply their own suppression.
- Gate subprocesses receive only an allowlisted environment (`HOME` + `PATH`), never the watcher's full environment, so a malicious Makefile cannot read Kafka or GitHub credentials.
- The whole per-repo operation (clone + both gates) is bounded by a hard 20-minute timeout that kills hung subprocesses; the clone directory is always removed when the scan finishes.
- Every `GO-\d+` and `CVE-\d+` marker in the combined gate output is extracted, deduplicated, and sorted into a canonical list; a red gate with no markers is classified as a scan failure, not a vuln signal.
- The clone also yields the repo's full 40-char HEAD SHA, which later prompts stamp into the emitted task (`ref`, title).
- Failures classify into three labelled outcomes: `clone_failed`, `gate_timeout`, and `scan_failed` — each retried next cycle, never fatal to the rest of the cycle.
</summary>

<objective>
Add the signal stage: an ephemeral full clone of each consenting repo followed by the repo's own `make vulncheck` + `make check` under a hard 20-minute timeout, with `GO-\d+`/`CVE-\d+` marker classification into a canonical sorted list and the HEAD SHA. The watcher's per-repo loop now runs the scan and routes its outcomes to the correct skip reasons.
</objective>

<context>
Read `docs/dod.md`.

Read these coding plugin docs before writing code (paths are inside the container):
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-patterns.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-error-wrapping-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-testing-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-mocking-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-security-linting.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-context-cancellation-in-loops.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/definition-of-done.md`

Read these repo files before writing code:
- `pkg/watcher.go` — `processRepos` (this prompt inserts the scan step into its loop) and `NewWatcher` (this prompt adds the scanner collaborator).
- `pkg/repo.go` — `Repo` with the `CloneURL` field the scanner clones from.
- `pkg/candidate.go` — `Candidate` already has `HeadSHA` and `VulnIDs` fields the scan result fills.
- `pkg/factory/factory.go` — `CreateWatcher` (this prompt constructs the scanner inside it; the signature is unchanged).
- `pkg/metrics.go` — `IncFilterSkipped` and the frozen `FilterSkipReasons` set.

**Sibling entry-point check (already run):** one binary entry point (`main.go`). The `CreateWatcher` signature does NOT change in this prompt, so `main.go` is untouched.

Spec context you must honor:
- Signal source is `Makefile.precommit`'s gates as they exist today: `make vulncheck` runs govulncheck in JSON mode, honors `VULNCHECK_IGNORE`, and exits 1 printing `OSV\tmodule@version -> fixed_version\tsummary` lines on unignored findings; `make check = lint vet errcheck vulncheck osv-scanner gosec trivy`. The classification extracts markers from captured output; the `VULNCHECK_IGNORE` default list and the govulncheck known-benign panic handling are the REPOS' OWN business — the watcher never applies or reimplements them.
- `os/exec` is allowed ONLY for (a) `git clone` and (b) invoking the repo's own `make vulncheck` / `make check`. Never shell out to a vuln scanner directly.
- Full clone (not shallow) with env allowlist `HOME`+`PATH`; gate subprocesses never receive the watcher's full environment.
- The clone directory is removed when the repo's scan finishes.

Library API facts (verified — do not re-derive from memory):
- `os/exec` — `exec.CommandContext(ctx, name, args...)` (kills the process when ctx is done), `cmd.Env`, `cmd.Dir`, `cmd.CombinedOutput()`, `cmd.Output()`. Exec-start failures return `*exec.Error`; non-zero exits return `*exec.ExitError`.
- `github.com/bborbe/errors` — `errors.Wrapf(ctx, err, fmt, args...)`. Sentinels via `stderrors "errors"` + `stderrors.Is`.
- `os.MkdirTemp(dir, pattern)`, `os.RemoveAll`, `os.Getenv`, `strings.Builder`, `regexp.MustCompile`, `sort.Strings`, `strings.TrimSpace`.
</context>

<requirements>

### 1. `pkg/scanner.go` — clone + gates + classification

Package `pkg`. No new module dependencies (stdlib `os/exec` only).

```go
// ErrCloneFailed is returned when the git clone of a repo fails (exec error
// or non-zero exit). Callers map it to filter reason "clone_failed".
var ErrCloneFailed = stderrors.New("git clone failed")

// ErrGateTimeout is returned when the per-repo time bound expires during the
// clone or one of the repo's gates. Callers map it to "gate_timeout".
var ErrGateTimeout = stderrors.New("gate timed out")

// ErrScanFailed is returned when a gate cannot run, or a gate exits non-zero
// with no vuln markers (a broken repo is not a vuln-drift signal). Callers
// map it to "scan_failed".
var ErrScanFailed = stderrors.New("gate scan failed")

// goMarkerPattern and cveMarkerPattern match the two marker families the
// classification extracts from gate output.
var (
	goMarkerPattern = regexp.MustCompile(`GO-\d+`)
	cveMarkerPattern = regexp.MustCompile(`CVE-\d+`)
)

// ScanResult is the outcome of scanning one repo: its HEAD SHA and the
// canonical (deduped, sorted) vuln marker list found in the gate output.
type ScanResult struct {
	HeadSHA string
	VulnIDs []string
}

//counterfeiter:generate -o ../mocks/scanner.go --fake-name Scanner . Scanner

// Scanner clones a repo and runs its own vuln gates. It is NOT a vuln
// scanner: suppression (VULNCHECK_IGNORE, .trivyignore, .osv-scanner.toml)
// is applied only by the repo's own gates, never here.
type Scanner interface {
	// Scan clones repo (full clone from repo.CloneURL, never shallow) into
	// an ephemeral directory, runs the repo's own `make vulncheck` and
	// `make check`, and returns the canonical marker list plus the cloned
	// HEAD SHA.
	//
	// Classified errors (callers map to skip reasons):
	//   - ErrCloneFailed  -> "clone_failed"  (git clone exec error or non-zero exit)
	//   - ErrGateTimeout  -> "gate_timeout"  (the per-repo bound expired during clone or a gate)
	//   - ErrScanFailed   -> "scan_failed"   (a gate could not run, or a gate exited non-zero with no markers)
	//   - (ScanResult{}, nil) -> "already_clean" (both gates ran and no markers were found)
	Scan(ctx context.Context, repo Repo) (ScanResult, error)
}

// NewScanner returns a Scanner that clones with the git binary and runs the
// repo's own gates. gateTimeout is the hard bound for the whole per-repo scan
// (clone + both gates) — 20 minutes in production wiring. tempDir is the
// parent for the ephemeral clone directories ("" = system temp; fixture tests
// pass a dedicated root to assert clone-dir cleanup).
func NewScanner(gateTimeout time.Duration, tempDir string) Scanner {
	return &scanner{
		gateTimeout: gateTimeout,
		tempDir:     tempDir,
	}
}

type scanner struct {
	gateTimeout time.Duration
	tempDir     string
}

// scanEnv is the subprocess environment allowlist. Gate subprocesses run the
// repo's own Makefile, which is attacker-controlled code, so they never
// receive the watcher's full environment (which contains Kafka and GitHub
// credentials). HOME+PATH is all `git` and `make` need.
func scanEnv() []string {
	return []string{
		"HOME=" + os.Getenv("HOME"),
		"PATH=" + os.Getenv("PATH"),
	}
}
```

Implement `Scan` with exactly this algorithm:

1. `ctx, cancel := context.WithTimeout(ctx, s.gateTimeout)`; `defer cancel()`.
2. `cloneDir, err := os.MkdirTemp(s.tempDir, "github-vuln-watcher-*")`; on error return `ScanResult{}, errors.Wrapf(ctx, err, "create clone dir for %s", repo.Key())`. `defer` `os.RemoveAll(cloneDir)` (log a warning if removal fails — the clone dir must never survive the scan, spec DB 3).
3. Resolve the clone URL: `cloneURL := repo.CloneURL; if cloneURL == "" { cloneURL = fmt.Sprintf("git@github.com:%s/%s.git", repo.Owner, repo.Name) }`.
4. Clone: `clone := exec.CommandContext(ctx, "git", "clone", cloneURL, cloneDir)`; `clone.Env = scanEnv()`; `out, cerr := clone.CombinedOutput()`. On error: if `ctx.Err() != nil` return `ErrGateTimeout`, else log `glog.Warningf("git clone failed repo=%s err=%v out=%s", repo.Key(), cerr, out)` and return `ErrCloneFailed`. This is a FULL clone — never pass `--depth` or any shallow flag.
5. Run both gates, capturing combined output into one `strings.Builder`, and record whether any gate failed:
   ```go
   var combined strings.Builder
   anyGateFailed := false
   for _, target := range []string{"vulncheck", "check"} {
       gate := exec.CommandContext(ctx, "make", target)
       gate.Dir = cloneDir
       gate.Env = scanEnv()
       out, gerr := gate.CombinedOutput()
       combined.Write(out)
       if gerr != nil {
           if ctx.Err() != nil {
               return ScanResult{}, ErrGateTimeout
           }
           // exec-start failure (make missing, no Makefile) and non-zero exit
           // are both recorded here; classification below decides whether this
           // is a vuln-drift signal.
           anyGateFailed = true
       }
   }
   ```
6. Classify:
   ```go
   markers := extractMarkers(combined.String())
   if len(markers) == 0 {
       if anyGateFailed {
           return ScanResult{}, ErrScanFailed
       }
       return ScanResult{}, nil // both gates green, no markers -> "already_clean"
   }
   headSHA, err := gitHeadSHA(ctx, cloneDir)
   if err != nil {
       return ScanResult{}, ErrScanFailed
   }
   return ScanResult{HeadSHA: headSHA, VulnIDs: markers}, nil
   ```

Add the two helpers:

```go
// extractMarkers returns the deduped, lexicographically-sorted list of
// GO-\d+ / CVE-\d+ markers in output.
func extractMarkers(output string) []string {
	seen := make(map[string]struct{})
	for _, re := range []*regexp.Regexp{goMarkerPattern, cveMarkerPattern} {
		for _, m := range re.FindAllString(output, -1) {
			seen[m] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// gitHeadSHA returns the full HEAD SHA of the repo in dir.
func gitHeadSHA(ctx context.Context, dir string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	cmd.Dir = dir
	cmd.Env = scanEnv()
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
```

`stderrors "errors"` is required for the sentinel declarations above; `bufio` is not needed.

### 2. `pkg/scanner_test.go` — real git + real make

`package pkg_test`. Add the fixture helper (the container has real `git` and real `make`):

```go
// writeFixtureRepo creates a real git repo at a temp path whose Makefile is
// exactly makefile. Returns the repo path (usable as a Repo.CloneURL).
func writeFixtureRepo(makefile string) string {
	dir := filepath.Join(GinkgoT().TempDir(), "fixture")
	Expect(os.MkdirAll(dir, 0o755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.com/fixture\n\ngo 1.24.0\n"), 0o644)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "Makefile"),
		[]byte(makefile), 0o644)).To(Succeed())
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

(Note the `0o` octal literals and the `GIT_AUTHOR_*` env override so the commit works without global git config. Makefile bodies MUST use literal tab characters inside the Go string, i.e. `"\t@"` — make rejects spaces.)

The specs, using `pkg.NewScanner(gateTimeout, tempDir)`:

- `"returns the canonical marker list from a repo whose vulncheck gate exits 1"`: Makefile `"vulncheck:\n\t@echo \"GO-2024-5678\\tgithub.com/example/mod2@v1.2.0 -> v1.2.1\\tsummary\"\n\t@echo \"GO-2024-1234\\tgithub.com/example/mod@v1.0.0 -> v1.0.1\\tsummary\"\n\t@exit 1\ncheck:\n\t@echo \"check ok\"\n"`. `Scan(ctx, Repo{Owner:"fixture-owner", Name:"fixture-repo", CloneURL: dir})` returns `VulnIDs == []string{"GO-2024-1234", "GO-2024-5678"}` (deduped + sorted) and `HeadSHA` matching `^[0-9a-f]{40}$`.
- `"extracts CVE markers too"`: a gate prints `CVE-2025-1234` → `VulnIDs == []string{"CVE-2025-1234"}`.
- `"dedupes repeated markers"`: a gate prints `GO-2024-5678` twice → `VulnIDs == []string{"GO-2024-5678"}`.
- `"already_clean when both gates are green"`: Makefile `"vulncheck:\n\t@echo \"no vulns\"\ncheck:\n\t@echo \"check ok\"\n"` → `Scan` returns `(ScanResult{}, nil)` and the clone dir is removed.
- `"scan_failed on a red gate with no markers"`: Makefile `"vulncheck:\n\t@echo \"lint error\"\n\t@exit 1\ncheck:\n\t@echo \"check ok\"\n"` → `stderrors.Is(err, ErrScanFailed)`.
- `"scan_failed when a make target is missing"`: Makefile `"check:\n\t@echo \"check ok\"\n"` (no `vulncheck` target) → `stderrors.Is(err, ErrScanFailed)`.
- `"clone_failed on a bad clone URL"`: `Scan(ctx, Repo{CloneURL: filepath.Join(GinkgoT().TempDir(), "does-not-exist")})` → `stderrors.Is(err, ErrCloneFailed)`.
- `"gate_timeout kills a hanging gate"`: Makefile `"vulncheck:\n\t@sleep 100\ncheck:\n\t@echo \"check ok\"\n"` with `gateTimeout = 100 * time.Millisecond` → `stderrors.Is(err, ErrGateTimeout)`.
- `"removes the clone directory after the scan"`: scan `tempDir` (a fresh `GinkgoT().TempDir()` subdir) has zero entries after `Scan` returns.
- `"gate subprocess sees only the allowlisted environment"`: `GinkgoT().Setenv("VULN_WATCHER_SECRET", "s3cr3t")`; Makefile `"vulncheck:\n\t@test -z \"$$VULN_WATCHER_SECRET\" && echo \"no-secret-leak\"\ncheck:\n\t@echo \"check ok\"\n"` → `Scan` returns `(ScanResult{}, nil)` (already_clean). If the secret leaked into the gate env, `test -z` would fail, the gate would exit non-zero with no markers, and `Scan` would return `ErrScanFailed` — so `nil` proves the env allowlist.

### 3. `pkg/watcher.go` — run the scan in the per-repo loop

Package `pkg`.

- `NewWatcher` and the `watcher` struct gain the scanner:

```go
func NewWatcher(
	ghClient GitHubClient,
	scanner Scanner,
	metrics Metrics,
	cursorPath string,
	owner string,
	taskCreationFilter filter.TaskCreationFilter,
) Watcher {
	return &watcher{
		ghClient:           ghClient,
		scanner:            scanner,
		metrics:            metrics,
		cursorPath:         cursorPath,
		owner:              owner,
		taskCreationFilter: taskCreationFilter,
	}
}

type watcher struct {
	ghClient           GitHubClient
	scanner            Scanner
	metrics            Metrics
	cursorPath         string
	owner              string
	taskCreationFilter filter.TaskCreationFilter
}
```

- Extend `processRepos` — replace the trailing comment with the scan step, keeping everything before it (gather, pre-scan chain skip) unchanged:

```go
		// Signal stage: clone + the repo's own gates.
		scanResult, scanErr := w.scanner.Scan(ctx, repo)
		if scanErr != nil {
			reason := classifyScanError(scanErr)
			w.metrics.IncFilterSkipped(reason)
			glog.V(2).Infof(
				"repo skipped repo=%s reason=%s",
				repo.Key(),
				reason,
			)
			continue
		}
		if len(scanResult.VulnIDs) == 0 {
			w.metrics.IncFilterSkipped("already_clean")
			glog.V(2).Infof(
				"repo skipped repo=%s reason=%s",
				repo.Key(),
				"already_clean",
			)
			continue
		}
		candidate.HeadSHA = scanResult.HeadSHA
		candidate.VulnIDs = scanResult.VulnIDs
		// Emit and dedup are added by the remaining spec layers.
```

- Add `classifyScanError`:

```go
// classifyScanError maps a Scanner error to its metric-label skip reason.
func classifyScanError(err error) string {
	switch {
	case stderrors.Is(err, ErrCloneFailed):
		return "clone_failed"
	case stderrors.Is(err, ErrGateTimeout):
		return "gate_timeout"
	default:
		return "scan_failed"
	}
}
```

`pkg/watcher_test.go` — extend with `mocks.Scanner`-driven specs (any `pkg_test` metric-reading helper must be named distinctly, e.g. `watcherMetricValue` — the name `metricValue` is reserved for the final prompt's integration test in the same package):
- One consenting repo + `ScanStub` returning `ScanResult{HeadSHA: strings.Repeat("a", 40), VulnIDs: []string{"GO-2024-1234"}}` → `Poll` returns nil, `poll_cycle_total{result="success"}` == 1, and `repos_scanned_total` == 1.
- The pre-clone gates run before the scan: a repo with `GoModPresent:false` is skipped `no_gomod` and the scanner's `ScanCallCount()` stays 0.
- `ScanStub` returns `ErrGateTimeout` → `filter_skipped_total{reason="gate_timeout"}` == 1; `ErrCloneFailed` → `clone_failed`; a wrapped generic error → `scan_failed`.
- `ScanStub` returns `(ScanResult{}, nil)` (no markers) → `filter_skipped_total{reason="already_clean"}` == 1.

### 4. `pkg/factory/factory.go` — construct the scanner

Package `factory`. The `CreateWatcher` signature is unchanged from the previous prompt; replace its body to construct the scanner:

```go
// scanTimeout is the hard per-repo bound for the clone + gates scan (spec DB 3:
// "Each gate invocation is bounded by a hard 20-minute timeout"). The scanner
// receives it via the constructor so tests can use a short bound.
const scanTimeout = 20 * time.Minute

// CreateWatcher wires all watcher dependencies. Pure composition — no I/O.
func CreateWatcher(
	githubHTTPClient *http.Client,
	metrics pkg.Metrics,
	cursorPath string,
	owner string,
	taskCreationFilter filter.TaskCreationFilter,
) pkg.Watcher {
	ghClient := pkg.NewGitHubClient(githubHTTPClient)
	scanner := pkg.NewScanner(scanTimeout, "")
	return pkg.NewWatcher(
		ghClient,
		scanner,
		metrics,
		cursorPath,
		owner,
		taskCreationFilter,
	)
}
```

`time` is already imported in `factory.go`.

### 5. CHANGELOG

Append to the `## Unreleased` section in `CHANGELOG.md`:

```
- feat: Add the signal stage — ephemeral full clone (env allowlist HOME+PATH) of each consenting repo, run of the repo's own make vulncheck + make check under a hard 20-minute timeout, and GO-/CVE- marker classification with clone_failed / gate_timeout / scan_failed / already_clean outcomes
```

</requirements>

<constraints>
- Module path is `github.com/bborbe/github-vuln-watcher`.
- **Do NOT touch `k8s/*.yaml`** (deploy-step concern, per spec Non-goal).
- `os/exec` is allowed ONLY for git plumbing on the freshly-cloned repo (`git clone`, `git rev-parse HEAD`) and invoking the repo's own `make vulncheck` / `make check`. Never shell out to a vuln scanner directly; never invoke `govulncheck`, `trivy`, `osv-scanner`, or `gosec` binaries.
- The clone is FULL (never `--depth` / shallow); gate subprocesses receive ONLY the allowlisted env (`HOME`, `PATH`) — never the watcher's full environment.
- No reimplementation of suppression: the watcher neither reads `VULNCHECK_IGNORE`, `.trivyignore`, `.osv-scanner.toml` nor filters markers against them — the repos' own gates apply them.
- The clone directory is removed when the repo's scan finishes (deferred `RemoveAll`).
- Do NOT modify `pkg/metrics.go` label sets — they are frozen.
- The scanner's only configured knobs are `gateTimeout` (20 minutes in production wiring) and `tempDir` (test seam). Do NOT add any other flag, threshold, or opt-out.
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

Must exit 0.

```
grep -rn 'scanTimeout' pkg/factory/factory.go
grep -rn '20 \* time.Minute' pkg/factory/factory.go
grep -rn 'ErrGateTimeout\|ErrCloneFailed\|ErrScanFailed' pkg/scanner.go
grep -rn 'extractMarkers' pkg/scanner.go
```
Each expects at least one hit.

```
grep -rn '[]string{"vulncheck", "check"}' pkg/scanner.go
grep -rn '"make", target' pkg/scanner.go
grep -rn 'git", "clone' pkg/scanner.go
```
Each expects at least one hit (the `os/exec` call sites are exactly these three).

```
grep -rn 'exec.Command\|exec.CommandContext' --include=*.go -g '!*_test.go' pkg/ main.go
```
Expect matches ONLY for `git clone`, `git rev-parse HEAD`, and `make` (in `pkg/scanner.go`). No other `os/exec` usage anywhere in production code (`*_test.go` excluded — the test fixture helpers use git too).

```
go test -mod=mod ./pkg/...
```
Must exit 0.
</verification>
