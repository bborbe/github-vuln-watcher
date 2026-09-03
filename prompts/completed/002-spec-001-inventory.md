---
status: completed
spec: [001-vuln-drift-watcher]
summary: 'Added the inventory layer: GitHub App auth resolution (pkg/auth), read-only repo-listing and file-fetching client (pkg/githubclient), the pre-clone filter chain (pkg/filter: allowlist/consent/go.mod) and the watcher cycle that inventories the owner''s repos and applies the filters before any clone'
execution_id: github-vuln-watcher-vuln-drift-watcher-exec-002-spec-001-inventory
dark-factory-version: dev
created: "2026-09-03T20:30:00Z"
queued: "2026-09-03T18:43:31Z"
started: "2026-09-03T18:49:30Z"
completed: "2026-09-03T18:56:47Z"
---

<summary>
- The service can now enumerate the configured GitHub owner's repos through the GitHub App installation, reading both public and private repos, and can read each repo's `.maintainer.yaml` and `go.mod` at HEAD.
- GitHub App credentials (app ID, installation ID, PEM key) resolve to an authenticated HTTP client; a partial credential set fails at startup with the missing env var names.
- Three skip gates decide repo eligibility BEFORE any clone: the operator's allowlist (`scope`), the repo's own `goUpdate.autoUpdate: true` consent (`auto_update_disabled`), and `go.mod` presence (`no_gomod`). Consent is positive opt-in only — absent file, absent section, absent key, or any non-true value all mean skip.
- The consent parser distinguishes a genuinely-missing key from a present-but-false one using the raw YAML node, so a quoted `"true"` string can never be mistaken for consent.
- The watcher now lists repos, counts them, and applies the filter chain per repo, bumping `filter_skipped_total{reason}` for every skip; a GitHub rate limit or API error aborts the cycle with the matching `poll_cycle_total{result}` outcome.
- The `Repo` value type carries an optional scan-clone URL override so the later fixture-repo integration test can clone from a local path.
</summary>

<objective>
Add the inventory layer: GitHub-App authentication, the read-only repo-listing and file-fetching client, and the pre-clone filter chain (allowlist / consent / go.mod presence) with its metric labels and skip logging. The watcher's cycle now inventories the owner's repos and applies the filters before any clone.
</objective>

<context>
Read `docs/dod.md`.

Read these coding plugin docs before writing code (paths are inside the container):
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-patterns.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-factory-pattern.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-filter-pattern.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-error-wrapping-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-testing-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-mocking-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-doc-best-practices.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/definition-of-done.md`

Read these repo files before writing code:
- `pkg/watcher.go` — the skeleton `Watcher` / `NewWatcher` / `Poll` created by the previous prompt. This prompt extends `NewWatcher`, `Poll`, and adds `processRepos` / `gatherCandidate` / `dropRepo`.
- `pkg/metrics.go` — `Metrics` interface with `IncPollCycle`, `IncReposScanned`, `IncFilterSkipped`; the closed label sets.
- `pkg/factory/factory.go` — `CreateWatcher` (this prompt changes its signature) and `CreateRouter` (unchanged).
- `main.go` — `Run` (this prompt adds the allowlist parse/validate and the GitHub client resolution).

**Sibling entry-point check (already run):** this repo has exactly one binary entry point — `main.go`. Run `grep -rn "factory.Create" --include=*.go .` and `grep -rn "func (.*) Run(ctx" --include=*.go .` before you start; the only `CreateWatcher` call site is `main.go`. Update it in step 7.

Library API facts (verified against the module cache — do not re-derive from memory):
- `github.com/bborbe/maintainer/repoallowlist` — `repoallowlist.IsAllowed(allowlist []string, target string) bool`; `repoallowlist.Validate(ctx context.Context, allowlist []string) error`. Import as `"github.com/bborbe/maintainer/repoallowlist"` (NOT a `lib/` alias).
- `github.com/bborbe/maintainer/githubapp` — `githubapp.NewClient(ctx, githubapp.Config{AppID int64, InstallationID int64, PEM []byte, PEMPath string, BaseURL string}) (*http.Client, error)`; `PEM` and `PEMPath` are mutually exclusive; `BaseURL` is for httptest-based tests.
- `github.com/google/go-github/v84/github` (import `gogithub`) — `gogithub.NewClient(httpClient)`, `client.Apps.ListRepos(ctx, opts)`, `client.Repositories.GetContents(ctx, owner, repo, path, opts)`, `gogithub.RepositoryContentGetOptions{Ref: ...}`, `gogithub.ListOptions{PerPage: 100, Page: 1}`, `gogithub.RateLimitError`, `gogithub.AbuseRateLimitError`, `gogithub.ErrorResponse` (has `.Response`), `fileContent.GetContent()`, `fileContent.GetSize()`.
- `gopkg.in/yaml.v3` — `yaml.Unmarshal([]byte, &struct)`, `yaml.Node` with fields `Kind` (compare against `yaml.ScalarNode`), `Tag` (compare against `"!!bool"`), `Value`.
- `github.com/bborbe/errors` — `errors.Wrap`, `errors.Wrapf`, `errors.Errorf`; sentinel errors via `stderrors "errors"` and matched with `stderrors.Is` / `stderrors.As`.
- `github.com/bborbe/collection` and `github.com/bborbe/validation` are already indirect deps; the filter package's consent file does NOT need them (see step 4 — the vuln watcher's consent is binary at the gate).
</context>

<requirements>

### 1. go.mod: add maintainer, go-github, yaml

```
go get github.com/bborbe/maintainer@v0.50.2
go get github.com/google/go-github/v84@v84.0.0
go get gopkg.in/yaml.v3@v3.0.1
```

Then `go mod tidy` (also runs in `make precommit`). Do NOT add any other new module in this prompt.

### 2. `pkg/repo.go` — repository value type

Package `pkg`. 

```go
// Repo identifies a GitHub repository within the watcher's scope.
type Repo struct {
	Owner         string
	Name          string
	DefaultBranch string // typically "master" or "main"; cached to avoid a per-cycle lookup
	// CloneURL is the URL used to clone the repo for the scan stage. Empty
	// derives git@github.com:<owner>/<name>.git. Production never sets it;
	// fixture tests set it to a local path. This is distinct from the frozen
	// `clone_url` field emitted in task frontmatter (always the SSH form).
	CloneURL string
}

// Key returns the host-qualified repo key consumed by the repo allowlist
// (e.g. "github.com/bborbe/disk-status").
func (r Repo) Key() string {
	return fmt.Sprintf("github.com/%s/%s", r.Owner, r.Name)
}

// String returns the short "owner/name" form used in the emitted task fields
// and in log lines.
func (r Repo) String() string {
	return fmt.Sprintf("%s/%s", r.Owner, r.Name)
}
```

### 3. `pkg/auth/auth.go` — GitHub App credentials

Package `auth`. Mirror the sibling's proven shape exactly (this package owns the I/O — JWT exchange + installation-token fetch — so it lives outside `pkg/factory`, which is pure composition):

```go
// Package auth resolves GitHub App installation credentials to an HTTP client.
// I/O (JWT exchange + installation-token fetch) happens here, which is why it
// lives outside pkg/factory (the factory package is pure composition).
package auth

import (
	"context"
	"net/http"

	"github.com/bborbe/errors"
	"github.com/bborbe/maintainer/githubapp"
	"github.com/golang/glog"
)

// Credentials carries the inputs needed for GitHub App auth. Read from the
// binary's argument struct by the caller. PEMKey is the long-lived secret:
// it arrives by environment only and is never logged.
type Credentials struct {
	AppID          int64
	InstallationID int64
	PEMKey         []byte
}

// ResolveGitHubClient returns an *http.Client authenticated as the GitHub App
// installation.
//
// Rules:
//   - All three fields set -> App auth.
//   - Any subset set without the other two -> error naming the MISSING env var
//     names only (never the value of PEM_KEY).
//   - Nothing set -> error.
func ResolveGitHubClient(ctx context.Context, creds Credentials) (*http.Client, error) {
	appPartial := creds.AppID != 0 || creds.InstallationID != 0 || len(creds.PEMKey) != 0
	appComplete := creds.AppID != 0 && creds.InstallationID != 0 && len(creds.PEMKey) != 0

	if appPartial && !appComplete {
		var missing []string
		if creds.AppID == 0 {
			missing = append(missing, "APP_ID")
		}
		if creds.InstallationID == 0 {
			missing = append(missing, "INSTALLATION_ID")
		}
		if len(creds.PEMKey) == 0 {
			missing = append(missing, "PEM_KEY")
		}
		return nil, errors.Errorf(
			ctx,
			"watcher auth: partial GitHub App config — missing %v; set all three or none",
			missing,
		)
	}

	if appComplete {
		glog.V(2).Infof(
			"watcher auth mode=github-app app_id=%d installation_id=%d",
			creds.AppID, creds.InstallationID,
		)
		client, err := githubapp.NewClient(
			ctx, githubapp.Config{
				AppID:          creds.AppID,
				InstallationID: creds.InstallationID,
				PEM:            creds.PEMKey,
			},
		)
		if err != nil {
			return nil, errors.Wrap(ctx, err, "create github app client")
		}
		client.Timeout = 30 * time.Second // bound each GitHub API request; a hung call must not hold the single CycleGate slot
		return client, nil
	}

	return nil, errors.Errorf(
		ctx,
		"watcher auth: GitHub App credentials not configured — set APP_ID, INSTALLATION_ID, and PEM_KEY",
	)
}
```

`pkg/auth/auth_suite_test.go` (package `auth_test`, with the counterfeiter `//go:generate` directive) and `pkg/auth/auth_test.go`:
- All three credentials set (use a fake PEM, e.g. `[]byte("not-a-real-key")`) — `ResolveGitHubClient` returns an error (the PEM cannot be parsed) rather than a nil client; the partial-config error paths take precedence so assert those with a partial set FIRST.
- Only `APP_ID` set → error whose message contains `APP_ID`, `INSTALLATION_ID`, and `PEM_KEY` but never the PEM value.
- Only `PEMKey` set → error containing `APP_ID`.
- Nothing set → error containing `"not configured"`.
- No panic and no nil-pointer dereference on any path.

### 4. `pkg/filter/` — the pre-clone filter chain

New package `filter`. Create `pkg/filter/filter_suite_test.go` (package `filter_test`, `time.Local = time.UTC`, `RegisterFailHandler(Fail)`, `RunSpecs(t, "Filter Suite", ...)`, plus the `//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6@v6.12.2 -generate` directive).

**`pkg/filter/filter.go`** — the frozen filter-chain semantics (spec Constraints):

```go
// Package filter implements the TaskCreationFilter chain — the predicates that
// decide whether a vuln-drift work item should be filed for one observed repo.
//
// Pre-scan chain order (frozen; the first non-empty reason wins):
//
//  1. RepoAllowlistFilter  -> "scope"                  — operator-configured scope
//  2. AutoUpdateFilter     -> "auto_update_disabled"   — consent gate (positive opt-in)
//  3. GoModPresentFilter   -> "no_gomod"               — repo has no go.mod
//
// The finding-set dedup filter (FindingSetUnchangedFilter) is NOT part of this
// pre-scan chain: it needs the scan result, so it is evaluated post-scan on a
// second, per-cycle pass (and omitted entirely on a forced cycle).
package filter

//counterfeiter:generate -o ../../mocks/task_creation_filter.go --fake-name TaskCreationFilter . TaskCreationFilter

// Candidate is the filter-evaluation input. It mirrors the watcher's per-repo
// observation as a local type so this package never imports pkg (pkg imports
// filter; the reverse would be an import cycle).
type Candidate struct {
	// RepoKey is the host-qualified key "github.com/<owner>/<name>".
	RepoKey string
	// HeadSHA is the full HEAD SHA of the default branch (populated by the
	// scan stage).
	HeadSHA string
	// GoModPresent is false when the repo has no go.mod at all.
	GoModPresent bool
	// Consent is the verdict of `.maintainer.yaml: goUpdate.autoUpdate`.
	Consent Consent
	// TaskIdentifier is the deterministic UUID5 of the repo's finding set
	// (populated by the emit layer once the vuln list is known; read by the
	// FindingSetUnchangedFilter).
	TaskIdentifier string
}

// TaskCreationFilter decides whether a single Candidate should be skipped.
// Implementations return the metric-label reason for the skip, or "" to pass
// through. Returning the reason (rather than a bool) means the caller never
// re-evaluates the predicates to work out which counter to bump.
type TaskCreationFilter interface {
	// Skip returns the skip reason (metric label) or "" to pass through.
	Skip(candidate Candidate) string
}

// TaskCreationFilterFunc adapts a function to the TaskCreationFilter interface.
type TaskCreationFilterFunc func(candidate Candidate) string

// Skip implements TaskCreationFilter for the function adapter.
func (f TaskCreationFilterFunc) Skip(candidate Candidate) string {
	return f(candidate)
}

// TaskCreationFilterList is a slice composite returning the first non-empty
// reason from its members. An empty slice never skips.
type TaskCreationFilterList []TaskCreationFilter

// Skip returns the first non-empty reason from any contained filter,
// short-circuiting on the first hit.
func (fs TaskCreationFilterList) Skip(candidate Candidate) string {
	for _, f := range fs {
		if reason := f.Skip(candidate); reason != "" {
			return reason
		}
	}
	return ""
}
```

**`pkg/filter/consent.go`** — the consent verdict type and parser. The vuln watcher's gate is POSITIVE OPT-IN ONLY (spec Constraints): the only passing value is `goUpdate.autoUpdate` explicitly boolean true. The tri-state type is kept because the parser must distinguish "present and false" from "absent", but the GATE collapses both non-granted outcomes into one label (`auto_update_disabled`). The YAML-node walking is deliberate — `yaml.v3`'s implicit resolver only tags a plain unquoted `true/True/TRUE` as `!!bool`, so a quoted string, an integer, `yes/no`, or an explicit null can never reach the granted branch:

```go
package filter

import (
	"context"

	"github.com/bborbe/errors"
	"gopkg.in/yaml.v3"
)

// Consent is the three-valued outcome of reading `.maintainer.yaml:
// goUpdate.autoUpdate` for one repo.
//
//   - GrantedConsent — the key is present and explicitly boolean true.
//   - RefusedConsent — the key is present and explicitly boolean false.
//   - UndecidedConsent — the file is absent, the goUpdate section is absent,
//     the autoUpdate key is absent, or the key holds any non-boolean value.
//
// The vuln watcher's gate treats both RefusedConsent and UndecidedConsent as
// "auto_update_disabled" — only GrantedConsent passes.
type Consent string

const (
	GrantedConsent   Consent = "granted"
	RefusedConsent   Consent = "refused"
	UndecidedConsent Consent = "undecided"
)

// maintainerDoc is the minimal shape ParseConsent needs to reach the
// goUpdate.autoUpdate node as a raw yaml.Node, so it can tell "absent" from
// "present and false" apart.
type maintainerDoc struct {
	GoUpdate struct {
		AutoUpdate yaml.Node `yaml:"autoUpdate"`
	} `yaml:"goUpdate"`
}

// ParseConsent reads raw `.maintainer.yaml` bytes and returns the consent
// verdict. Returns (Consent(""), non-nil error) when content is not valid YAML
// at all — the caller MUST treat a non-nil error as a drop-before-evaluation,
// never read the zero-value Consent as a verdict.
func ParseConsent(ctx context.Context, content []byte) (Consent, error) {
	if len(content) == 0 {
		return UndecidedConsent, nil
	}

	var doc maintainerDoc
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return Consent(""), errors.Wrapf(ctx, err, "parse .maintainer.yaml")
	}

	node := doc.GoUpdate.AutoUpdate
	if node.Kind == 0 {
		return UndecidedConsent, nil
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" {
		return UndecidedConsent, nil
	}
	switch node.Value {
	case "true", "True", "TRUE":
		return GrantedConsent, nil
	case "false", "False", "FALSE":
		return RefusedConsent, nil
	default:
		return UndecidedConsent, nil
	}
}
```

**`pkg/filter/auto_update_filter.go`** — the consent gate:

```go
// NewAutoUpdateFilter is the per-repo trust gate sourced from
// `.maintainer.yaml: goUpdate.autoUpdate`. It is POSITIVE OPT-IN: only
// Consent == GrantedConsent passes. RefusedConsent, UndecidedConsent, and any
// other/invalid Consent value (including the zero value) all return
// "auto_update_disabled" — the vuln watcher does not distinguish "refused"
// from "not answered".
//
// This gate is the only thing that turns this service's attention into agent
// action on somebody else's repository. There is deliberately no flag, env
// var, or code path that disables it or defaults any non-granted value to
// consent.
func NewAutoUpdateFilter() TaskCreationFilter {
	return TaskCreationFilterFunc(func(candidate Candidate) string {
		if candidate.Consent == GrantedConsent {
			return ""
		}
		return "auto_update_disabled"
	})
}
```

**`pkg/filter/repo_allowlist_filter.go`**:

```go
// ParseRepoAllowlist parses a comma-separated allowlist string into
// host-qualified repo keys (e.g. "github.com/bborbe/disk-status").
// Whitespace is trimmed and empty entries dropped. nil on empty input, which
// repoallowlist.IsAllowed treats as allow-all within the configured owner.
func ParseRepoAllowlist(raw string) []string {
	if raw == "" {
		return nil
	}
	var result []string
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		result = append(result, entry)
	}
	return result
}

// NewRepoAllowlistFilter returns the operator-scope gate: "scope" for any
// Candidate whose RepoKey is not permitted by the allowlist.
func NewRepoAllowlistFilter(allowlist []string) TaskCreationFilter {
	return TaskCreationFilterFunc(func(candidate Candidate) string {
		if !repoallowlist.IsAllowed(allowlist, candidate.RepoKey) {
			return "scope"
		}
		return ""
	})
}
```

**`pkg/filter/gomod_present_filter.go`**:

```go
// NewGoModPresentFilter returns "no_gomod" for a repo with no go.mod at HEAD.
// Not a failure: most repos in a mixed-language org simply are not Go repos.
func NewGoModPresentFilter() TaskCreationFilter {
	return TaskCreationFilterFunc(func(candidate Candidate) string {
		if !candidate.GoModPresent {
			return "no_gomod"
		}
		return ""
	})
}
```

**`pkg/filter/filter_test.go`** (`package filter_test`):
- `NewRepoAllowlistFilter`: a Candidate outside the allowlist → `"scope"`; inside → `""`; empty allowlist → `""` (allow-all).
- `ParseRepoAllowlist`: `"github.com/bborbe/a, github.com/bborbe/b ,, "` → `["github.com/bborbe/a", "github.com/bborbe/b"]`; `""` → nil.
- Library-validator boundary: `repoallowlist.Validate(ctx, ParseRepoAllowlist("github.com/bborbe/a, github.com/bborbe/b"))` returns nil; a malformed entry (e.g. `"github.com/*/*"` or `"*"`) returns a non-nil error.
- `NewAutoUpdateFilter`: GrantedConsent → `""`; RefusedConsent → `"auto_update_disabled"`; UndecidedConsent → `"auto_update_disabled"`; zero-value Consent → `"auto_update_disabled"`.
- `NewGoModPresentFilter`: `GoModPresent:false` → `"no_gomod"`; `GoModPresent:true` → `""`.
- `TaskCreationFilterList`: short-circuits on the first non-empty reason; an empty list never skips.
- `ParseConsent`: raw YAML with `goUpdate:\n  autoUpdate: true` → GrantedConsent; `false` → RefusedConsent; `True`/`TRUE` → GrantedConsent; quoted `"true"` → UndecidedConsent; `yes` → UndecidedConsent; `autoUpdate: 1` → UndecidedConsent; empty document → UndecidedConsent; missing goUpdate section → UndecidedConsent; malformed YAML (`"{{{"`) → non-nil error; empty bytes → UndecidedConsent.

### 5. `pkg/githubclient.go` — read-only inventory client

Package `pkg`. The interface has exactly three methods — the vuln watcher gets the HEAD SHA from the cloned repo in the scan stage, not from the API:

```go
// ErrRateLimited is returned when the GitHub API responds with a primary or
// abuse rate-limit error. Callers abort the whole cycle on this sentinel
// (poll_cycle_total{result="rate_limited"}) rather than retrying in a loop.
var ErrRateLimited = stderrors.New("github rate limited")

// maxContentBytes caps every file this client decodes. The contents of go.mod
// and .maintainer.yaml in any observed repo are attacker-controlled, so the
// API-reported Size is checked BEFORE decoding.
const maxContentBytes = 1024 * 1024

// maxListPages bounds repo-list pagination so a self-referential or
// misbehaving `next` link cannot loop the cycle forever.
const maxListPages = 100

//counterfeiter:generate -o ../mocks/github_client.go --fake-name GitHubClient . GitHubClient

// GitHubClient is the read-only upstream surface for the vuln-drift watcher.
// Nothing in this interface writes to an observed repository.
type GitHubClient interface {
	// ListRepos returns the non-archived repositories under owner that the
	// authenticated GitHub App installation can access — public AND private.
	// Enumeration goes through GET /installation/repositories
	// (Apps.ListRepos), NOT GET /users/{u}/repos, because the latter silently
	// omits private repos under an installation token. Pagination is internal
	// and capped at maxListPages; the returned slice is the full set.
	ListRepos(ctx context.Context, owner string) ([]Repo, error)

	// GetGoMod returns the raw bytes of go.mod at HEAD of repo's default
	// branch. Returns (nil, nil) when the file does not exist (HTTP 404) —
	// the caller maps a nil slice to skip reason "no_gomod". Returns
	// (nil, ErrRateLimited) on rate limiting. Every other failure (network,
	// 5xx, oversize, base64 decode) returns a wrapped error and drops the repo.
	GetGoMod(ctx context.Context, repo Repo) ([]byte, error)

	// GetMaintainerConfig returns the parsed consent verdict from
	// `.maintainer.yaml` at HEAD of repo's default branch.
	//
	//   - (filter.GrantedConsent, nil) — autoUpdate is explicitly boolean true.
	//   - (filter.RefusedConsent, nil) — autoUpdate is explicitly boolean false.
	//   - (filter.UndecidedConsent, nil) — the file is absent (HTTP 404), the
	//     goUpdate section is absent, the autoUpdate key is absent, or the key
	//     holds any non-boolean value.
	//   - (filter.Consent(""), ErrRateLimited) on primary or abuse rate limiting.
	//   - (filter.Consent(""), wrapped error) on every other failure including
	//     5xx, oversize files, base64 decode failures, and YAML parse failures.
	//
	// Malformed YAML MUST NOT be silently treated as UndecidedConsent — it is
	// an error so the repo is dropped from the cycle rather than recorded as a
	// consent verdict.
	GetMaintainerConfig(ctx context.Context, repo Repo) (filter.Consent, error)
}

// NewGitHubClient returns the production GitHubClient backed by the given
// HTTP client (authenticated via GitHub App installation token).
func NewGitHubClient(httpClient *http.Client) GitHubClient {
	return &githubClient{client: gogithub.NewClient(httpClient)}
}

type githubClient struct {
	client *gogithub.Client
}
```

Implement the unexported helpers from the sibling: `isRateLimitError(err) bool` (`stderrors.As` on `*gogithub.RateLimitError` and `*gogithub.AbuseRateLimitError`), `isNotFound(err) bool` (404 on `*gogithub.ErrorResponse.Response.StatusCode`), `wrapRateLimitErr(ctx, err, msg, args...) error` (returns `ErrRateLimited` on rate-limit responses, else `errors.Wrapf`).

- `ListRepos`: paginate `client.Apps.ListRepos(ctx, &gogithub.ListOptions{PerPage: 100, Page: 1})`, following `resp.NextPage` up to `maxListPages`. Map each repo with `mapGitHubRepos` — drop archived repos, repos whose `repo.GetOwner().GetLogin() != owner`, repos with an empty name, and repos whose owner or name fails the `[a-zA-Z0-9_.-]+` charset check (spec Security — repo/owner names must be validated before entering frontmatter or the cursor; this is the single choke point, so every later layer gets validated names). Log at V(2): `"github-vuln-watcher listed installation repos owner=%s total=%d private=%d in_scope=%d"`. On error use `wrapRateLimitErr`. Check `ctx.Done()` inside the pagination loop (return a wrapped `ctx.Err()` on cancellation).
- `GetGoMod`: `client.Repositories.GetContents(ctx, repo.Owner, repo.Name, "go.mod", &gogithub.RepositoryContentGetOptions{Ref: repo.DefaultBranch})`. 404 → `(nil, nil)`; rate-limit → `(nil, ErrRateLimited)`; check `fileContent.GetSize()` and the decoded length against `maxContentBytes`; decode via `fileContent.GetContent()`.
- `GetMaintainerConfig`: same fetch pattern for `.maintainer.yaml`; 404 → `(filter.UndecidedConsent, nil)`; rate-limit → `(filter.Consent(""), ErrRateLimited)`; then `filter.ParseConsent(ctx, []byte(decoded))` and propagate its error (never map a parse error to a verdict).

Create `pkg/githubclient_export_test.go` (package `pkg`, test-only), mirroring the sibling:

```go
// SetBaseURL points c at a test server. Test-only.
func SetBaseURL(c GitHubClient, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if sc, ok := c.(*githubClient); ok {
		sc.client.BaseURL = u
	}
	return nil
}
```

`pkg/githubclient_test.go` (`package pkg_test`) using `httptest.NewServer` + `pkg.SetBaseURL`:
- `ListRepos`: two pages via the `Link` header → 3 repos; archived / foreign-owner / empty-name repos dropped; a repo whose owner or name contains characters outside `[a-zA-Z0-9_.-]` is dropped; rate-limit response (HTTP 403 with `X-RateLimit-Remaining: 0`) → `ErrRateLimited`.
- `GetGoMod`: found → bytes; 404 → `(nil, nil)`; rate-limit → `ErrRateLimited`; oversize (set `"size"` > 1 MiB) → wrapped error.
- `GetMaintainerConfig`: found with `goUpdate.autoUpdate: true` → `filter.GrantedConsent`; 404 → `filter.UndecidedConsent`; malformed YAML → non-nil error; rate-limit → `ErrRateLimited`.

### 6. `pkg/candidate.go` — per-repo observation

Package `pkg`:

```go
// Candidate is the watcher's per-repo observation: everything needed to
// (a) decide whether to file a work item and (b) populate the emitted message.
//
// Built per cycle by the Watcher in this order, so partial failures degrade
// gracefully:
//  1. Repo         (from ListRepos)
//  2. GoModPresent (from GetGoMod — false when the repo has no go.mod)
//  3. Consent      (from GetMaintainerConfig)
//  4. HeadSHA      (from the cloned HEAD — scan stage)
//  5. VulnIDs      (from the scan stage classification)
type Candidate struct {
	Repo         Repo
	HeadSHA      string
	GoModPresent bool
	Consent      filter.Consent
	VulnIDs      []string // canonical (deduped, sorted) marker list
}

// ShortSHA returns the first 7 chars of HeadSHA, used in the title and body.
func (c Candidate) ShortSHA() string {
	if len(c.HeadSHA) < 7 {
		return c.HeadSHA
	}
	return c.HeadSHA[:7]
}

// FilterCandidate projects this observation onto the filter package's input.
func (c Candidate) FilterCandidate() filter.Candidate {
	return filter.Candidate{
		RepoKey:       c.Repo.Key(),
		HeadSHA:       c.HeadSHA,
		GoModPresent:  c.GoModPresent,
		Consent:       c.Consent,
		TaskIdentifier: "", // populated by the emit layer once the vuln list is known
	}
}
```

### 7. `pkg/watcher.go` — inventory into the cycle

Package `pkg`. Extend the skeleton from the previous prompt:

- `NewWatcher` signature and the `watcher` struct gain the inventory client and the cycle-invariant filter chain:

```go
// NewWatcher wires the cycle's collaborators. taskCreationFilter is the
// cycle-invariant pre-scan chain built at wiring time; the finding-set dedup
// filter is composed in per cycle because it needs a fresh cursor (and is
// omitted on a forced cycle) — that layer arrives in a later prompt.
func NewWatcher(
	ghClient GitHubClient,
	metrics Metrics,
	cursorPath string,
	owner string,
	taskCreationFilter filter.TaskCreationFilter,
) Watcher {
	return &watcher{
		ghClient:           ghClient,
		metrics:            metrics,
		cursorPath:         cursorPath,
		owner:              owner,
		taskCreationFilter: taskCreationFilter,
	}
}

type watcher struct {
	ghClient           GitHubClient
	metrics            Metrics
	cursorPath         string
	owner              string
	taskCreationFilter filter.TaskCreationFilter
}
```

- Replace the skeleton `Poll` body with the inventory cycle (the cursor load/save and the finding-set dedup arrive in a later prompt):

```go
func (w *watcher) Poll(ctx context.Context, force bool) error {
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

	if abortReason := w.processRepos(ctx, repos, w.taskCreationFilter); abortReason != "" {
		w.metrics.IncPollCycle(abortReason)
		return nil
	}

	w.metrics.IncPollCycle("success")
	glog.V(2).Infof("poll cycle complete result=success")
	return nil
}
```

- Add `processRepos` (per-repo: gather candidate, apply the pre-scan chain, skip with the metric label and log line; the scan/emit/dedup stages are added by later prompts), `gatherCandidate` (fetch go.mod + consent via the API; rate-limit aborts the cycle, other errors drop the repo), and `dropRepo` (mirroring the sibling):

```go
func (w *watcher) processRepos(
	ctx context.Context,
	repos []Repo,
	cycleFilter filter.TaskCreationFilter,
) string {
	for _, repo := range repos {
		select {
		case <-ctx.Done():
			glog.V(2).Infof(
				"poll cancelled during processRepos at repo=%s",
				repo.Key(),
			)
			return ""
		default:
		}

		candidate, abortReason, dropped := w.gatherCandidate(ctx, repo)
		if abortReason != "" {
			return abortReason
		}
		if dropped {
			continue
		}

		if reason := cycleFilter.Skip(candidate.FilterCandidate()); reason != "" {
			w.metrics.IncFilterSkipped(reason)
			glog.V(2).Infof(
				"repo skipped repo=%s reason=%s",
				repo.Key(),
				reason,
			)
			continue
		}
		// Repos that pass the pre-scan chain are scanned and emitted by the
		// later spec layers.
	}
	return ""
}

func (w *watcher) gatherCandidate(
	ctx context.Context,
	repo Repo,
) (Candidate, string, bool) {
	goModContent, err := w.ghClient.GetGoMod(ctx, repo)
	if err != nil {
		if stderrors.Is(err, ErrRateLimited) {
			return Candidate{}, "rate_limited", false
		}
		return dropRepo(repo, "go_mod", err)
	}

	consent, err := w.ghClient.GetMaintainerConfig(ctx, repo)
	if err != nil {
		if stderrors.Is(err, ErrRateLimited) {
			return Candidate{}, "rate_limited", false
		}
		return dropRepo(repo, "maintainer_config", err)
	}

	candidate := Candidate{
		Repo:         repo,
		GoModPresent: goModContent != nil,
		Consent:      consent,
	}
	return candidate, "", false
}

// dropRepo logs the always-on per-repo drop line. The phrase
// "repo dropped from cycle" is the operator's grep handle — do not reword it.
func dropRepo(repo Repo, step string, err error) (Candidate, string, bool) {
	glog.Warningf(
		"repo dropped from cycle: owner=%s repo=%s step=%s err=%v",
		repo.Owner,
		repo.Name,
		step,
		err,
	)
	return Candidate{}, "", true
}
```

The `Watcher` interface doc comment on `Poll` stays as-is (force semantics unchanged).

`pkg/watcher_test.go` — extend with a `mocks.GitHubClient`-driven spec:
- `ListRepos` returns 3 repos; the fake `GetGoMod` returns non-nil bytes for one and nil for the other two; the fake `GetMaintainerConfig` returns GrantedConsent for all. After one `Poll`: `filter_skipped_total{reason="no_gomod"}` == 2, `poll_cycle_total{result="success"}` == 1.
- `ListRepos` returns `ErrRateLimited` → `poll_cycle_total{result="rate_limited"}` == 1 and `success` stays 0.
- `ListRepos` returns a wrapped non-rate-limit error → `poll_cycle_total{result="github_error"}` == 1.
- `GetMaintainerConfig` returns `ErrRateLimited` mid-cycle → the whole cycle aborts with `rate_limited` (the first repo's rate limit stops the loop).

### 8. `pkg/factory/factory.go` — wire the inventory

Package `factory`. Keep `CreateTriggerHandler` and `CreateRouter` from the previous prompt. Replace `CreateWatcher`:

```go
// CreateWatcher wires all watcher dependencies. Pure composition — no I/O.
func CreateWatcher(
	githubHTTPClient *http.Client,
	metrics pkg.Metrics,
	cursorPath string,
	owner string,
	taskCreationFilter filter.TaskCreationFilter,
) pkg.Watcher {
	ghClient := pkg.NewGitHubClient(githubHTTPClient)
	return pkg.NewWatcher(
		ghClient,
		metrics,
		cursorPath,
		owner,
		taskCreationFilter,
	)
}

// CreateStaticFilters builds the cycle-invariant pre-scan chain in its frozen
// order (spec DB 2: allowlist -> consent -> go.mod presence).
func CreateStaticFilters(allowlist []string) filter.TaskCreationFilter {
	return filter.TaskCreationFilterList{
		filter.NewRepoAllowlistFilter(allowlist),
		filter.NewAutoUpdateFilter(),
		filter.NewGoModPresentFilter(),
	}
}
```

Update the imports (add `net/http` and the `filter` package; `handler`/`libsentry`/`mux`/`promhttp`/`log`/`libhttp`/`time` stay).

Add `pkg/factory/factory_test.go` specs covering the `CreateStaticFilters` chain order (allowlist -> consent -> go.mod):
- A fully-qualifying `filter.Candidate{RepoKey:"github.com/bborbe/x", GoModPresent:true, Consent:filter.GrantedConsent}` with an empty allowlist passes (`""`).
- With an empty allowlist (allow-all) the first non-empty reason is NOT `"scope"` — a Candidate with `GoModPresent:false, Consent:filter.UndecidedConsent` returns `"auto_update_disabled"` (the consent gate fires before the go.mod-presence gate in the frozen chain order). To observe `"no_gomod"` as the first reason, the candidate must carry `Consent:filter.GrantedConsent` with `GoModPresent:false`.
- A Candidate with `Consent:filter.RefusedConsent` and `GoModPresent:true` returns `"auto_update_disabled"`.
- A Candidate with `Consent:filter.GrantedConsent` and `GoModPresent:false` returns `"no_gomod"`.
- A Candidate whose RepoKey is outside a non-empty allowlist returns `"scope"` regardless of the other fields.

### 9. `main.go` — wire auth + allowlist into Run

Keep the previous prompt's `application` struct, `pollLoop`, and `createHTTPServer` exactly as they are. Extend `Run` in order:

1. After the poll-interval parse/ceiling check, parse and validate the allowlist:
   ```go
   allowlist := filter.ParseRepoAllowlist(a.RepoAllowlist)
   if err := repoallowlist.Validate(ctx, allowlist); err != nil {
       return errors.Wrapf(ctx, err, "validate repo allowlist")
   }
   if len(allowlist) == 0 {
       glog.V(2).Infof("repo-allowlist empty: allow-all within owner=%s", a.Owner)
   } else {
       glog.V(2).Infof("repo-allowlist count=%d", len(allowlist))
   }
   ```
2. Resolve the GitHub client:
   ```go
   httpClient, err := auth.ResolveGitHubClient(ctx, auth.Credentials{
       AppID:          a.AppID,
       InstallationID: a.InstallationID,
       PEMKey:         []byte(a.PEMKey),
   })
   if err != nil {
       return errors.Wrapf(ctx, err, "resolve GitHub client")
   }
   defer httpClient.CloseIdleConnections()
   ```
3. Replace the watcher construction line:
   ```go
   w := factory.CreateWatcher(
       httpClient,
       metrics,
       a.CursorPath,
       a.Owner,
       factory.CreateStaticFilters(allowlist),
   )
   ```

New imports: `github.com/bborbe/maintainer/repoallowlist`, `"github.com/bborbe/github-vuln-watcher/pkg/auth"`, `"github.com/bborbe/github-vuln-watcher/pkg/filter"`.

### 10. CHANGELOG

Append to the `## Unreleased` section in `CHANGELOG.md`:

```
- feat: Inventory the GitHub owner via the GitHub App installation and gate repos pre-clone by allowlist (scope), .maintainer.yaml goUpdate.autoUpdate consent (auto_update_disabled), and go.mod presence (no_gomod)
```

</requirements>

<constraints>
- Module path is `github.com/bborbe/github-vuln-watcher`.
- **Do NOT touch `k8s/*.yaml`** (deploy-step concern, per spec Non-goal).
- Do NOT modify `pkg/metrics.go` label sets — they are frozen and already carry the full reason set.
- The GitHubClient interface has EXACTLY three methods: `ListRepos`, `GetGoMod`, `GetMaintainerConfig`. Do NOT add `GetHeadSHA` or any merged-PR/complete-task surface — this service is publish-only and gets the HEAD SHA from the cloned repo (spec Non-goals: no Kafka consumption, no merge detection).
- Consent is positive opt-in only: `goUpdate.autoUpdate: true` is the only passing value. Do NOT introduce an `auto_update_undecided` label or a decision-task flow.
- `os/exec` is still forbidden in this prompt (the scan subprocess stage arrives in the next prompt).
- Never use `fmt.Errorf`; all errors go through `github.com/bborbe/errors` and carry `ctx`.
- The GitHub App private key is never logged, and error messages name env var names only, never the PEM value.
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
grep -rn 'auto_update_disabled' pkg/filter/
grep -rn 'no_gomod' pkg/filter/
grep -rn '"scope"' pkg/filter/
```
Each expects at least one hit.

```
grep -n 'SetBaseURL' pkg/githubclient_export_test.go
grep -n 'ParseConsent' pkg/filter/consent.go
```
Each expects at least one line.

```
go test -mod=mod ./pkg/... ./pkg/filter/... ./pkg/auth/...
```
Must exit 0.

The acceptance-criterion-2 behavior (skip reasons and `filter_skipped_total` deltas) is asserted end-to-end in the final prompt's integration test; this prompt's unit tests cover the individual gates.
</verification>
