---
status: completed
spec: [002-private-repo-scan-clone-auth]
execution_id: github-vuln-watcher-private-clone-auth-exec-006-spec-002-scanner-credential-env
dark-factory-version: dev
created: "2026-09-16T20:45:00Z"
queued: "2026-09-16T21:12:20Z"
started: "2026-09-16T21:12:21Z"
completed: "2026-09-16T21:19:26Z"
branch: dark-factory/private-repo-scan-clone-auth
---

<summary>
- The scan stage's clone can now authenticate as the watcher's own GitHub App installation, so private repos become scannable; today every private repo fails before any gate runs.
- The credential is handed to the clone process through its environment only — never through the clone URL, never on the command line, never written into the cloned directory, and never written to a log line.
- The untrusted-code isolation boundary is unchanged: the scanned repo's own gates still receive exactly the `HOME` and `PATH` entries and nothing else.
- A scan with no credential source configured clones exactly as it does today, and the existing unauthenticated-path assertions are untouched apart from one constructor call.
- A credential source that fails (or hangs) is logged as a warning and degrades to today's unauthenticated clone, so no previously-working scan starts failing.
- New integration tests use a recording `git` shim on `PATH` to capture what the real clone subprocess actually received, and a real clone of a local fixture repo to prove nothing credential-bearing lands on disk.
- The negative properties are asserted separately for the literal credential and for its base64 header form, because the encoded form contains no part of the literal and a literal-only search cannot see it.
- A log-capture test proves the credential and its encoded form appear in no captured log output, while first proving the capture itself is live. (The vendored mint library's own 8-character prefix line is outside this repo's control and is deliberately not covered by that test.)
</summary>

<objective>
Make the scan stage clone private repos as the watcher's GitHub App installation by minting one installation access token per scan and conveying it to the `git clone` subprocess through git's environment-configuration interface (`http.extraheader`), while the untrusted-code isolation boundary stays exactly as frozen: the credential exists only in the clone process's environment — no URL, no argv, no file in the clone directory, no log line — and the scanned repo's gates still receive only `HOME` and `PATH`. A missing or failing token source degrades to today's unauthenticated clone instead of adding a new failure mode.
</objective>

<context>
Read `docs/dod.md` (this repo's Definition of Done).

Read these coding plugin docs before writing code (paths are inside the container):
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-testing-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-mocking-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-security-linting.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-error-wrapping-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-glog-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-patterns.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/definition-of-done.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/changelog-guide.md`

Read these repo files before writing code:
- `pkg/scanner.go` — `scanEnv()` (the frozen `HOME`+`PATH` allowlist, used by the clone, both gates, and `gitHeadSHA`), `Scan` (clone construction, the `cloneURL` derivation, `clone.Env = scanEnv()`), `NewScanner`, the `scanner` struct, the `Scanner` interface and its `//counterfeiter:generate` directive.
- `pkg/repo.go` — `Repo.CloneURL` (empty in production; fixture tests set it to a local path) and `Repo.Key()`.
- `pkg/scanner_test.go` — the existing suite and the `writeFixtureRepo(makefile string) string` helper (a new test file in the same `pkg_test` package reuses this helper; do NOT re-implement it).
- `pkg/dispatch_integration_test.go` — the existing integration harness: it constructs `pkg.NewScanner` directly and drives a real clone + real `make` against a local fixture repo. Mirror its fixture style.
- `pkg/pkg_suite_test.go` — carries `//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6@v6.12.2 -generate`, which is what turns `//counterfeiter:generate` directives into `mocks/*.go`.
- `Makefile.precommit` — `make generate` wipes `mocks/`, recreates `mocks/mocks.go` (`package mocks`), then runs `go generate -mod=mod ./...`.
- `CHANGELOG.md` — its top section is currently `## v0.2.2`; there is no `## Unreleased` section yet.
- `mocks/scanner.go` — the generated-mock conventions (never hand-edit; the file is wiped and regenerated).

Spec context you must honor:
- Every repo in the target fleet is private, so the current unauthenticated HTTPS clone fails with `could not read Username for 'https://github.com'` and the repo is reported `clone_failed` before any gate runs.
- The credential must reach `git clone` through git's environment-configuration interface: `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=http.extraheader`, `GIT_CONFIG_VALUE_0` = a Basic authorization header whose user is `x-access-token` and whose password is the minted token. `x-access-token` is the fleet convention (the binding part; `github-update-go-agent`'s `injectToken` helper embeds the same user form in a URL, which is exactly the conveyance this spec rejects).
- `http.extraheader` is not persisted: unlike a token embedded in the clone URL, it is never written to `<cloneDir>/.git/config`. A URL-embedded token would land in `remote.origin.url`, where the repo's own Makefile could read it.
- The credential environment is attached whenever a token source is configured, **regardless of the URL's scheme** — that is what makes the local-fixture integration test meaningful.
- The gate subprocesses are constructed independently and keep the frozen `HOME`+`PATH` allowlist. Adding a credential key to it is a regression, not an implementation choice.
- A mint failure (invalid App config, API unreachable, rate limit) is logged at WARN with its cause and the clone proceeds unauthenticated; the repo then reports `clone_failed` as it does today. A mint that hangs must be bounded by its own short timeout and must never consume the 20-minute scan budget.

Verified library/environment facts (do not re-derive from memory):
- `os/exec` — `exec.CommandContext(ctx, "git", args...)` resolves `git` through the process `PATH` at construction time; `cmd.Env`, `cmd.Dir`, `cmd.CombinedOutput()`, `cmd.Output()`.
- `encoding/base64` — `base64.StdEncoding.EncodeToString([]byte(...))`; the header payload is `base64("x-access-token:" + token)`. `base64.StdEncoding.DecodeString` in the test.
- `github.com/golang/glog` v1.2.5 — `glog.Warningf` writes through a stderr sink whose `Emit` resolves `os.Stderr` **at write time** (`glog_file.go`: `w := s.w; if w == nil { w = os.Stderr }`), and whose `Enabled` returns true when `alsoToStderr` is set. The `alsologtostderr` flag is bound with `flag.BoolVar(&alsoToStderr, ...)` in `glog_flags.go`. So `flag.Set("alsologtostderr", "true")` plus swapping `os.Stderr` for an `*os.File` captures WARN and INFO lines in-process — no pipe, no goroutine, no buffer-limit deadlock.
- git ≥ 2.31 is required for the `GIT_CONFIG_*` interface. The runtime image's `alpine:3.24` ships git 2.54.0 and the dev container ships git 2.39.5 — both fine.
- GNU make injects its own variables (`MAKELEVEL`, `MAKEFLAGS`, `MFLAGS`, `PWD`) into a recipe's environment: a recipe run under `env -i HOME=... PATH=... make` sees 6 lines from `env`, not 2. Any gate-environment assertion must therefore assert the credential-free properties plus the presence of the scanner's own `HOME`/`PATH` entries — an exact two-line equality can never pass.
- counterfeiter v6.12.2 is in the module cache; `make generate` regenerates every mock in `mocks/` from the `//counterfeiter:generate` directives. Mocks are never hand-written.

**Sibling entry-point check (already run):** one binary entry point (`main.go`). `pkg.NewScanner` has exactly three call sites — `pkg/factory/factory.go`, `pkg/scanner_test.go`, `pkg/dispatch_integration_test.go` — and this prompt updates the latter two; `pkg/factory/factory.go` is updated by the follow-up wiring prompt (which depends on this one). There is no `cmd/` tree.

<!-- REVIEWER NOTE (not for the executor, and not an action item for this prompt): the vendored
     `githubapp.MintIAT` emits a glog V(2) line containing an 8-character prefix of the minted token.
     That library behavior cannot be changed from this repo and is out of scope here; the constraint
     above governs the code this prompt writes. See prompt 2's requirements for the full note. -->

<!-- OPEN QUESTION FOR THE REVIEWER (not for the executor): requirement 1c adds `TokenSourceOf` as real
     package API purely so the follow-up prompt's factory test can observe the credential plumbing. The
     spec's AC 3 ("a factory test asserts that a scanner built with App credentials configured carries a
     non-nil token source while one built without them carries nil") cannot be satisfied from package
     `factory_test` by an `export_test.go` helper — those are only visible inside `pkg`'s own test binary —
     so the accessor must live in non-test code. If the reviewer prefers zero test-only API, the
     alternative is a behavioural factory test (build a scanner via the factory, run a real clone of a
     local fixture with the recording shim) at the cost of duplicating the shim harness across packages.
     Either way the `Scanner` interface must not grow a credential accessor. -->
</context>

<requirements>

### 1. `pkg/scanner.go` — token-source seam + credential-bearing clone environment

Package `pkg`. No new module dependencies (stdlib `encoding/base64` and `context` only).

**1a. Add the token-source contract** immediately above the `Scanner` interface, next to the existing `//counterfeiter:generate` directive for `Scanner`:

```go
//counterfeiter:generate -o ../mocks/token_source.go --fake-name TokenSource . TokenSource

// TokenSource mints the credential the scan-stage clone authenticates with.
// A nil TokenSource at the Scanner is the documented "unauthenticated" value:
// the clone then runs exactly as it did before this change.
type TokenSource interface {
	// Token returns one fresh credential for a single scan. The returned
	// value must never be logged, placed in argv, or written to disk.
	Token(ctx context.Context) (string, error)
}
```

Do NOT add `Token` (or any credential accessor) to the `Scanner` interface — the mock in `mocks/scanner.go` and the watcher's collaborator contract stay as they are.

**1b. Extend `NewScanner` and the `scanner` struct** with a `tokenSource TokenSource` parameter/field. Go has no default parameters, so the existing call sites must be updated in this same change (see 2 and 3):

```go
func NewScanner(
	gateTimeout time.Duration,
	tempDir string,
	gateTargets []string,
	tokenSource TokenSource,
) Scanner {
	return &scanner{
		gateTimeout: gateTimeout,
		tempDir:     tempDir,
		gateTargets: gateTargets,
		tokenSource: tokenSource,
	}
}
```

**1c. Add the wiring-introspection accessor.** The follow-up prompt's factory test must be able to assert that a scanner built with App credentials carries a non-nil token source and one built without carries nil. Because that test lives in a different package (`factory_test`) it cannot use an `export_test.go` helper (those are only visible inside `pkg`'s own test binary), so the accessor is real package API:

```go
// TokenSourceOf returns the token source s was built with (nil when the
// scanner clones unauthenticated). It exists so the wiring test can assert the
// credential plumbing without widening the Scanner contract; it is
// deliberately not part of the Scanner interface.
func TokenSourceOf(s Scanner) TokenSource {
	if sc, ok := s.(*scanner); ok {
		return sc.tokenSource
	}
	return nil
}
```

No other test-only API may be added to `pkg`.

**1d. Add the mint bound and the credential environment.** The mint must be bounded by its own short timeout so a hung mint can never consume the per-scan budget:

```go
// tokenMintTimeout bounds one installation-token mint. A hung mint must not
// consume the per-scan budget: it would surface as a spurious clone_failed for
// a repo whose clone was never attempted.
const tokenMintTimeout = 30 * time.Second

// credentialEnv returns the git environment-configuration entries that convey
// token to the clone subprocess. git >= 2.31 reads GIT_CONFIG_COUNT /
// GIT_CONFIG_KEY_<n> / GIT_CONFIG_VALUE_<n>; http.extraheader is not persisted
// to .git/config, unlike a token embedded in the clone URL. The credential
// lives in this slice only: never in the URL, never in argv, never on disk,
// never in a log line.
func credentialEnv(token string) []string {
	header := "AUTHORIZATION: basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))
	return []string{
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.extraheader",
		"GIT_CONFIG_VALUE_0=" + header,
	}
}
```

**1e. Add the clone-environment method** and use it for the clone only:

```go
// cloneEnv returns the clone subprocess's environment: the frozen HOME+PATH
// allowlist plus, when a token source is configured, the git
// environment-configuration entries carrying the installation credential. A
// mint failure is logged at WARN with its cause and degrades to the
// unauthenticated clone. The gate subprocesses never receive these entries —
// they keep using scanEnv().
func (s *scanner) cloneEnv(ctx context.Context, repo Repo) []string {
	env := scanEnv()
	if s.tokenSource == nil {
		return env
	}
	mintCtx, cancel := context.WithTimeout(ctx, tokenMintTimeout)
	defer cancel()
	token, err := s.tokenSource.Token(mintCtx)
	if err != nil {
		glog.Warningf(
			"mint installation token failed repo=%s err=%v; cloning unauthenticated",
			repo.Key(),
			err,
		)
		return env
	}
	return append(env, credentialEnv(token)...)
}
```

In `Scan`, change exactly one line — `clone.Env = scanEnv()` becomes `clone.Env = s.cloneEnv(ctx, repo)`. `Scan` is already close to the `funlen` limit (80 lines), so keep the mint logic in `cloneEnv`; do not inline it.

**1f. Freeze the rest of `Scan`.** The clone URL derivation stays exactly as it is (`repo.CloneURL`, else `https://github.com/<owner>/<name>.git`) — the URL is credential-free by construction and must stay that way. `glog.Infof("git clone repo=%s url=%s", ...)` stays (the URL carries no credential). The gate subprocesses (`gate.Env = scanEnv()`) and `gitHeadSHA` (`cmd.Env = scanEnv()`) keep the frozen allowlist — the minted credential must not reach them. No log statement anywhere may contain the token, a prefix of it, the base64 header form, or a hash of it.

### 2. `pkg/scanner_test.go` — one changed line, nothing else

In the `ginkgo.JustBeforeEach` block, the constructor call becomes:

```go
scanner = pkg.NewScanner(gateTimeout, tempDir, []string{"vulncheck", "check"}, nil)
```

That single line is the ONLY change permitted in this file. Every other line — all existing `Expect` assertions, the `writeFixtureRepo` helper, the describe/it text — must remain byte-identical to its pre-change content. This is a spec acceptance criterion: the unauthenticated path must be provably unchanged, and the evidence is a diff that removes zero `Expect` lines. Do not reformat, reorder, or "improve" anything here, and do not add new specs to this file (new specs go in the new file from requirement 4).

### 3. `pkg/dispatch_integration_test.go` — constructor call only

Update the existing call in `newDispatchHarness` to pass `nil` as the token source:

```go
realScanner := pkg.NewScanner(time.Minute, h.scanRoot, []string{"vulncheck", "check"}, nil)
```

Change nothing else in that file.

### 4. New file `pkg/scanner_auth_integration_test.go` — the credential evidence

Package `pkg_test` (external test package, Ginkgo/Gomega, BSD license header like every other file). This file reuses `writeFixtureRepo(makefile string) string` from `pkg/scanner_test.go` — do not re-implement a fixture helper, and do not modify that helper.

**4a. The recording `git` shim.** The scan's own subprocess environment is only observable from outside the scanner, so the test prepends a recording `git` shim to `PATH`:

```go
// installRecordingGitShim writes an executable `git` shim into a fresh temp dir
// and prepends that dir to PATH for the rest of the spec. Each shim run records
// its own invocation (argv, env, cwd) into its own directory under recordRoot,
// then delegates to the real git binary.
func installRecordingGitShim(recordRoot string) { ... }
```

Non-negotiable mechanics (each of these has a concrete failure mode):
- Resolve the real binary with `exec.LookPath("git")` **before** touching `PATH`, and `exec` it by absolute path in the shim. A relative `git` call from inside the shim recurses into the shim forever.
- **Bake the absolute `recordRoot` path into the script text** (string interpolation). The shim cannot read it from the environment: the scanner replaces the child environment with its own allowlist, so no custom variable survives to the shim. Pass nothing to the shim via env.
- Give each invocation its own record directory, e.g. `d="<recordRoot>/$$"; mkdir -p "$d"` — a fresh shell per invocation, so `$$` is unique per invocation and no index/lock is needed.
- Record `argv` (`printf '%s\n' "$@" > "$d/argv"`), `env` (`env > "$d/env"`), and `cwd` (`pwd > "$d/cwd"`), then `exec <absolute real git> "$@"`.
- Write the script with `os.WriteFile(..., 0o755)` and install it with `GinkgoT().Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))`. (gosec skips `_test.go` files by default — `-tests=false` — and `.golangci.yml` excludes gosec for `_test.go`, so the executable mode is fine; do not add a `#nosec`.)
- **Identify invocations by their recorded `argv`, never by index.** In one scan the scanner runs `git clone` and `git rev-parse HEAD`, and the fixture Makefile also shells out to git; only `argv[0] == "clone"` is the clone invocation.

**4b. The fixture Makefile evidence probes.** Build the fixture's Makefile text and hand it to the existing `writeFixtureRepo` helper. Create the fixture repo **before** installing the shim so fixture-setup git calls are not recorded. The Makefile must write, into a test-provided absolute evidence directory:

- `gate-env-vulncheck.txt` / `gate-env-check.txt` — `env | sort` captured from inside each gate (one file per gate target), proving what the gate subprocess actually received.
- `remote-origin-url.txt` — the output of `<absolute real git> config --get remote.origin.url` run from inside the clone directory (the gate's cwd). Bake the absolute real-git path in so the probe bypasses the shim.
- `clone-dir-grep-token.txt` / `clone-dir-grep-header.txt` — `grep -rlF "$$(cat <evidenceDir>/token-form.txt)" .` and `grep -rlF "$$(cat <evidenceDir>/header-form.txt)" .` over the clone directory. The two credential forms are written by the test into the evidence directory (which lives OUTSIDE the clone) and read at recipe time — they must never be inlined into the Makefile text, because that Makefile is itself checked out inside the clone directory, so an inlined pattern makes the grep match its own fixture and the "both grep files are empty" assertion can never pass. Use `grep -F` (the base64 payload contains `+`, `/`, `=`), escape the command substitution for make as `$$(cat ...)`, and tolerate a non-zero exit (`|| true`) so an empty result is not a gate failure.

`vulncheck` prints one `GO-2024-1234\t...` marker line and exits 1 (the existing fixtures' pattern) so the scan also reaches `gitHeadSHA`; `check` prints `check ok`. Recipe lines must be tab-indented (use `"\t"` escapes as the existing helpers do).

**4c. The log capture helper.** In-process glog capture, verified against glog v1.2.5:

```go
// scanCapturingStderr runs fn with glog's WARN/INFO output redirected into a
// temp file, and returns the captured text plus fn's error.
func scanCapturingStderr(fn func(ctx context.Context) error) (string, error) { ... }
```

It must: `Expect(flag.Set("alsologtostderr", "true")).To(Succeed())` (this is what makes the WARNING reach the stderr sink) and restore it to `"false"` afterwards; create a temp `*os.File`; save `os.Stderr`, assign the file to `os.Stderr`, run `fn(context.Background())`, restore `os.Stderr`, close the file, and return `os.ReadFile(f.Name())`. Use a file, not an `os.Pipe` — a pipe whose buffer fills would deadlock the scan.

**4d. Specs to write.** A `Describe("scan-stage clone credentials")` whose `BeforeEach` performs one authenticated scan (sentinel credential `"ghs_sentinel"`, base64 payload computed in the test as `base64.StdEncoding.EncodeToString([]byte("x-access-token:"+sentinel))`, a token source built from `&mocks.TokenSource{TokenReturns(sentinel, nil)}`, the shim installed, a 60-second gate timeout, `pkg.Repo{Owner: "fixture-owner", Name: "fixture-repo", CloneURL: fixtureDir}`) and stores the recorded invocations, the evidence files, and the captured log for the `It` blocks:

1. **The credential reaches the real clone process.** The `clone` invocation's recorded env contains `GIT_CONFIG_COUNT=1` and `GIT_CONFIG_KEY_0=http.extraheader`, and its `GIT_CONFIG_VALUE_0`'s final whitespace-separated field base64-decodes to `x-access-token:ghs_sentinel`. (Decode in the assertion; do not hardcode the encoded string.)
2. **The credential never reaches the URL or argv.** The clone invocation's argv has exactly three elements — `clone`, `fixtureDir`, and a non-empty clone directory distinct from `fixtureDir` (the clone dir is a fresh `os.MkdirTemp` path the test cannot know in advance, so assert its shape, not its value) — and no recorded argv entry of ANY invocation contains the literal `ghs_sentinel` or the base64 payload.
3. **The scanned repo's own gates never receive the credential, and the allowlist is still exactly `HOME`+`PATH`.** Each captured gate env contains the scanner's own `HOME=<value>` and `PATH=<value>` entries verbatim (`"HOME=" + os.Getenv("HOME")`, `"PATH=" + os.Getenv("PATH")`), and no line matches `GIT_CONFIG|Authorization`, contains the literal `ghs_sentinel`, or contains the base64 payload. **Assert the positive allowlist as well as the absence of the credential**: every captured line's variable name must be one of `HOME`, `PATH`, plus the variables make itself injects (derive the exact set from the captured file — do not assume it; the expected additions are `MAKELEVEL`, `MAKEFLAGS`, `MFLAGS`, `PWD`). An absence-only assertion cannot catch a widening that introduces a *different* variable — `KAFKA_BROKERS` or `SENTRY_DSN` would slip past a denylist that names only `GIT_CONFIG|Authorization`, and the spec calls any widening of this allowlist a regression. Comment in the test why an exact two-line equality can never pass (make injects those four).
4. **Nothing credential-bearing is persisted into the clone directory.** `remote-origin-url.txt` equals the fixture path, contains no `@`, and contains neither credential form; both clone-dir grep files are empty.
5. **The credential is never logged.** The captured log contains neither the literal `ghs_sentinel`, nor the base64 payload, nor the 8-character prefix `ghs_sent` (the spec forbids logging the token, its prefix, or its encoded form). **Before** those zero-match assertions, assert the capture is live by requiring a known line, e.g. `ContainSubstring("git clone ok repo=fixture-owner/fixture-repo")` — a capture that silently produced nothing would otherwise make the zero-match assertions vacuous.

A second `Describe("scan-stage clone fallbacks")` with its own setup, covering:
6. **A mint failure degrades to today's unauthenticated clone.** Token source `&mocks.TokenSource{TokenReturns("", stderrors.New("mint boom"))}`: the scan of the local fixture succeeds, the recorded clone env contains no entry with the prefix `GIT_CONFIG_`, and the captured log contains both `mint installation token failed` and `mint boom` (and still neither credential form).
7. **An unconfigured token source clones unauthenticated.** `pkg.NewScanner(..., nil)`: the scan succeeds and the recorded clone env contains no `GIT_CONFIG_` entry.
8. **The derived URL is used when `Repo.CloneURL` is empty.** With `CloneURL: ""` and a token source configured, the recorded clone argv's URL is exactly `https://github.com/fixture-owner/fixture-repo.git` and the clone env still carries the credential entries (the credential env is attached regardless of the URL's scheme). This clone may fail or hang — bound it with a 2-second gate timeout and assert nothing about the scan outcome; the shim records the invocation before delegating, so the recorded argv is available either way.
9. **The mint is bounded by its own timeout.** Use a token source whose `Token` records `ctx.Deadline()` and then returns an error immediately — do NOT wait for the deadline; a spec that sleeps 30 seconds is not acceptable. Assert that a deadline was set and lands within 30 seconds of the call. `tokenMintTimeout` is unexported, so assert the bound, not the symbol. This is the only guard for the spec's "a mint that hangs must never consume the 20-minute scan budget" failure mode: the other token sources in this file ignore their context, so dropping the timeout would leave the whole suite green.

### 5. `CHANGELOG.md` — new `## Unreleased` section

The file's top section is currently `## v0.2.2`. Create a new `## Unreleased` section **above** it (a bullet added to the released section would ship inside that release's tag; `.maintainer.yaml` sets `release.autoRelease: true`, so the release bot cuts the version — never create a tag by hand) with one bullet:

```
- feat: scan-stage clone authenticates as the watcher's GitHub App installation — the installation token reaches `git clone` through the process environment (`http.extraheader` via `GIT_CONFIG_*`) and never through the clone URL, argv, the clone directory, or a log line, while gate subprocesses keep the frozen `HOME`+`PATH` allowlist
```

<!-- OPEN QUESTION FOR THE REVIEWER (not for the executor): the spec's Suggested Decomposition assigns
     the CHANGELOG bullet to prompt 2. This prompt creates the `## Unreleased` section instead, and
     prompt 2 appends to it, because the project's own changelog rule requires the entry at
     implementation time and because creating the section in both prompts would risk two `## Unreleased`
     headings. The binding constraint — the bullet must not land inside the released `## v0.2.2` section —
     holds either way. -->

### 6. Self-check before finishing

Re-run every command in `<verification>` and confirm each passes. Walk each acceptance criterion in this prompt against the change: the credential reaches the real clone env; it appears in no argv, no clone-directory file, no gate env, and no log line (each asserted in both literal and base64 form); a mint failure and a nil token source both still clone; `pkg/scanner_test.go` changed by exactly one line.

</requirements>

<constraints>
- **Credential conveyance is frozen**: environment only, via `http.extraheader`. The credential must never appear in the clone URL, in argv, in any file inside the clone directory, or in any log line. These four are the reason the mechanism was chosen and must not be relaxed for convenience.
- **The gate environment allowlist is frozen** at `HOME` + `PATH`. Adding a credential key to it is a regression, not an implementation choice.
- **No new failure mode**: an unconfigured or failing token source must not make a previously-working scan fail. A mint that hangs is bounded by its own short timeout (30s) and treated as a mint failure — it must never consume the 20-minute scan budget.
- **No credential is logged by code you write** — not the token, not its prefix, not its base64 header form, not a hash of it. This governs every log statement this prompt adds or changes. (The vendored `githubapp.MintIAT` emits an 8-character token prefix at `glog.V(2)`, and the deployed pod runs with `-v=2`, so that line is live — but it is dependency behavior this repo cannot change. It is a reviewer decision recorded in `<context>`, not an executor action: do not attempt to suppress it, and do not let it block the work.)
- **No caching layer.** A token is minted per scan. GitHub App installation tokens are valid for up to one hour and a single repo's scan is bounded by the existing 20-minute gate timeout, so a per-scan mint is always fresh. Do not add a refresh interval, a cache, or a tunable.
- **No SSH.** The runtime image ships no `openssh-client` and no key, by design. Do not add either, and do not change the HTTPS URL derivation.
- **No change to the consent / allowlist / `go.mod` filters, the cursor, the dedup, or the emit contract.** Do not touch `pkg/metrics.go` label sets.
- Do NOT modify `mocks/*.go` by hand — add the `//counterfeiter:generate` directive and run `make generate`.
- Never use `fmt.Errorf`; all errors go through `github.com/bborbe/errors` and carry `ctx`.
- Every new `.go` file starts with the BSD license header block used by the existing files.
- Keep every line under 100 characters (`golines --max-len=100`), every function under 80 lines / 50 statements (`funlen`), and nesting under 4 (`nestif`).
- **AC 10 of the spec (the live private-repo clone proof on the dev cluster) is jointly owned with the octopus rollout task and is NOT satisfiable inside this container.** Do not attempt it, do not add a command that pretends to check it, and do not weaken anything to make it appear to pass.
- Do NOT commit — dark-factory handles git.
- Existing tests must still pass.
</constraints>

<verification>
Run from the repo root. Every command below must pass; the first two are the binding evidence, the rest are supporting checks.

```
make precommit
```
Must exit 0.

Unauthenticated path unchanged (`pkg/scanner_test.go` is frozen except for the constructor line). `.git` is masked in this container (`hideGit=true` is set on the daemon), so `git merge-base` and `git diff` exit 128 with `fatal: not a git repository` here — the merge-base diff that the spec names as this criterion's evidence therefore runs on the host, in the operator rung. The same property is asserted below without git, against the baseline recorded when this prompt was written (27 `Expect(` lines, 218 lines — both re-verified against the file):

```
test "$(grep -cF 'Expect(' pkg/scanner_test.go)" = "27" || { echo "FAIL: Expect-line count changed"; exit 1; }
test "$(wc -l < pkg/scanner_test.go | tr -d ' ')" = "218" || { echo "FAIL: file length changed"; exit 1; }
grep -qF 'pkg.NewScanner(gateTimeout, tempDir, []string{"vulncheck", "check"}, nil)' pkg/scanner_test.go \
  || { echo "FAIL: constructor call not updated"; exit 1; }
echo "OK: 27 Expect lines, 218 lines, constructor call updated"
```

The token user form matches the fleet convention (spec verification rung):

```
grep -rn 'x-access-token' pkg/ --include='*.go' | grep -v '_test.go'
```
Expect at least one hit (in `pkg/scanner.go`).

```
grep -c 'GIT_CONFIG_COUNT\|GIT_CONFIG_KEY_0\|GIT_CONFIG_VALUE_0' pkg/scanner.go
```
Expect at least 3 (the `credentialEnv` doc comment also names `GIT_CONFIG_COUNT`, so the line count is 4 — this is a presence check, not an exact count).

The credential mechanism stays confined to the scanner (supporting check — the wiring prompt adds nothing credential-shaped elsewhere):

```
for p in pkg/watcher.go pkg/factory main.go; do test -e "$p" || { echo "FAIL: missing $p"; exit 1; }; done
if grep -rn 'GIT_CONFIG' pkg/watcher.go pkg/factory/ main.go 2>/dev/null; then
  echo "FAIL: GIT_CONFIG found outside pkg/scanner.go"; exit 1
fi
echo "OK: GIT_CONFIG confined to pkg/scanner.go"
```

```
go test -mod=mod ./pkg/... -count=1
```
Must exit 0 (this repo does not commit `vendor/`, so `-mod=mod` is required).

The new specs actually ran (a focus-less pass could otherwise hide a typo'd `Describe`):

```
go test -mod=mod ./pkg/... -count=1 -v -ginkgo.v 2>&1 | grep -c 'scan-stage clone'
```
Expect at least 1.
</verification>
