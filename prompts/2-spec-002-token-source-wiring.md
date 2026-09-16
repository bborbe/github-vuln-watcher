---
status: draft
spec: [002-private-repo-scan-clone-auth]
created: "2026-09-16T20:46:00Z"
branch: dark-factory/private-repo-scan-clone-auth
---

<summary>
- The watcher now mints its own GitHub App installation credential, from the same App configuration the inventory stage already uses, so one App configuration drives both stages.
- A credential source built with App credentials is threaded through the composition root into the scanner; without credentials the scanner is left with none and clones unauthenticated exactly as before.
- The scan credential is minted per scan from the GitHub API and is never cached, never logged, and never stored — the scan's own 20-minute bound is what keeps it fresh.
- A mint that fails or is unreachable returns an error instead of failing the service or the scan, so a broken App configuration degrades to the old behavior rather than taking the watcher down.
- The security rationale that justifies the design — the gate allowlist, why the credential travels in the process environment rather than the clone URL, and the residual risk that is accepted rather than mitigated — is written down in the repo so it survives this change.
- Operators get the App configuration documented in the sample environment file and the README.
- The release notes carry the change under a new unreleased heading rather than inside an already-released section.
</summary>

<objective>
Thread the GitHub App credential from the composition root into the scanner: build a per-scan token source on top of the already-vendored `githubapp.MintIAT`, pass it through the watcher factory into the scanner built by the previous prompt, and record the security rationale (gate allowlist, environment-only conveyance, accepted `/proc/<pid>/environ` residual risk) in `docs/security-model.md` so the reasoning outlives the spec.
</objective>

<context>
Read `docs/dod.md` (this repo's Definition of Done).

Read these coding plugin docs before writing code (paths are inside the container):
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-factory-pattern.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-patterns.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-error-wrapping-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-testing-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-security-linting.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/definition-of-done.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/changelog-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/readme-guide.md`

Read these repo files before writing code:
- `pkg/scanner.go` — the `TokenSource` interface, `NewScanner`, and `TokenSourceOf` added by the previous prompt (this prompt consumes them; do not change them).
- `pkg/auth/auth.go` — `Credentials`, `ResolveGitHubClient`, and the package doc that explains why I/O lives in `auth` and not in `pkg/factory`.
- `pkg/factory/factory.go` — `CreateWatcher` and `scanTimeout`; `pkg/factory/factory_test.go` — the existing `CreateWatcher` wiring spec.
- `main.go` — `application.Run` already builds `auth.Credentials` inline for `auth.ResolveGitHubClient` and calls `factory.CreateWatcher`.
- `docs/dod.md` — the counterfeiter/mock rule.
- `CHANGELOG.md` — the previous prompt created a `## Unreleased` section above `## v0.2.2`; append to it, do not create a second one.
- `example.env`, `README.md`, `.maintainer.yaml` (`release.autoRelease: true` — the release bot cuts the version; never create a tag by hand).

Verified library facts (do not re-derive from memory):
- `github.com/bborbe/maintainer/githubapp` (already a direct dependency at the version in `go.mod`) — `func MintIAT(ctx context.Context, cfg Config) (string, error)` returns the installation access token as a plain string, e.g. `ghs_...`; `type Config struct { AppID int64; InstallationID int64; PEM []byte; PEMPath string; BaseURL string }` where `BaseURL` "defaults to https://api.github.com; used for testing with httptest". `MintIAT` wraps `errors.Wrap` internally and returns an error when the config is invalid (AppID/InstallationID must be positive; exactly one of PEM/PEMPath must be set) or when the token exchange fails.
- `githubapp.MintIAT` is the right seam here and `githubapp.NewClient` is not: `NewClient` returns a long-lived `*http.Client` with an auto-refreshing transport, which is what the inventory stage needs, while the scan needs one raw token string per scan to hand to a subprocess. A per-scan mint is always fresh: installation tokens live up to an hour and one scan is bounded by the existing 20-minute gate timeout.
- The mint is an HTTP exchange with the GitHub API: `POST <BaseURL>/app/installations/<installationID>/access_tokens` with an `Authorization: Bearer <app JWT>` header, and the response body is JSON `{"token": "...", "expires_at": "..."}`. `ctx` is honoured end to end (`ghinstallation` calls `req.WithContext(ctx)`), so the scanner's own mint timeout really does bound it.
- `github.com/bborbe/errors` — `errors.Wrap(ctx, err, "message")` / `errors.Wrapf(ctx, err, fmt, args...)`. Never `fmt.Errorf`.
- `main.go`'s `a.AppID` / `a.InstallationID` are `int64` and `a.PEMKey` is a `string`; `auth.Credentials.PEMKey` is `[]byte`.

**Sibling entry-point check (already run):** one binary entry point (`main.go`); no `cmd/` tree. `factory.CreateWatcher` has exactly two call sites — `main.go` and `pkg/factory/factory_test.go` — and both are updated here. `pkg.NewScanner`'s remaining call site is `pkg/factory/factory.go`, updated here; the two test call sites were updated by the previous prompt.
</context>

<requirements>

### 1. `pkg/auth/auth.go` — a documented API base-URL seam

Add one field to `Credentials`:

```go
type Credentials struct {
	AppID          int64
	InstallationID int64
	PEMKey         []byte
	// BaseURL is the GitHub API base URL; empty means https://api.github.com.
	// It mirrors githubapp.Config.BaseURL. Its consumer today is a test seam
	// (httptest servers); a GitHub Enterprise deployment would be the
	// production consumer, so it is not test-only state.
	BaseURL string
}
```

Pass it through in `ResolveGitHubClient` — the `githubapp.Config` it already builds gains `BaseURL: creds.BaseURL`. Nothing else in that function changes; its partial-credential and unconfigured error behavior is frozen (existing tests must pass untouched).

### 2. New file `pkg/auth/tokensource.go` — the mint

Package `auth`, BSD license header, imports `context`, `github.com/bborbe/errors`, `github.com/bborbe/maintainer/githubapp`, and `github.com/bborbe/github-vuln-watcher/pkg`.

```go
// NewTokenSource returns a token source that mints a GitHub App installation
// access token per call. Construction performs no I/O and never fails: a mint
// error surfaces per call, so one scan's mint failure degrades that scan to an
// unauthenticated clone instead of taking the service down.
func NewTokenSource(creds Credentials) pkg.TokenSource
```

`Token(ctx)` calls `githubapp.MintIAT(ctx, githubapp.Config{AppID: ..., InstallationID: ..., PEM: ..., BaseURL: ...})` and wraps a failure with `errors.Wrap(ctx, err, "mint installation token")`. No caching, no refresh interval, no expiry bookkeeping — a token is minted per call and nothing about it is retained. No log statement in this file may contain the token, a prefix of it, or the PEM bytes (the PEM is the long-lived secret and arrives by environment only).

`Token` must not validate the credentials itself; `MintIAT` already returns a named error for an invalid config, and duplicating that logic would drift.

<!-- OPEN QUESTION FOR THE REVIEWER (not for the executor): the spec's constraints say "No credential is
     logged, ever — not the token, not its prefix, not its base64 header form, not a hash of it", but the
     vendored `githubapp.MintIAT` emits `glog.V(2).Infof("githubapp: minted IAT for app_id=%d
     installation_id=%d token_prefix=%s...", ..., prefix8(token))` — the first 8 characters of the live
     token, at a verbosity this deployment runs with. This repo cannot change that (it is a module-cache
     dependency, not vendored code), and forking or wrapping it to silence the line is out of scope for
     this spec. Consequence: spec AC 7 ("`grep -c` over the scan's captured log output for both the literal
     `ghs_sentinel` and its base64 header form returns 0") still passes, because the library truncates at
     8 characters and the encoded form appears nowhere — but the stricter prose constraint is not met by
     the library. The reviewer should decide whether to file an upstream issue against
     `bborbe/maintainer` (recommended, since the pod logs currently carry an 8-character token prefix) or
     to accept it and amend the constraint to "no full credential, no encoded form, no hash". Do NOT ask
     the executor to suppress it — that is impossible from this repo. -->

### 3. New file `pkg/auth/tokensource_test.go` — the mint crosses a real HTTP boundary

Package `auth_test`, Ginkgo/Gomega, BSD license header. This is the only test that exercises the real mint path — the scanner's own tests use a mock token source — so it must drive the real code through a real HTTP exchange rather than assert on shapes.

Generate a throwaway RSA key in the test (`crypto/rsa` + `crypto/x509` + `encoding/pem`: `rsa.GenerateKey(rand.Reader, 2048)`, `x509.MarshalPKCS1PrivateKey`, `pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})`) and build `auth.Credentials{AppID: 12345, InstallationID: 67890, PEMKey: keyPEM, BaseURL: server.URL}`.

With an `httptest.NewServer` whose handler records the request and responds:
- `POST` to `/app/installations/67890/access_tokens` with `Content-Type: application/json` and an `Authorization` header that starts with `Bearer ` — assert the recorded path and method, and that the bearer value is a JWT (three dot-separated segments).
- body `{"token":"ghs_minted","expires_at":"<RFC3339, one hour ahead>"}` and status 200.

Specs to write:
1. **happy path**: `Token(ctx)` returns exactly `"ghs_minted"` and no error; the recorded request path/method/headers are as above (this is what proves the App credential path — JWT signing plus the installation-token exchange — actually works, not merely that a struct was populated).
2. **API failure**: the handler returns 500 → `Token(ctx)` returns an error and an empty string.
3. **unreachable API**: point `BaseURL` at a closed listener (e.g. a server closed immediately after `httptest.NewServer`) → `Token(ctx)` returns an error, no panic.
4. **invalid config, no network**: `auth.Credentials{}` and `auth.Credentials{AppID: 1, InstallationID: 1, PEMKey: []byte("not-a-real-key")}` → `Token(ctx)` returns an error without any server being contacted, and the error text contains neither the PEM bytes nor the string `not-a-real-key` (mirror the existing `pkg/auth/auth_test.go` style for "never the PEM value").
5. **context cancellation is honoured**: with a handler that blocks until the request context is done, cancel the context passed to `Token(ctx)` → it returns promptly with an error rather than hanging (this is the property the scanner's mint timeout depends on).

### 4. `pkg/factory/factory.go` — build the scanner with the token source

Add a zero-logic factory function and use it from `CreateWatcher` (the factory stays pure composition — no I/O, no conditionals):

```go
// CreateScanner builds the signal-stage scanner. tokenSource may be nil, which
// is the documented "unauthenticated" value: the clone then runs without any
// credential in its environment.
func CreateScanner(gateTargets []string, tokenSource pkg.TokenSource) pkg.Scanner {
	return pkg.NewScanner(scanTimeout, "", gateTargets, tokenSource)
}
```

`CreateWatcher` gains a final parameter `tokenSource pkg.TokenSource` and replaces its inline `pkg.NewScanner(scanTimeout, "", gateTargets)` call with `CreateScanner(gateTargets, tokenSource)`. Its parameter order is otherwise unchanged: `(githubHTTPClient, sender, metrics, cursorPath, owner, stage, taskCreationFilter, gateTargets, tokenSource)`.

### 5. `pkg/factory/factory_test.go` — the threading assertion

Update the existing `CreateWatcher` spec's call to pass the new final argument (`nil` keeps that spec's meaning unchanged), and add a spec asserting the credential plumbing — this is a spec acceptance criterion, and the factory test outcome is its binding evidence (a `grep` for `MintIAT` is supporting context only, since a grep is satisfiable by a comment):

```go
It("threads the token source into the scanner, nil when unconfigured", func() {
	tokenSource := &mocks.TokenSource{}
	Expect(pkg.TokenSourceOf(
		factory.CreateScanner([]string{"vulncheck", "check"}, tokenSource),
	)).To(BeIdenticalTo(tokenSource))

	Expect(pkg.TokenSourceOf(
		factory.CreateScanner([]string{"vulncheck", "check"}, nil),
	)).To(BeNil())
})
```

`mocks.TokenSource` is the counterfeiter fake generated for `pkg.TokenSource` by the previous prompt; do not hand-write or edit anything under `mocks/`.

### 6. `main.go` — build the token source at the composition root

In `application.Run`, hoist the credentials literal into a variable and use it twice, so one App configuration drives both stages:

```go
creds := auth.Credentials{
	AppID:          a.AppID,
	InstallationID: a.InstallationID,
	PEMKey:         []byte(a.PEMKey),
}
httpClient, err := auth.ResolveGitHubClient(ctx, creds)
if err != nil {
	return errors.Wrapf(ctx, err, "resolve GitHub client")
}
defer httpClient.CloseIdleConnections()

// The scan-stage clone authenticates as the same App installation as the
// inventory stage. Construction performs no I/O: a mint failure surfaces per
// scan and degrades to the unauthenticated clone.
tokenSource := auth.NewTokenSource(creds)
```

and pass `tokenSource` as the new final argument of `factory.CreateWatcher`. No new error path is added to `Run` — `ResolveGitHubClient` remains the only credential gate at startup.

**Guard the composition root.** `application.Run` cannot be exercised (it needs a Kafka broker), and this call site is the one link in the chain that nothing else covers: if it passed `nil` instead of `tokenSource`, every other test in the repo would still be green while the deployed feature stayed inert — the exact "mint but never wire" failure this spec exists to prevent. `main_test.go` already reads `main.go` and asserts substrings (the `DATADIR` / `BATCH_SIZE` / `default:"12h"` spec), so extend that idiom with a wiring guard:

```go
It("wires the scan token source into the watcher", func() {
	source, err := os.ReadFile("main.go")
	Expect(err).NotTo(HaveOccurred())
	text := string(source)
	Expect(text).To(ContainSubstring("tokenSource := auth.NewTokenSource(creds)"))
	Expect(text).To(MatchRegexp(`(?s)CreateWatcher\(.*?tokenSource,\s*\)`))
})
```

The regexp is the load-bearing half: it requires the `CreateWatcher` call to end with `tokenSource,`, so passing `nil` there fails the test rather than merely looking plausible. A bare `grep` for the symbol is not sufficient evidence for this — it is satisfiable by a comment.

### 7. New file `docs/security-model.md` — the rationale outlives the spec

Completed specs are immutable, so the reasoning this change depends on must live in the repo. Write a short, factual document (no speculation, no TODOs) covering:

1. **The threat**: a scanned repo is hostile — its Makefile runs arbitrary commands as the watcher's user, so if it can read the installation token it can act as the App installation across every repo the App can reach. That is a privilege escalation from "one repo's CI" to "the installation's whole scope".
2. **The gate allowlist**: gate subprocesses receive exactly `HOME` and `PATH` and nothing else; the credential key is never added to that allowlist. Adding it is a regression, not an implementation choice.
3. **Why the credential travels in the process environment**: `http.extraheader` via git's environment-configuration interface (`GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_0` / `GIT_CONFIG_VALUE_0`) is not persisted to `.git/config`, unlike a token embedded in the clone URL (which lands in `remote.origin.url`, where the repo's own Makefile can read it, and in clone-failure output that gets logged). The credential is not in argv, so it is not readable from the process table. It is never logged, so it does not survive in pod logs, log shipping, or Sentry.
4. **The bounding window**: the clone directory is removed after each scan, and the credential is minted per scan (no cache) and is valid for at most an hour.
5. **The residual risk, stated plainly and accepted rather than mitigated**: the token is a live credential in the clone process's environment for the duration of the clone. A process that could read `/proc/<pid>/environ` as the same user during that window could obtain it. No untrusted code runs during the clone — gates execute after it returns — so reaching that window requires a process the watcher did not start. The alternatives (an SSH key in the image, a credential on disk) are strictly worse and were already rejected by the original design.
6. **The failure behavior**: a mint failure is logged at WARN with its cause and the clone proceeds unauthenticated, so public repos are unaffected and private repos report `clone_failed` exactly as they did before this change.

The document must contain the literal `HOME` (the allowlist) and the literal `/proc/<pid>/environ` (the residual risk) — both are asserted by the spec's acceptance criteria.

### 8. `example.env` and `README.md` — the operator-facing surface

- `example.env`: add the three App settings the scan now also depends on, as empty placeholders (`export APP_ID=`, `export INSTALLATION_ID=`, `export PEM_KEY=`). Never put a real key or token in this file — it is committed.
- `README.md`: two or three sentences stating that the scan-stage clone authenticates as the watcher's GitHub App installation using `APP_ID` / `INSTALLATION_ID` / `PEM_KEY` (the same values the inventory stage uses, populated from a Kubernetes Secret), that the credential never enters the clone URL or the cloned repo's gates, and that with no App credentials configured the clone runs unauthenticated.

### 9. `CHANGELOG.md` — append to the existing section

The previous prompt created `## Unreleased` above `## v0.2.2`. Append this bullet to that section (do not create a second `## Unreleased`, and never add bullets to a released section — `.maintainer.yaml` sets `release.autoRelease: true`, so the release bot cuts the version and no tag is created by hand):

```
- feat: build the scan-stage token source from the same GitHub App credentials the inventory stage uses (per-scan `githubapp.MintIAT`, no cache, no refresh knob) and document the clone-credential security model in `docs/security-model.md`
```

### 10. Self-check before finishing

Re-run every command in `<verification>` and confirm each passes. Walk each acceptance criterion in this prompt against the change: the factory test asserts non-nil versus nil token source; the mint is exercised through a real HTTP exchange; the security rationale is on disk with both required literals; the unreleased section is above the latest release.

</requirements>

<constraints>
- **Credential conveyance is frozen**: environment only, via `http.extraheader`. The credential must never appear in the clone URL, in argv, in any file inside the clone directory, or in any log line. Nothing in this prompt may move the credential anywhere else — in particular, do not add the credential to the gate environment allowlist (frozen at `HOME` + `PATH`; widening it is a regression against the frozen constraint from spec 001).
- **No caching layer.** A token is minted per scan. GitHub App installation tokens are valid for up to one hour and a single repo's scan is bounded by the existing 20-minute gate timeout, so a per-scan mint is always fresh. Do not add a cache, a refresh interval, or any tunable.
- **No multi-owner or per-repo credentials.** One App installation per instance, mirroring the inventory stage.
- **No SSH.** The runtime image ships no `openssh-client` and no key, by design. Do not add either.
- **No change to the consent / allowlist / `go.mod` filters, the cursor, the dedup, or the emit contract.** Do not touch `pkg/metrics.go` label sets and do not add metrics.
- **No credential is logged by code you write** — not the token, not its prefix, not its base64 header form, not a hash of it, not the PEM bytes. Do not add any log statement that contains any part of the minted token or the PEM, and do not attempt to silence the vendored library's own logging. (See the reviewer note in requirement 2: the vendored `githubapp.MintIAT` emits an 8-character token prefix at `glog.V(2)` and the deployed pod runs with `-v=2`, so that line is live — it is an upstream decision, not an executor action, and it must not block this work.)
- The App auth surface mints nothing today: `auth.ResolveGitHubClient` returns an authenticated `*http.Client` only. Minting is new code on top of the already-vendored `githubapp.MintIAT`, not a reuse of an existing call.
- `pkg/factory` stays pure composition: no I/O, no conditionals, `Create*` prefix, constructors return interfaces.
- Do NOT modify `mocks/*.go` by hand; counterfeiter fakes come from `//counterfeiter:generate` directives. Do NOT change the `TokenSource` interface or `TokenSourceOf` (previous prompt) — if something there seems wrong, stop and report it instead of editing it.
- Never use `fmt.Errorf`; all errors go through `github.com/bborbe/errors` and carry `ctx`.
- Every new `.go` file starts with the BSD license header block used by the existing files.
- Keep every line under 100 characters (`golines --max-len=100`), every function under 80 lines / 50 statements (`funlen`), and nesting under 4 (`nestif`).
- **Out of scope here: spec AC 10, the live private-repo clone proof on the dev cluster.** It is jointly owned with the octopus rollout task — the deployed image and the dev unit are that task's work, and the proof needs cluster credentials this container does not have. Do not attempt it, do not add a command that pretends to check it, and do not weaken anything to make it appear to pass. This prompt's evidence is the factory/auth tests above; the deployed-clone evidence belongs to the rollout task.
- Do NOT commit — dark-factory handles git.
- Existing tests must still pass.
</constraints>

<verification>
Run from the repo root. The first command is the binding evidence; the rest are targeted checks.

```
make precommit
```
Must exit 0.

```
go test -mod=mod ./pkg/auth/... ./pkg/factory/... -count=1
```
Must exit 0 (this repo does not commit `vendor/`, so `-mod=mod` is required).

The new specs actually ran (a focus-less pass could otherwise hide a typo'd `Describe`):

```
go test -mod=mod ./pkg/auth/... ./pkg/factory/... -count=1 -v -ginkgo.v 2>&1 | grep -cE 'NewTokenSource|threads the token source into the scanner'
```
Expect at least 1.

The App credential is actually wired (supporting context only — the factory test above is the binding evidence, since a grep is satisfiable by a comment):

```
grep -rn 'MintIAT' main.go pkg/ --include='*.go'
```
Expect at least one hit (in `pkg/auth/tokensource.go`).

The security rationale is on disk with both required literals:

```
test -f docs/security-model.md || { echo "FAIL: docs/security-model.md missing"; exit 1; }
test "$(grep -c 'HOME' docs/security-model.md)" -ge 1 || { echo "FAIL: gate allowlist not documented"; exit 1; }
grep -q '/proc/<pid>/environ' docs/security-model.md || { echo "FAIL: residual risk not documented"; exit 1; }
echo "OK: security model documented"
```

The credential mechanism stays confined to the scanner (no credential plumbing leaked into auth/factory/main, and no second conveyance invented):

```
for p in pkg/auth pkg/factory main.go; do test -e "$p" || { echo "FAIL: missing $p"; exit 1; }; done
for pattern in GIT_CONFIG x-access-token; do
  if grep -rn "$pattern" pkg/auth/ pkg/factory/ main.go 2>/dev/null; then
    echo "FAIL: $pattern found outside pkg/scanner.go"; exit 1
  fi
done
echo "OK: neither GIT_CONFIG nor x-access-token appears outside pkg/scanner.go"
```

The changelog section sits above the latest release:

```
test "$(grep -n '^## ' CHANGELOG.md | head -n1 | cut -d: -f2)" = "## Unreleased" || { echo "FAIL: top changelog section is not ## Unreleased"; exit 1; }
grep -c '^## Unreleased' CHANGELOG.md
```
The `test` must pass and `grep -c` must print exactly `1`.
</verification>
