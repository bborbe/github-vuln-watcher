---
status: completed
summary: Added header-aware rate-limit retry and an inflight concurrency bound to the GitHub client, threaded a configurable API base URL through main/factory, and logged poll-cycle starts
execution_id: github-vuln-watcher-exec-010-retry-backoff-roundtripper
dark-factory-version: v0.198.17
created: "2026-11-25T02:44:53Z"
queued: "2026-11-25T02:44:53Z"
started: "2026-11-25T02:45:03Z"
completed: "2026-11-25T02:48:00Z"
---

# Retry GitHub rate-limit responses and bound concurrent requests

<summary>
- A GitHub rate-limit response is retried with a bounded, header-aware wait instead of failing the request
- A wait longer than five minutes is deferred to the next poll cycle rather than slept
- Concurrent GitHub requests are capped at a named bound
- The API base URL becomes an argument-struct field, so the existing test seam is reachable in production
- The poll cycle logs one line at start, so a cycle rate can be counted before and after the change
- Every other behaviour is unchanged
</summary>

<objective>
Stop a rate limit from ending the watcher's work. Today a 429 or a primary-quota 403 surfaces as `ErrRateLimited` and aborts the cycle; the next tick retries from scratch, so a long window silently does nothing. Retrying inside the client, with the server's own delay, keeps the cycle alive — and bounding concurrency stops a retry from making a secondary limit worse.
</objective>

<context>
Read `CLAUDE.md` for project conventions and `docs/dod.md` for the Definition of Done.

Read these files before writing anything:
- `pkg/githubclient.go` — `NewGitHubClient` (today a bare `gogithub.NewClient(httpClient)` with no transport wrapper of its own), and `ErrRateLimited` / `wrapRateLimitErr` (the current fail-fast path).
- `pkg/auth/auth.go` — `Credentials` (already carries `BaseURL`) and the `githubapp.Config` it builds.
- `main.go` — the argument struct, the `factory.CreateWatcher` call, and the poll loop where `poll cycle skipped` is logged.
- `pkg/factory/factory.go` — `CreateWatcher` is the **only** production caller of `pkg.NewGitHubClient` (~line 79); `main.go` is the only caller of `CreateWatcher`. There is no `NewGitHubClient` call in `main.go`.
- `pkg/githubclient_test.go` and the suite file — the Ginkgo/Gomega style.

The library this uses is already released: `github.com/bborbe/http v1.28.0`, which ships `NewRoundTripperRetryWithBackoff` (honours `Retry-After` then `X-RateLimit-Reset`, defers a wait over five minutes as `retry deferred wait=<d>`, emits `retry attempt=<n> status=<403|429> class=<…> wait=<…>` and `retry exhausted status=<code> retries=<n>`) and `NewRoundTripperLimitConcurrency` (logs `inflight_bound=<n>` once at construction). Read their source under `$(go env GOMODCACHE)/github.com/bborbe/http@v1.28.0/` before wiring.
</context>

<requirements>
1a. Bump `GOLANGCI_LINT_VERSION` in `tools.env` from `v2.13.1` to `v2.14.0`, matching the sibling watcher repos. v2.13.1 cannot read Go 1.27 export data (`export data version 5 is greater than maximum supported version 4`), so `make precommit`'s lint target fails for a tooling reason before any code is judged.

1. Bump `github.com/bborbe/http` to `v1.28.0` (`go get github.com/bborbe/http@v1.28.0 && go mod tidy`). That release's `go.mod` declares `go 1.27.4`, above this repo's `go 1.27.1`, so the `go get` raises this repo's `go` directive. In the same change update **both** `FROM ${DOCKER_REGISTRY}/golang:1.27.1` stages in `Dockerfile` (build and toolchain) to `1.27.4` — the builder tag must match the `go` directive, or the image build silently depends on a GOTOOLCHAIN auto-download inside the builder.

2. In `pkg/githubclient.go`, add a named constant `githubAPIInflightBound = 4` with a doc comment explaining that GitHub's secondary limit is a concurrency heuristic.

3. In `NewGitHubClient`, wrap the transport as **retry → limit → network** (outermost first). This repo has **no** transport wrapper today (`NewGitHubClient` is just `gogithub.NewClient(httpClient)`), so there is no capture stage to preserve — do not invent one. Take `inner := httpClient.Transport` (falling back to `http.DefaultTransport` when nil), wrap it with `libhttp.NewRoundTripperLimitConcurrency(inner, githubAPIInflightBound, nil)`, then wrap that with `libhttp.NewRoundTripperRetryWithBackoff(..., RetryBackoffOptions{RetryHosts: retryHosts})`, and assign the result to `httpClient.Transport` **before** calling `gogithub.NewClient(httpClient)` — `NewClient` copies the `http.Client` struct, so a later assignment is silently ignored. Alias the import (`libhttp "github.com/bborbe/http"`) because this file already imports `net/http`. A retry must re-acquire a slot, not hold one across the wait.

   **`RetryHosts` is not optional here.** The library gates retries on `req.URL.Hostname()` and defaults `RetryHosts` to `[]string{"api.github.com"}`. Set `retryHosts = nil` when `apiBaseURL` is empty (the default applies), and `[]string{<parsed base URL>.Hostname()}` when it is set — otherwise a client pointed at a test server or a GitHub Enterprise host silently never retries, and the retry test below cannot pass.

4. Give `NewGitHubClient` an `apiBaseURL string` parameter and, after `gogithub.NewClient(httpClient)`, apply it to the go-github client's `BaseURL` when non-empty — parse it, ensure a trailing slash on the path, and log a warning and keep the default when it does not parse. Extract that into a small `applyAPIBaseURL` helper so the constructor stays under the linter's complexity limits. Parse the URL **once** in `NewGitHubClient` and derive both `retryHosts` (requirement 3) and the go-github `BaseURL` from that single parse: when parsing fails, keep `retryHosts = nil` too, so a malformed URL leaves both the default base URL and the default retry host (`api.github.com`) in place.

5. In `main.go`, add `APIBaseURL string` to the argument struct with `arg:"api-base-url" env:"GITHUB_API_BASE_URL"`, pass it into `auth.Credentials.BaseURL` (the field already exists as a test seam — this makes it reachable in production), and pass it to `factory.CreateWatcher` as a new `apiBaseURL string` parameter. Do not read it with `os.Getenv` — this repo threads configuration through the argument struct.

5a. In `pkg/factory/factory.go`, add `apiBaseURL string` as the **second** parameter of `CreateWatcher` (immediately after `githubHTTPClient`) and change its `pkg.NewGitHubClient(githubHTTPClient)` call (~line 79) to `pkg.NewGitHubClient(githubHTTPClient, apiBaseURL)`. Insert the argument in the same position in `main.go`'s `CreateWatcher` call and in `pkg/factory/factory_test.go`'s call. **Position matters:** `main_test.go` asserts `CreateWatcher\(.*?tokenSource,\s*\)`, so anything appended after `tokenSource` breaks those specs. **Do not add a `NewGitHubClient` call to `main.go`** — there is none today.

6. In `pollLoop`'s `poll` closure, add one line immediately after `gate.TryAcquire()` succeeds (a skipped cycle keeps logging only `poll cycle skipped`):
   ```go
   glog.V(2).Infof("poll cycle start stage=%s", a.Stage)
   ```
   It must be visible at `-v=2`, which is what the deployed StatefulSets run.

7. Add tests in `pkg/githubclient_chain_test.go` (`package pkg_test`, Ginkgo/Gomega):
   - a 429 with `Retry-After: 0` followed by a 200 drives exactly **two** calls through the transport — build the client with `pkg.NewGitHubClient(server.Client(), server.URL+"/")` and issue a real API call, so the request host is the test server and `RetryHosts` includes it. Do **not** construct the round-tripper directly in the test: that would leave the production wiring untested
   - an API call issued through a client built with `apiBaseURL` set to `http://stub.invalid/` reaches host `stub.invalid` — `stub.invalid` does not resolve, so pass an `&http.Client{Transport: <recorder>}` whose transport records `req.URL.Host` and returns a canned 200, and assert the recorded host
   - an unparsable `apiBaseURL` (e.g. `"://bad"`) logs the warning and keeps the default base URL — same recording transport, assert the recorded host is `api.github.com`

8. Update any existing test call site for the new `NewGitHubClient` signature (pass `""`).

9. Add a `## Unreleased` entry to `CHANGELOG.md` (prefix `fix:`) and add `export GITHUB_API_BASE_URL=` to `example.env` (CLAUDE.md points at it as the env-var reference).

10. Run `make precommit` and confirm it passes; walk each numbered requirement against the change.
</requirements>

<constraints>
- Do NOT commit — dark-factory handles git.
- Existing tests must still pass.
- All paths are repo-relative; no absolute or home-relative paths.
- Use Ginkgo/Gomega for tests.
- Wrap errors with `github.com/bborbe/errors`.
- Do not add a `//nolint` without an explanation on the same line.
- Do not run `go mod vendor`.
</constraints>

<verification>
Run `make precommit` — must pass.
</verification>
