---
status: completed
summary: Added a non2xxLoggingTransport that emits one credential-free structured glog V(2) line per non-2xx GitHub API response, installed in NewGitHubClient, with 25 Ginkgo specs covering restore, error, and sanitization paths plus a changelog entry.
execution_id: github-vuln-watcher-non2xx-log-exec-010-github-api-non2xx-response-logging
dark-factory-version: v0.198.7
created: "2026-10-31T13:18:09Z"
queued: "2026-10-31T14:44:24Z"
started: "2026-10-31T14:57:51Z"
completed: "2026-10-31T15:00:21Z"
---

# Log non-2xx GitHub API responses at the HTTP client boundary

<summary>
- Every GitHub API response with a status outside 200–299 now produces exactly one structured log line, so a rate limit or an auth failure is diagnosable from pod logs instead of only as a downstream symptom.
- The line is emitted at the HTTP transport boundary, so it covers every GitHub API call made through the watcher's API client (repo listing and file fetches) without any call site opting in; installation-token minting is not covered.
- The line carries the signals needed to tell primary-quota exhaustion from secondary rate limiting: the rate-limit resource, the remaining quota, and the retry-after value.
- A header or body the response does not carry is logged as the literal `absent`, so a missing value is distinguishable from an empty one.
- Only the first 4096 bytes of the response body are buffered for the snippet; the caller receives that prefix followed by the unread remainder, so it still sees the complete body and no existing behavior changes.
- A body read error is not swallowed: it re-surfaces on the caller's own read, after the prefix, and closing the restored body closes the original one.
- The snippet is collapsed to one line and capped, so a large or multi-line error payload cannot flood or break the log stream.
- Credentials never reach a log line: only the request method, host, and path are logged — never the full URL (which may carry userinfo or query tokens) and never a request header.
- Successful responses log nothing, so the change adds no noise on the healthy path.
- The line format is byte-identical to the same change in the sibling watcher repositories, so one log query works across the fleet.
- A changelog entry records the change under an Unreleased section.
</summary>

<objective>
Add one structured log line per non-2xx GitHub API response, emitted from a transport wrapper installed at the single point where this repository builds its GitHub API client, so rate limiting and auth failures are diagnosable from logs — and do it without ever emitting a credential and without changing what the caller receives.
</objective>

<context>
Read `docs/dod.md` (this repository's definition of done — it is wired as the dark-factory validation prompt).
Read `docs/security-model.md` — the invariant this change must not break: no log statement in the watcher emits the token, a prefix of it, its base64 header form, or a hash of it. The new log line is in scope of that rule.

Read these coding plugin docs before writing code (paths are inside the container):
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-testing-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-test-types-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-glog-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-linting-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/changelog-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/definition-of-done.md`

Read these repo files before writing code:
- `pkg/githubclient.go` — `NewGitHubClient` is the only production construction point of the GitHub API client; every GitHub API call (repo enumeration, `go.mod` fetch, `.maintainer.yaml` fetch) goes through the `*http.Client` it wraps.
- `pkg/factory/factory.go` — `CreateWatcher` calls `pkg.NewGitHubClient(githubHTTPClient)`; this is the only production call site of that constructor.
- `pkg/auth/auth.go` — `ResolveGitHubClient` builds the authenticated `*http.Client` (GitHub App installation token) and sets its `Timeout`. It performs I/O and is deliberately outside `pkg/factory`.
- `pkg/pkg_suite_test.go` — the single Ginkgo suite (`package pkg_test`, `func TestSuite`). Ginkgo specs declared in `package pkg` test files register into that same suite; there is precedent in `pkg/githubclient_export_test.go`, which is `package pkg`.
- `pkg/githubclient_test.go` — the existing `package pkg_test` style, `pkg.SetBaseURL` usage, and how an httptest server backs the client.

Scope note: git clone traffic is not a GitHub API call. It authenticates through `pkg/auth.NewTokenSource` and git's `GIT_CONFIG_*` environment interface (see `docs/security-model.md`), never through this `*http.Client`. It is out of scope for this prompt.
</context>

<requirements>
1. Create `pkg/non2xx_log.go` (package `pkg`) with exactly the content below. It is a reference implementation already reviewed in a sibling repository and must be reproduced verbatim — same identifiers, same comments, same formatting, same log format string. Do not rename fields, do not reorder them, do not change the prefix `github non-2xx`, and do not add or remove spaces in the format string.

```go
// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/golang/glog"
)

// non2xxBodyLimit is the maximum number of runes of the response body carried
// in a non-2xx log line; longer bodies are truncated and suffixed with "…".
const non2xxBodyLimit = 200

// non2xxAbsent is logged for a header (or body) the response does not carry,
// so a missing value is distinguishable from an empty one.
const non2xxAbsent = "absent"

// logNon2xxV2 is the production sink for non-2xx lines. The watchers run with
// -v=2, so a V(2) line is visible in pod logs.
func logNon2xxV2(line string) {
	glog.V(2).Info(line)
}

// non2xxPeekBytes bounds how much of a non-2xx body is buffered for the
// snippet: enough for non2xxBodyLimit runes of 4-byte UTF-8 plus whitespace.
const non2xxPeekBytes = 4096

// logNon2xxResponse emits one line for a response whose status is outside
// 200-299 — 3xx included, so a redirect hop or a 304 is logged too — carrying
// the signals needed to tell primary-quota exhaustion from secondary rate
// limiting. Nothing is emitted for a 2xx.
//
// Only the first non2xxPeekBytes of the body are read. The body handed back to
// the caller is that prefix followed by the unread remainder of the original
// body, so the caller sees the full body; a read error is not swallowed but
// re-surfaces on the caller's own read, after the prefix.
func logNon2xxResponse(req *http.Request, resp *http.Response, log func(string)) {
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return
	}
	var prefix []byte
	if resp.Body != nil {
		var readErr error
		prefix, readErr = io.ReadAll(io.LimitReader(resp.Body, non2xxPeekBytes))
		rest := io.Reader(resp.Body)
		if readErr != nil {
			rest = errReader{err: readErr}
		}
		resp.Body = peekedBody{
			Reader: io.MultiReader(bytes.NewReader(prefix), rest),
			Closer: resp.Body,
		}
	}
	log(non2xxLine(req, resp, prefix))
}

// peekedBody replays a buffered prefix before the rest of the original body
// and closes the original body.
type peekedBody struct {
	io.Reader
	io.Closer
}

// errReader returns err on every read.
type errReader struct {
	err error
}

func (r errReader) Read([]byte) (int, error) {
	return 0, r.err
}

// non2xxLine formats the non-2xx line. Only method, host and path of the
// request are logged — never the full URL (userinfo, query tokens) and never a
// request header.
func non2xxLine(req *http.Request, resp *http.Response, body []byte) string {
	method, host, path := non2xxAbsent, non2xxAbsent, non2xxAbsent
	if req != nil {
		method = req.Method
		if req.URL != nil {
			host = orAbsent(req.URL.Host)
			path = orAbsent(req.URL.Path)
		}
	}
	return fmt.Sprintf(
		"github non-2xx method=%s host=%s path=%s status=%d resource=%s remaining=%s retry_after=%s body=%s",
		method,
		host,
		path,
		resp.StatusCode,
		orAbsent(resp.Header.Get("X-RateLimit-Resource")),
		orAbsent(resp.Header.Get("X-RateLimit-Remaining")),
		orAbsent(resp.Header.Get("Retry-After")),
		bodySnippet(body),
	)
}

func orAbsent(v string) string {
	if v == "" {
		return non2xxAbsent
	}
	return v
}

// bodySnippet collapses whitespace so the line stays one line, and truncates
// to non2xxBodyLimit runes with a trailing "…".
func bodySnippet(body []byte) string {
	s := strings.Join(strings.Fields(string(body)), " ")
	if s == "" {
		return non2xxAbsent
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "?")
	}
	if utf8.RuneCountInString(s) <= non2xxBodyLimit {
		return s
	}
	runes := []rune(s)
	return string(runes[:non2xxBodyLimit]) + "…"
}
```

2. Append the transport wrapper to the end of `pkg/non2xx_log.go`, exactly as given:

```go
// non2xxLoggingTransport wraps an http.RoundTripper and logs one line per non-2xx response.
type non2xxLoggingTransport struct {
	inner http.RoundTripper
	log   func(string)
}

// RoundTrip delegates to the wrapped transport and logs the response when its
// status is outside 200-299. A transport error, or a nil response, is returned
// unchanged and produces no line.
func (t *non2xxLoggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.inner.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	if t.log != nil {
		logNon2xxResponse(req, resp, t.log)
	}
	return resp, err
}
```

3. Install the wrapper at the single construction point in `pkg/githubclient.go`. `NewGitHubClient` is where every GitHub API call in this repository enters the GitHub client, so the wrapper belongs there and nowhere else. Replace its body with:

```go
func NewGitHubClient(httpClient *http.Client) GitHubClient {
	inner := httpClient.Transport
	if inner == nil {
		inner = http.DefaultTransport
	}
	httpClient.Transport = &non2xxLoggingTransport{inner: inner, log: logNon2xxV2}
	return &githubClient{client: gogithub.NewClient(httpClient)}
}
```

   Extend the existing `NewGitHubClient` doc comment with one sentence stating that the client's transport is wrapped so every non-2xx GitHub API response is logged.

   Do NOT install the wrapper in `pkg/auth/auth.go` (`ResolveGitHubClient`) and do NOT install it in `pkg/factory/factory.go`. `ResolveGitHubClient` only produces the authenticated client; the single consumer is `NewGitHubClient`, so wrapping there would double-wrap as soon as a second consumer appears. `CreateWatcher` is pure composition and must stay that way.

   Do NOT wrap in `pkg/factory/factory_test.go`'s `&http.Client{}` — that test passes an empty client whose `Transport` is nil, which the new code handles via `http.DefaultTransport`.

4. Create `pkg/non2xx_log_test.go` in `package pkg` (internal test package — the transport type is unexported). Do not add a second `RunSpecs`/`TestSuite`: the existing suite in `pkg/pkg_suite_test.go` runs the specs registered by this file. Reproduce every case below; the transport is always constructed as `&non2xxLoggingTransport{inner: srv.Client().Transport, log: sink}` and always driven through a real `httptest` server, so the test exercises the real `http.RoundTripper` path rather than a hand-built `*http.Response`.

```go
// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("non-2xx response logging", func() {
	var (
		lines []string
		sink  func(string)
	)
	BeforeEach(func() {
		lines = nil
		sink = func(l string) { lines = append(lines, l) }
	})

	roundTrip := func(status int, headers map[string]string, body string) *http.Response {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			for k, v := range headers {
				w.Header().Set(k, v)
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}))
		DeferCleanup(srv.Close)
		tr := &non2xxLoggingTransport{inner: srv.Client().Transport, log: sink}
		req, err := http.NewRequest("GET", srv.URL+"/repos/o/r/pulls", nil)
		Expect(err).NotTo(HaveOccurred())
		resp, err := tr.RoundTrip(req)
		Expect(err).NotTo(HaveOccurred())
		return resp
	}

	DescribeTable("emit predicate",
		func(status int, wantLine bool) {
			roundTrip(status, nil, "x")
			if wantLine {
				Expect(lines).To(HaveLen(1))
				Expect(lines[0]).To(HavePrefix("github non-2xx "))
			} else {
				Expect(lines).To(BeEmpty())
			}
		},
		Entry("200 emits nothing", http.StatusOK, false),
		Entry("204 emits nothing", http.StatusNoContent, false),
		Entry("304 emits a line", http.StatusNotModified, true),
		Entry("403 emits a line", http.StatusForbidden, true),
		Entry("404 emits a line", http.StatusNotFound, true),
		Entry("429 emits a line", http.StatusTooManyRequests, true),
		Entry("500 emits a line", http.StatusInternalServerError, true),
	)

	It("carries all fields when the headers are present", func() {
		roundTrip(http.StatusTooManyRequests, map[string]string{
			"X-RateLimit-Resource":  "core",
			"X-RateLimit-Remaining": "0",
			"Retry-After":           "60",
		}, `{"message":"API rate limit exceeded"}`)
		Expect(lines).To(HaveLen(1))
		Expect(lines[0]).To(ContainSubstring("method=GET "))
		Expect(lines[0]).To(ContainSubstring(" path=/repos/o/r/pulls "))
		Expect(lines[0]).To(ContainSubstring(" status=429 "))
		Expect(lines[0]).To(ContainSubstring(" resource=core "))
		Expect(lines[0]).To(ContainSubstring(" remaining=0 "))
		Expect(lines[0]).To(ContainSubstring(" retry_after=60 "))
		Expect(lines[0]).To(HaveSuffix(` body={"message":"API rate limit exceeded"}`))
	})

	DescribeTable("logs the literal absent for a missing header",
		func(missing string, field string) {
			headers := map[string]string{
				"X-RateLimit-Resource":  "core",
				"X-RateLimit-Remaining": "10",
				"Retry-After":           "5",
			}
			delete(headers, missing)
			roundTrip(http.StatusForbidden, headers, "denied")
			Expect(lines).To(HaveLen(1))
			Expect(lines[0]).To(ContainSubstring(" " + field + "=absent "))
		},
		Entry("X-RateLimit-Resource", "X-RateLimit-Resource", "resource"),
		Entry("X-RateLimit-Remaining", "X-RateLimit-Remaining", "remaining"),
		Entry("Retry-After", "Retry-After", "retry_after"),
	)

	It("logs body=absent for an empty body", func() {
		roundTrip(http.StatusBadGateway, nil, "")
		Expect(lines).To(HaveLen(1))
		Expect(lines[0]).To(HaveSuffix(" body=absent"))
	})

	DescribeTable("truncates the body snippet",
		func(n int, wantEllipsis bool) {
			roundTrip(http.StatusInternalServerError, nil, strings.Repeat("a", n))
			Expect(lines).To(HaveLen(1))
			snippet := lines[0][strings.Index(lines[0], " body=")+len(" body="):]
			if wantEllipsis {
				Expect(snippet).To(Equal(strings.Repeat("a", 200) + "…"))
			} else {
				Expect(snippet).To(Equal(strings.Repeat("a", n)))
			}
		},
		Entry("200 chars kept whole", 200, false),
		Entry("201 chars truncated", 201, true),
	)

	It("keeps the line on one line for a multi-line body", func() {
		roundTrip(http.StatusInternalServerError, nil, "line one\nline two\r\n\tline three")
		Expect(lines).To(HaveLen(1))
		Expect(lines[0]).NotTo(ContainSubstring("\n"))
		Expect(lines[0]).To(HaveSuffix(" body=line one line two line three"))
	})

	It("restores the response body for the caller", func() {
		resp := roundTrip(http.StatusNotFound, nil, `{"message":"Not Found"}`)
		read, err := io.ReadAll(resp.Body)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(read)).To(Equal(`{"message":"Not Found"}`))
	})

	It("never logs credentials from the request", func() {
		const sentinel = "ghs_SENTINELtoken123"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		DeferCleanup(srv.Close)
		tr := &non2xxLoggingTransport{inner: srv.Client().Transport, log: sink}
		u := strings.Replace(srv.URL, "http://", "http://x-access-token:"+sentinel+"@", 1)
		req, err := http.NewRequest("GET", u+"/repos/o/r?access_token="+sentinel, nil)
		Expect(err).NotTo(HaveOccurred())
		req.Header.Set("Authorization", "Bearer "+sentinel)
		_, err = tr.RoundTrip(req)
		Expect(err).NotTo(HaveOccurred())
		Expect(lines).To(HaveLen(1))
		Expect(lines[0]).NotTo(ContainSubstring("SENTINEL"))
		Expect(lines[0]).NotTo(ContainSubstring("Bearer"))
		Expect(lines[0]).NotTo(ContainSubstring("access_token"))
	})

	It("restores a body larger than the peek window in full", func() {
		big := strings.Repeat("x", non2xxPeekBytes*3+7)
		resp := roundTrip(http.StatusInternalServerError, nil, big)
		read, err := io.ReadAll(resp.Body)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(read)).To(Equal(big))
		Expect(lines).To(HaveLen(1))
		Expect(lines[0]).To(HaveSuffix(" body=" + strings.Repeat("x", 200) + "…"))
	})

	It("re-surfaces a body read error to the caller instead of swallowing it", func() {
		readErr := errors.New("connection reset mid-body")
		resp := &http.Response{
			StatusCode: http.StatusBadGateway,
			Header:     http.Header{},
			Body: io.NopCloser(
				io.MultiReader(strings.NewReader("partial"), errReader{err: readErr}),
			),
		}
		logNon2xxResponse(newNon2xxRequest(), resp, sink)
		Expect(lines).To(HaveLen(1))
		Expect(lines[0]).To(HaveSuffix(" body=partial"))
		read, err := io.ReadAll(resp.Body)
		Expect(string(read)).To(Equal("partial"))
		Expect(err).To(MatchError(readErr))
	})

	It("closes the original body when the caller closes the restored one", func() {
		closed := false
		resp := &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     http.Header{},
			Body:       closeSpy{Reader: strings.NewReader("nf"), closed: &closed},
		}
		logNon2xxResponse(newNon2xxRequest(), resp, sink)
		Expect(resp.Body.Close()).To(Succeed())
		Expect(closed).To(BeTrue())
	})

	It("logs body=absent when the response has no body", func() {
		logNon2xxResponse(
			newNon2xxRequest(),
			&http.Response{StatusCode: http.StatusNotModified, Header: http.Header{}},
			sink,
		)
		Expect(lines).To(HaveLen(1))
		Expect(
			lines[0],
		).To(HaveSuffix(" status=304 resource=absent remaining=absent retry_after=absent body=absent"))
	})

	It("logs absent for a nil request and for a request without a URL", func() {
		resp := &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{}}
		Expect(
			non2xxLine(nil, resp, nil),
		).To(HavePrefix("github non-2xx method=absent host=absent path=absent status=403 "))
		Expect(
			non2xxLine(&http.Request{Method: "GET"}, resp, nil),
		).To(HavePrefix("github non-2xx method=GET host=absent path=absent status=403 "))
	})

	It("replaces invalid UTF-8 in the body snippet", func() {
		resp := &http.Response{StatusCode: http.StatusInternalServerError, Header: http.Header{}}
		Expect(non2xxLine(nil, resp, []byte{'o', 'k', 0xff, 0xfe})).To(HaveSuffix(" body=ok?"))
	})

	It("emits nothing when log is nil", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		DeferCleanup(srv.Close)
		tr := &non2xxLoggingTransport{inner: srv.Client().Transport}
		req, err := http.NewRequest("GET", srv.URL, nil)
		Expect(err).NotTo(HaveOccurred())
		_, err = tr.RoundTrip(req)
		Expect(err).NotTo(HaveOccurred())
		Expect(lines).To(BeEmpty())
	})

	It("passes a transport error through without logging", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		target := srv.URL
		srv.Close()
		tr := &non2xxLoggingTransport{inner: srv.Client().Transport, log: sink}
		req, err := http.NewRequest("GET", target, nil)
		Expect(err).NotTo(HaveOccurred())
		resp, err := tr.RoundTrip(req)
		Expect(err).To(HaveOccurred())
		Expect(resp).To(BeNil())
		Expect(lines).To(BeEmpty())
	})
})

func newNon2xxRequest() *http.Request {
	req, err := http.NewRequest("GET", "https://api.github.com/repos/o/r", nil)
	Expect(err).NotTo(HaveOccurred())
	return req
}

// closeSpy records whether Close was called.
type closeSpy struct {
	io.Reader
	closed *bool
}

func (c closeSpy) Close() error {
	*c.closed = true
	return nil
}
```

   The last case ("passes a transport error through") covers the wrapper's error branch, which the reference implementation did not have; every other case is the reference case set plus the six restore/error specs (large body restored in full, read error re-surfaced, original body closed, nil body → `body=absent`, nil request / request without URL → `absent`, invalid UTF-8 → `?`).

5. Add the changelog entry to `CHANGELOG.md`. Insert a new section directly above the first `## v` heading (currently `## v0.3.6`), keeping the blank-line spacing of the existing sections:

```markdown
## Unreleased

- feat: log one structured line per non-2xx GitHub API response at the HTTP client boundary — method, host, path, status, rate-limit resource, remaining quota, retry-after and a truncated body snippet, with `absent` for a missing header or body; never the full URL or a request header, and the response body is restored for the caller
```

   Do not touch any existing released section, and do not add a version heading.

6. Self-check before finishing: re-run `<verification>` and confirm it passes; then walk each bullet of `<summary>` against the change and confirm each one is true of the code you wrote.
</requirements>

<constraints>
- Do NOT commit — dark-factory handles git.
- Existing tests must still pass.
- Stay on `github.com/golang/glog`. Do not introduce `log/slog`, `logr`, or any new logging dependency.
- Never log `req.URL.String()`, a request header, a query string, or userinfo. Only `req.Method`, `req.URL.Host`, and `req.URL.Path` may reach a log line — this is the `docs/security-model.md` invariant that no log statement emits the token or any form of it.
- Only the response headers `X-RateLimit-Resource`, `X-RateLimit-Remaining`, and `Retry-After` may be read; nothing else from the response is logged.
- The log line must keep the exact prefix `github non-2xx` and the exact field order `method= host= path= status= resource= remaining= retry_after= body=` — the format is shared with the sibling watcher repositories.
- Always restore `resp.Body` as `peekedBody{Reader: io.MultiReader(bytes.NewReader(prefix), rest), Closer: original}` so the caller sees the complete body and closing it closes the original; a 2xx response must produce no line at all.
- Emit at `glog.V(2)` only. Do not add a metric, a config flag, or a tunable threshold — this change is the log line and nothing else.
- Do not modify `pkg/auth/auth.go`, `pkg/factory/factory.go`, or `pkg/githubclient_test.go`.
- Do not touch git clone traffic, `pkg/auth.NewTokenSource`, or the gate environment — out of scope for this change.
- Do not edit generated files (`mocks/` is regenerated by `make precommit`'s `generate` target).
</constraints>

<verification>
Run from the repo root:

```
make precommit
```

Must exit 0. Then confirm the new specs actually ran — a spec that never runs cannot fail, so `make precommit` alone does not prove this file was exercised. Focus the suite on the new specs and require Ginkgo's summary line to report at least 25 executed specs (the case set below is 25 specs):

```
go test -mod=mod ./pkg/ -run TestSuite -v -args --ginkgo.focus="non-2xx response logging" 2>&1 \
  | grep -ao 'Ran [0-9]* of' \
  | awk '{ if ($2 >= 25) ok=1 } END { exit !ok }'
```

Then each of these must succeed:

```
! grep -q 'slog' pkg/non2xx_log.go
! grep -q 'URL.String()' pkg/non2xx_log.go
grep -q 'github non-2xx method=%s host=%s path=%s status=%d resource=%s remaining=%s retry_after=%s body=%s' pkg/non2xx_log.go
grep -q 'non2xxLoggingTransport{inner: inner, log: logNon2xxV2}' pkg/githubclient.go
```
</verification>
