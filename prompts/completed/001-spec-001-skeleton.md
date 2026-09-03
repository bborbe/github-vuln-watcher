---
status: completed
spec: ["001"]
summary: 'Reworked the scaffold binary into the vuln-drift watcher service shell: full env config surface, single-cycle poll loop (immediate first cycle, 12h default/24h ceiling), POST /trigger endpoint with CycleGate single-writer lock, four-counter Prometheus metrics scaffold, and consolidated CreateRouter route table with BoltDB/DATADIR/BATCH_SIZE removed'
execution_id: github-vuln-watcher-vuln-drift-watcher-exec-001-spec-001-skeleton
dark-factory-version: dev
created: "2026-09-03T20:30:00Z"
queued: "2026-09-03T18:43:31Z"
started: "2026-09-03T18:43:33Z"
completed: "2026-09-03T18:49:28Z"
---

<summary>
- The binary's configuration moves to a full environment surface: which GitHub owner to watch, which deployment stage to stamp on emitted tasks, the repo scope allowlist, the poll cadence, the cursor file location, the Kafka topic prefix, and the GitHub App credentials.
- The on-disk key-value store and its admin endpoints are gone; the service's persistent memory becomes a single JSON cursor file with a working default path (`/data/cursor.json`).
- One scan cycle fires immediately at startup, then on a fixed interval that defaults to 12h and is hard-capped at 24h — the latency ceiling the spec guarantees.
- Exactly one scan runs at a time, whether started by the timer or by the operator, so the cursor file always has a single writer.
- An operator can force a scan via `POST /trigger`; a forced scan while one is already running is refused with 409 rather than queued, so a burst of triggers cannot pile up.
- The four core Prometheus counters (cycle outcomes, publishes, filtered-skip reasons, repos scanned) exist with every documented label pre-initialised to zero, so the metrics endpoint is complete before the first cycle.
- The HTTP surface keeps the existing health/readiness/log-level/GC/sentry endpoints and drops the key-value-store endpoints; `/trigger` is added.
- The service compiles and passes `make precommit` with the BoltDB dependency removed.
</summary>

<objective>
Rework the scaffold binary into the vuln-drift watcher's service shell: the full env/config surface, the single-cycle poll loop (immediate first cycle + interval, capped at 24h), the forced-cycle `/trigger` endpoint, the four-counter Prometheus metrics scaffold, and the consolidated HTTP route table. This is the skeleton every later layer plugs into.
</objective>

<context>
Read `docs/dod.md` for the Definition of Done and `CHANGELOG.md` for the changelog format.

Read these coding plugin docs before writing code (paths are inside the container):
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-patterns.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-factory-pattern.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-concurrency-patterns.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-prometheus-metrics-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-error-wrapping-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-testing-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-doc-best-practices.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-http-service-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/changelog-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/definition-of-done.md`

Read these repo files before writing code:
- `main.go` — the current scaffold `application` struct, `Run`, and `createHTTPServer`. This prompt rewrites all of them.
- `pkg/factory/factory.go` — currently has `CreateTestLoglevelHandler`, `CreateSentryAlertHandler`, `CreateHealthzHandler`. Keep all three; add to this file.
- `pkg/handler/healthz.go`, `pkg/handler/test-loglevel.go`, `pkg/handler/sentry-alert.go`, `pkg/handler/handler_suite_test.go` — existing; leave them.
- `pkg/pkg_suite_test.go` — the Ginkgo suite for `package pkg_test`, with the counterfeiter `//go:generate` directive. Do NOT add a second suite file to `pkg/`.
- `Makefile` — the `run` target passes `-datadir="data"` and `-batch-size="100"`, both of which this prompt removes from the binary.
- `example.env`, `.golangci.yml` (funlen caps functions at 80 lines / 50 statements), `Makefile.precommit` (`precommit: ensure format generate test check addlicense`; `format` runs `golines --max-len=100`, so keep lines under 100 chars).

**Sibling entry-point check (already run):** this repo has exactly one binary entry point — `main.go` at the repo root. There is no `cmd/` directory and no second `application.Run`. Run `grep -rn "factory.Create" --include=*.go .` and `grep -rn "func (.*) Run(ctx" --include=*.go .` before you start; if either surfaces a call site outside `main.go`, update it in this prompt too.

Library API facts (verified against the module cache — do not re-derive from memory):
- `github.com/bborbe/service` — `service.Main(ctx, app, &app.SentryDSN, &app.SentryProxy)`; `service.Run(ctx context.Context, funcs ...run.Func) error` (cancel-on-first-finish across all funcs).
- `github.com/bborbe/run` — `type Func func(context.Context) error` with method `Run(ctx context.Context) error`; `run.NewBackgroundRunner(ctx) BackgroundRunner`; `run.CatchPanic(fn Func) Func`.
- `github.com/bborbe/http` (import `libhttp`) — `libhttp.NewPrintHandler(format string, a ...any) http.Handler`; `libhttp.NewServer(addr string, router http.Handler, optionFns ...func(*ServerOptions)) run.Func` (invoke `.Run(ctx)`); `libhttp.NewGarbageCollectorHandler()`.
- `github.com/bborbe/log` — `log.NewSetLoglevelHandler(ctx, log.NewLogLevelSetter(2, 5*time.Minute))`.
- `github.com/bborbe/metrics` (import `libmetrics`) — `libmetrics.NewBuildInfoMetrics().SetBuildInfo(version, commit, buildDate)`.
- `github.com/bborbe/time` (import `libtime`) — `*libtime.DateTime` is the type already bound to `BUILD_DATE` in the scaffold.
- `github.com/bborbe/cqrs/base` — `type TopicPrefix string`. Used only as the type of the `TOPIC_PREFIX` config field in this prompt; the Kafka wiring that consumes it arrives in a later prompt.
- `github.com/prometheus/client_golang/prometheus` — `prometheus.NewCounterVec(prometheus.CounterOpts{...}, []string{...})`, `prometheus.NewCounter(prometheus.CounterOpts{...})`, `prometheus.Registerer.MustRegister(...)`, `prometheus.DefaultRegisterer`, `prometheus.NewRegistry()` for tests.
- The poll interval is bound as a `string` and parsed with `time.ParseDuration`. Do NOT declare the field as `time.Duration` — the argument binder cannot unmarshal it.
</context>

<requirements>

### 1. go.mod: drop the key-value store, add cqrs

Run `go get github.com/bborbe/cqrs@v0.6.10` then `go mod tidy` (tidy also runs as part of `make precommit`'s `ensure` target). After this prompt removes the `boltkv`/`kv` imports from `main.go` (step 5), `go mod tidy` drops `github.com/bborbe/boltkv` and `github.com/bborbe/kv` from `go.mod`. Confirm `go.mod` no longer requires `github.com/bborbe/boltkv` or `github.com/bborbe/kv` after `make precommit`.

### 2. `pkg/metrics.go` — the four core counters, injected registerer

Package `pkg`. The metric namespace is `github_vuln_watcher` (matches the binary name).

```go
//counterfeiter:generate -o ../mocks/metrics.go --fake-name Metrics . Metrics

// Metrics is the observable counters required of the watcher.
type Metrics interface {
	// IncPollCycle — result: "success" | "rate_limited" | "github_error" | "scan_error"
	IncPollCycle(result string)

	// IncPublished — status: "create" | "error"
	IncPublished(status string)

	// IncReposScanned adds n repos scanned in one cycle (no labels).
	IncReposScanned(n int)

	// IncFilterSkipped — reason: "scope" | "auto_update_disabled" |
	// "no_gomod" | "clone_failed" | "gate_timeout" | "scan_failed" |
	// "already_clean" | "finding_set_unchanged"
	IncFilterSkipped(reason string)
}

const metricNamespace = "github_vuln_watcher"

// PollCycleResults, PublishStatuses and FilterSkipReasons are the closed label
// sets. They are exported so tests stay in lockstep with the pre-initialisation
// loop below.
var (
	PollCycleResults = []string{
		"success",
		"rate_limited",
		"github_error",
		"scan_error",
	}
	PublishStatuses = []string{"create", "error"}
	FilterSkipReasons = []string{
		"scope",
		"auto_update_disabled",
		"no_gomod",
		"clone_failed",
		"gate_timeout",
		"scan_failed",
		"already_clean",
		"finding_set_unchanged",
	}
)

// NewMetrics returns the Prometheus-backed Metrics registered against the
// supplied Registerer. Pass nil for prometheus.DefaultRegisterer. Every label
// value is pre-initialised to 0 so /metrics exposes the full series set before
// the first cycle runs.
//
// Registration goes through the injected Registerer — never a package-level
// init() and never prometheus.MustRegister directly.
func NewMetrics(registerer prometheus.Registerer) Metrics
```

The label sets above are the FULL frozen sets for this service (they include reasons that later prompts' stages produce: `clone_failed`, `gate_timeout`, `scan_failed`, `already_clean`, `finding_set_unchanged`). Pre-initialise every label combination to 0 at construction, exactly like the loop below (repeated for each of the three label slices, plus a plain counter for `repos_scanned_total`):

```go
	for _, label := range PollCycleResults {
		m.pollCycle.WithLabelValues(label).Add(0)
	}
```

Metric names after namespace prefixing: `github_vuln_watcher_poll_cycle_total{result}`, `github_vuln_watcher_published_total{status}`, `github_vuln_watcher_repos_scanned_total`, `github_vuln_watcher_filter_skipped_total{reason}`. Implement the `metricsImpl` struct with unexported `*prometheus.CounterVec` / `prometheus.Counter` fields and the four `Inc*` methods.

`pkg/metrics_test.go` (`package pkg_test`):
- `NewMetrics(prometheus.NewRegistry())` then `registry.Gather()` yields all four metric families.
- Every label value in `PollCycleResults`, `PublishStatuses` and `FilterSkipReasons` is present at value 0 before any `Inc*` call.
- `IncFilterSkipped("scope")` moves that series to 1 and leaves the other seven skip-reason series at 0.
- `IncPollCycle("success")` moves that series to 1.
- Two `NewMetrics` calls against two distinct `prometheus.NewRegistry()` instances both succeed (proves no package-level registration).

### 3. `pkg/cyclegate.go` — single-cycle lock

Package `pkg`. This is the mechanism that guarantees the cursor file has exactly one writer, shared by the interval loop and the `/trigger` endpoint.

```go
//counterfeiter:generate -o ../mocks/cycle_gate.go --fake-name CycleGate . CycleGate

// CycleGate enforces "exactly one poll cycle at a time" across the interval
// loop and the forced-cycle HTTP endpoint. It is non-blocking by design: a
// caller that cannot acquire the slot backs off instead of queueing, so a
// burst of forced-cycle requests cannot pile up behind a slow cycle.
type CycleGate interface {
	// TryAcquire reports whether the caller now holds the single cycle slot.
	// A caller that receives true MUST call Release when its cycle finishes.
	TryAcquire() bool
	// Release frees the slot. Calling Release without holding it is a no-op.
	Release()
}

// NewCycleGate returns a CycleGate backed by a capacity-1 channel.
func NewCycleGate() CycleGate {
	return &cycleGate{slot: make(chan struct{}, 1)}
}

type cycleGate struct {
	slot chan struct{}
}

func (g *cycleGate) TryAcquire() bool {
	select {
	case g.slot <- struct{}{}:
		return true
	default:
		return false
	}
}

func (g *cycleGate) Release() {
	select {
	case <-g.slot:
	default:
	}
}
```

`pkg/cyclegate_test.go` (`package pkg_test`): first `TryAcquire` true; second false; after `Release` the next `TryAcquire` is true again; `Release` without holding is a no-op and does not panic; two goroutines racing `TryAcquire` yield exactly one winner (run with a `sync.WaitGroup` and an atomic counter).

### 4. `pkg/watcher.go` — the skeleton Watcher

Package `pkg`. This defines the cycle entry point that the poll loop, the `/trigger` handler and every later prompt share. The `Poll` body in this prompt is the Skeleton cycle: it counts the success outcome and logs the cycle-complete line. The inventory, signal, emit and dedup stages are layered in by the remaining prompts of this spec — the success accounting and the cycle-complete log line are the contract every later layer preserves.

```go
//counterfeiter:generate -o ../mocks/watcher.go --fake-name Watcher . Watcher

// Watcher scans one GitHub owner for repos with vulnerable dependencies and
// publishes one CreateTaskCommand per qualifying repo.
type Watcher interface {
	// Poll runs one scan cycle. Safe to call repeatedly on an interval.
	//
	// force=true omits the finding-set dedup filter from this cycle (spec DB
	// 5), so an unchanged finding set is re-emitted. Every other gate still
	// applies. The interval loop always passes false; only /trigger passes
	// true.
	Poll(ctx context.Context, force bool) error
}

// NewWatcher wires the cycle's collaborators. This prompt's skeleton wires
// only metrics, cursor path and owner; the remaining spec layers add the
// GitHub inventory client, the scan stage, the publisher and the filter chain.
func NewWatcher(
	metrics Metrics,
	cursorPath string,
	owner string,
) Watcher {
	return &watcher{
		metrics:    metrics,
		cursorPath: cursorPath,
		owner:      owner,
	}
}

type watcher struct {
	metrics    Metrics
	cursorPath string
	owner      string
}

func (w *watcher) Poll(ctx context.Context, force bool) error {
	// Skeleton cycle: the scan stages are added by the remaining spec layers.
	w.metrics.IncPollCycle("success")
	glog.V(2).Infof("poll cycle complete result=success")
	return nil
}
```

`pkg/watcher_test.go` (`package pkg_test`): `NewWatcher(pkg.NewMetrics(prometheus.NewRegistry()), "/tmp/cursor.json", "bborbe")` — one `Poll` increments `github_vuln_watcher_poll_cycle_total{result="success"}` to exactly 1; a second `Poll` increments it to 2.

### 5. `pkg/handler/trigger_handler.go` — forced cycle

Package `handler`. Mirror this shape exactly:

```go
//counterfeiter:generate -o ../../mocks/trigger_handler.go --fake-name TriggerHandler . TriggerHandler

// TriggerHandler handles POST /trigger.
//
// It runs the forced cycle IN-PROCESS: the request acquires the single-cycle
// slot, hands the cycle to a run.BackgroundRunner bound to the application's
// long-lived context, and returns 202 immediately.
//
// Security: the handler reads ONLY the optional ?force=<bool> query parameter.
// It takes no owner, repo or scope parameter, so a forced cycle can only
// re-examine repos that already pass the allowlist and the per-repo opt-in
// gate. Unknown query parameters are ignored.
type TriggerHandler interface {
	ServeHTTP(ctx context.Context, resp http.ResponseWriter, req *http.Request) error
}

type httpAdapter struct {
	h TriggerHandler
}

func (a *httpAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := a.h.ServeHTTP(r.Context(), w, r); err != nil {
		glog.Warningf("trigger handler error: %v", err)
	}
}

// NewTriggerHandler returns the forced-cycle handler. baseCtx is the
// application's long-lived context: the background cycle must NOT run under
// the request context, which is cancelled the moment the 202 is written.
func NewTriggerHandler(
	baseCtx context.Context,
	watcher pkg.Watcher,
	gate pkg.CycleGate,
) TriggerHandler {
	return &triggerHandler{
		runner:  run.NewBackgroundRunner(baseCtx),
		watcher: watcher,
		gate:    gate,
	}
}

// NewTriggerHandlerHTTPAdapter wraps a TriggerHandler in an http.Handler
// suitable for registration with gorilla/mux.
func NewTriggerHandlerHTTPAdapter(
	baseCtx context.Context,
	watcher pkg.Watcher,
	gate pkg.CycleGate,
) http.Handler {
	return &httpAdapter{NewTriggerHandler(baseCtx, watcher, gate)}
}

type triggerHandler struct {
	runner  run.BackgroundRunner
	watcher pkg.Watcher
	gate    pkg.CycleGate
}
```

`ServeHTTP(ctx context.Context, resp http.ResponseWriter, req *http.Request) error`:

1. `forceStr := req.URL.Query().Get("force")`; `force := forceStr == "true" || forceStr == "1"`.
2. If `!h.gate.TryAcquire()`, log `glog.Warningf("trigger rejected: a poll cycle is already running")` and return HTTP 409 with a JSON body `{"status":"conflict","error":"a poll cycle is already running"}`.
3. Otherwise start the cycle and return 202:
   ```go
   if err := h.runner.Run(run.CatchPanic(func(ctx context.Context) error {
       defer h.gate.Release()
       if err := h.watcher.Poll(ctx, force); err != nil {
           return errors.Wrapf(ctx, err, "forced poll cycle failed force=%t", force)
       }
       return nil
   })); err != nil {
       h.gate.Release()
       glog.Errorf("failed to start forced poll cycle force=%t err=%v", force, err)
       resp.Header().Set("Content-Type", "application/json")
       resp.WriteHeader(http.StatusInternalServerError)
       return json.NewEncoder(resp).Encode(map[string]interface{}{
           "status": "error",
           "error":  "failed to start poll cycle",
       })
   }
   glog.Warningf("forced poll cycle accepted force=%t", force)
   resp.Header().Set("Content-Type", "application/json")
   resp.WriteHeader(http.StatusAccepted)
   return json.NewEncoder(resp).Encode(map[string]interface{}{
       "status": "accepted",
   })
   ```
4. `_ = mux.Vars(req)` first (the router registers `{level}`-style patterns elsewhere; ignore the value).

Imports needed: `context`, `encoding/json`, `net/http`, `github.com/bborbe/errors`, `github.com/bborbe/run`, `github.com/golang/glog`, `github.com/gorilla/mux`, and `github.com/bborbe/github-vuln-watcher/pkg`.

`pkg/handler/trigger_handler_test.go` (`package handler_test`) — use the `mocks.Watcher` / `mocks.CycleGate` counterfeiter fakes (or a real `pkg.NewCycleGate()`), driven through `handler.NewTriggerHandlerHTTPAdapter(ctx, watcher, gate)` and `httptest.NewRecorder()`:
- `POST /trigger` with a free gate → status 202 and body containing `{"status":"accepted"}`; `Eventually(watcher.PollCallCount).Should(Equal(1))` and `watcher.PollArgsForCall(0)` second value is `false`.
- `POST /trigger?force=true` → `Eventually` shows `PollArgsForCall(0)` second value is `true`.
- `POST /trigger` while the gate is already held (acquire it in the test first) → status 409 and `watcher.PollCallCount()` stays 0.
- `POST /trigger?force=true&repo=attacker/repo` → 202, and the handler never reads `repo`: assert `PollArgsForCall(0)` force is `true` and that the handler source contains no reference to a repo parameter.
- The goroutine does not use the request context: cancel the request context immediately after the handler returns and assert the injected watcher still receives its `Poll` call.

Add the burst test that is the evidence for acceptance criterion 7 ("a burst of N concurrent /trigger calls runs exactly one cycle"):

```go
Describe("burst of concurrent /trigger calls", func() {
	It("runs exactly one cycle", func() {
		registry := prometheus.NewRegistry()
		metrics := pkg.NewMetrics(registry)
		release := make(chan struct{})
		var pollCalls int32
		watcher := &mocks.Watcher{}
		watcher.PollStub = func(ctx context.Context, force bool) error {
			atomic.AddInt32(&pollCalls, 1)
			<-release // hold the single cycle slot so the other triggers see it busy
			metrics.IncPollCycle("success")
			return nil
		}
		gate := pkg.NewCycleGate()
		handler := factory.CreateTriggerHandler(context.Background(), watcher, gate)
		server := httptest.NewServer(handler)
		defer server.Close()

		const n = 5
		statuses := make([]int, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				resp, err := http.Post(server.URL+"/trigger", "application/json", nil)
				Expect(err).NotTo(HaveOccurred())
				statuses[i] = resp.StatusCode
				_ = resp.Body.Close()
			}(i)
		}
		Eventually(func() int { return int(atomic.LoadInt32(&pollCalls)) }).
			Should(Equal(1))
		close(release)
		wg.Wait()

		Expect(atomic.LoadInt32(&pollCalls)).To(Equal(int32(1)))
		Expect(countStatuses(statuses, http.StatusAccepted)).To(Equal(1))
		Expect(countStatuses(statuses, http.StatusConflict)).To(Equal(n - 1))
		// the single cycle that ran counted its outcome (Eventually: the cycle runs in a
		// BackgroundRunner goroutine — the metric lands after release, not before wg.Wait)
		Eventually(func() float64 {
			return metricValue(registry, "github_vuln_watcher_poll_cycle_total",
				map[string]string{"result": "success"})
		}).Should(Equal(1.0))
	})
})
```

`countStatuses` counts occurrences of a status in the slice; `metricValue` gathers the registry (via `registry.Gather()`) and returns the counter value of the series whose name and label set match (return 0 when absent). Write both as small test helpers in this file.

### 6. `pkg/factory/factory.go` — composition

Package `factory`. Keep `CreateTestLoglevelHandler`, `CreateSentryAlertHandler`, `CreateHealthzHandler` untouched. Add:

```go
// CreateWatcher wires the watcher's current collaborators. Pure composition —
// no I/O. The skeleton wires metrics, cursor path and owner; the remaining
// spec layers add the inventory client, scan stage, publisher and filter chain.
func CreateWatcher(
	metrics pkg.Metrics,
	cursorPath string,
	owner string,
) pkg.Watcher {
	return pkg.NewWatcher(metrics, cursorPath, owner)
}

// CreateTriggerHandler wraps the forced-cycle handler in an http.Handler
// adapter so it can be registered with gorilla/mux.
func CreateTriggerHandler(
	ctx context.Context,
	watcher pkg.Watcher,
	gate pkg.CycleGate,
) http.Handler {
	return handler.NewTriggerHandlerHTTPAdapter(ctx, watcher, gate)
}

// CreateRouter builds the full HTTP route table. main.go's createHTTPServer
// and main_http_test.go both call this — the endpoint-contract test MUST
// exercise the same registration this function produces, not a hand-copied
// route table, or a route added/removed only in main.go would go undetected.
func CreateRouter(
	ctx context.Context,
	triggerHandler http.Handler,
	sentryClient libsentry.Client,
) *mux.Router {
	router := mux.NewRouter()
	router.Path("/healthz").Handler(CreateHealthzHandler())
	router.Path("/readiness").Handler(libhttp.NewPrintHandler("OK"))
	router.Path("/metrics").Handler(promhttp.Handler())
	router.Path("/trigger").Handler(triggerHandler)
	router.Path("/setloglevel/{level}").
		Handler(log.NewSetLoglevelHandler(ctx, log.NewLogLevelSetter(2, 5*time.Minute)))
	router.Path("/gc").Handler(libhttp.NewGarbageCollectorHandler())
	router.Path("/testloglevel").Handler(CreateTestLoglevelHandler())
	router.Path("/sentryalert").Handler(CreateSentryAlertHandler(sentryClient))
	return router
}
```

`/resetdb` and `/resetbucket/{BucketName}` are **removed** — an unregistered path returns 404 from mux, which is the documented contract. Do NOT add `/resetcursor` or `/setcursor` (spec Non-goal: no cursor-editing admin endpoints).

Add `pkg/factory/factory_test.go` (`package factory_test`): a spec asserting the router table is exactly `["/healthz", "/readiness", "/metrics", "/trigger", "/setloglevel/{level}", "/gc", "/testloglevel", "/sentryalert"]` (walk `router.Walk` collecting `r.GetPath()`), and that `/resetdb` / `/resetbucket/foo` are NOT in that set; and a spec asserting `CreateWatcher(pkg.NewMetrics(prometheus.NewRegistry()), "/tmp/c.json", "bborbe")` returns a non-nil `pkg.Watcher`.

### 7. `main.go` — rewrite

Keep `package main`, `const serviceName = "github-vuln-watcher"`, and the `main()` body (`service.Main(context.Background(), app, &app.SentryDSN, &app.SentryProxy)`).

Replace the `application` struct with exactly these fields:

```go
type application struct {
	SentryDSN   string `required:"true"  arg:"sentry-dsn"   env:"SENTRY_DSN"   usage:"SentryDSN"    display:"length"`
	SentryProxy string `required:"false" arg:"sentry-proxy" env:"SENTRY_PROXY" usage:"Sentry Proxy"`

	Listen        string `required:"true"  arg:"listen"         env:"LISTEN"         usage:"HTTP listen address"`
	Stage         string `required:"true"  arg:"stage"          env:"STAGE"          usage:"Deployment stage (dev|prod), stamped on every emitted task"`
	Owner         string `required:"true"  arg:"owner"          env:"OWNER"          usage:"GitHub owner / org to scan (e.g. bborbe)"`
	RepoAllowlist string `required:"false" arg:"repo-allowlist" env:"REPO_ALLOWLIST" usage:"Comma-separated host-qualified repo allowlist (host/owner/repo); empty = allow-all within OWNER"`
	PollInterval  string `required:"false" arg:"poll-interval"  env:"POLL_INTERVAL"  usage:"Poll interval (Go duration); must not exceed 24h"                               default:"12h"`
	CursorPath    string `required:"false" arg:"cursor-path"    env:"CURSOR_PATH"    usage:"Persisted-memory path (mount a PVC)"                                            default:"/data/cursor.json"`
	KafkaBrokers  string `required:"true"  arg:"kafka-brokers"  env:"KAFKA_BROKERS"  usage:"Comma separated list of Kafka brokers"`

	TopicPrefix base.TopicPrefix `required:"false" arg:"topic-prefix" env:"TOPIC_PREFIX" usage:"Kafka topic prefix for CQRS topic construction"`

	AppID          int64  `required:"false" arg:"app-id"          env:"APP_ID"          usage:"GitHub App ID"`
	InstallationID int64  `required:"false" arg:"installation-id" env:"INSTALLATION_ID" usage:"GitHub App Installation ID"`
	PEMKey         string `required:"false" arg:"pem-key"         env:"PEM_KEY"         usage:"GitHub App PEM key (populated from a k8s Secret)" display:"length"`

	BuildGitVersion string            `required:"false" arg:"build-git-version" env:"BUILD_GIT_VERSION" usage:"Build Git version"         default:"dev"`
	BuildGitCommit  string            `required:"false" arg:"build-git-commit"  env:"BUILD_GIT_COMMIT"  usage:"Build Git commit hash"     default:"none"`
	BuildDate       *libtime.DateTime `required:"false" arg:"build-date"        env:"BUILD_DATE"        usage:"Build timestamp (RFC3339)"`

	TriggerHandler http.Handler
}
```

`DataDir`/`DATADIR` and `BatchSize`/`BATCH_SIZE` are removed — the service has no on-disk key-value store. `CURSOR_PATH` defaults to `/data/cursor.json`. `APP_ID`/`INSTALLATION_ID`/`PEM_KEY`/`KAFKA_BROKERS`/`TOPIC_PREFIX` are declared here so the config surface is complete; `Run` does not consume them until the inventory (APP_ID/INSTALLATION_ID/PEM_KEY) and emit (KAFKA_BROKERS/TOPIC_PREFIX) layers arrive.

Imports after the rewrite: `context`, `net/http`, `os`, `time`, `github.com/bborbe/cqrs/base`, `github.com/bborbe/errors`, `libhttp "github.com/bborbe/http"`, `libmetrics "github.com/bborbe/metrics"`, `github.com/bborbe/run`, `libsentry "github.com/bborbe/sentry"`, `github.com/bborbe/service`, `libtime "github.com/bborbe/time"`, `github.com/golang/glog`, `"github.com/bborbe/github-vuln-watcher/pkg"`, `"github.com/bborbe/github-vuln-watcher/pkg/factory"`. Drop the `libboltkv` and `libkv` imports.

`Run(ctx context.Context, sentryClient libsentry.Client) error` body, in order:

1. `libmetrics.NewBuildInfoMetrics().SetBuildInfo(a.BuildGitVersion, a.BuildGitCommit, a.BuildDate)`.
2. `pollInterval, err := time.ParseDuration(a.PollInterval)`; on error `return errors.Wrapf(ctx, err, "parse poll interval %q", a.PollInterval)`.
3. Enforce the latency ceiling: `if pollInterval > 24*time.Hour { return errors.Errorf(ctx, "poll interval %s exceeds the 24h maximum", a.PollInterval) }`.
4. `metrics := pkg.NewMetrics(nil)` (nil → `prometheus.DefaultRegisterer`, which `promhttp.Handler()` serves).
5. `w := factory.CreateWatcher(metrics, a.CursorPath, a.Owner)`.
6. `gate := pkg.NewCycleGate()`; `a.TriggerHandler = factory.CreateTriggerHandler(ctx, w, gate)`.
7. `glog.V(2).Infof("github-vuln-watcher starting stage=%s owner=%s interval=%s cursor=%s listen=%s", a.Stage, a.Owner, a.PollInterval, a.CursorPath, a.Listen)`.
8. `return service.Run(ctx, a.pollLoop(w, gate, pollInterval), a.createHTTPServer(sentryClient))`.

Keep `Run` under the 80-line `funlen` cap; extract a helper if needed rather than adding `//nolint`.

`pollLoop` — fires one cycle immediately on start and one per tick thereafter, sharing the same single-cycle gate as the `/trigger` endpoint:

```go
// pollLoop fires one cycle immediately on start and one per tick thereafter.
// It shares the CycleGate with the /trigger endpoint, so a tick that lands
// while a forced cycle is running is skipped rather than run concurrently —
// the cursor file has exactly one writer.
func (a *application) pollLoop(
	w pkg.Watcher,
	gate pkg.CycleGate,
	interval time.Duration,
) run.Func {
	poll := func(ctx context.Context) {
		if !gate.TryAcquire() {
			glog.Warningf("poll cycle skipped: a cycle is already running")
			return
		}
		defer gate.Release()
		// The interval loop is the dedup-engaged path; force=true comes
		// exclusively from the /trigger endpoint.
		if err := w.Poll(ctx, false); err != nil {
			glog.Errorf("poll: %v", err)
		}
	}
	return func(ctx context.Context) error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		poll(ctx)
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				poll(ctx)
			}
		}
	}
}
```

`createHTTPServer(sentryClient libsentry.Client) run.Func` builds its router via `factory.CreateRouter(ctx, a.TriggerHandler, sentryClient)` and wraps it with `libhttp.NewServer(a.Listen, router).Run(ctx)`. Do NOT re-declare the route table inline in `main.go`.

### 8. `main_test.go` and `main_http_test.go`

Create `main_test.go` (`package main_test`) mirroring the sibling's shape: the `//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6@v6.12.2 -generate` directive, the `TestSuite` function (time.Local = UTC, `format.TruncatedDiff = false`, `RegisterFailHandler(Fail)`, `GinkgoConfiguration()`, `RunSpecs(t, "Main Suite", ...)`), and three specs:
- `"Compiles"`: `gexec.Build(".", "-mod=mod", "-buildvcs=false")` returns no error.
- `"defaults the cursor path to the PVC mount point"`: `Expect(pkg.DefaultCursorPath).To(Equal("/data/cursor.json"))`. (This requires `pkg` to export `DefaultCursorPath` — add `const DefaultCursorPath = "/data/cursor.json"` to `pkg/cursor.go` along with a doc comment. `pkg/cursor.go`'s full cursor implementation arrives in a later prompt; for now it only carries this constant.)
- `"does not declare the removed scaffold flags"`: read `main.go`, assert the text does not contain `DATADIR` or `BATCH_SIZE`, and that it contains `default:"12h"` (evidence for acceptance criterion 6).

Create `main_http_test.go` (`package main_test`) — the endpoint-contract test that exercises the SAME registration `factory.CreateRouter` produces:

- A hand-written `fakeWatcher` (struct with `Poll(ctx, force) error` returning nil; a `forceCalls chan bool` to observe calls) and a real `pkg.NewCycleGate()`.
- `metricsOnce sync.Once` that registers `pkg.NewMetrics(prometheus.DefaultRegisterer)` exactly once per test binary (re-registering the same collectors twice panics).
- `BeforeEach`: build `triggerHandler := factory.CreateTriggerHandler(baseCtx, watcherFake, gate)` and `router := factory.CreateRouter(baseCtx, triggerHandler, nil)`, serve with `httptest.NewServer(router)`.
- `GET /healthz` → 200. `GET /readiness` → 200.
- `GET /metrics` → 200 and body contains, for every label in `pkg.PollCycleResults`, the text `github_vuln_watcher_poll_cycle_total{result="<label>"} 0`; likewise `pkg.PublishStatuses` (`published_total{status="<label>"} 0`) and `pkg.FilterSkipReasons` (`filter_skipped_total{reason="<label>"} 0`), plus `github_vuln_watcher_repos_scanned_total 0`.
- `POST /trigger` → 202 and body contains `accepted`; `Eventually(watcherFake.forceCalls).Should(Receive(Equal(false)))`.
- `POST /trigger?force=true` → 202; `Eventually(watcherFake.forceCalls).Should(Receive(Equal(true)))`.
- `POST /trigger` while the gate is held (`gate.TryAcquire()`) → 409.
- `GET /setloglevel/2` → 200.
- `GET /resetdb` → 404; `GET /resetbucket/foo` → 404 (the removed key-value-store endpoints).

### 9. Makefile and example.env

- `Makefile` `run` target: remove `-datadir="data"` and `-batch-size="100"` (those flags no longer exist and the target would fail at startup). Add `-stage="${STAGE}"`, `-owner="${OWNER}"`, `-repo-allowlist="${REPO_ALLOWLIST}"`, `-cursor-path="data/cursor.json"`, `-poll-interval="12h"`. Keep the target name, the `-sentry-dsn` teamvault line, `-listen`, `-kafka-brokers` and `-v=2` as they are. Do not rename, add, or delete any Makefile target.
- `example.env`: add `export OWNER=bborbe`, `export STAGE=dev`, `export REPO_ALLOWLIST=`. Insert them following the file's existing ordering convention; do not reorder unrelated lines.

### 10. CHANGELOG

Add an `## Unreleased` section above `## v0.0.1` in `CHANGELOG.md`:

```
## Unreleased

- feat: Add github-vuln-watcher service shell with env config surface, single-cycle poll loop (immediate first cycle, 12h default interval, 24h ceiling), /trigger endpoint and four-counter metrics scaffold
- refactor: Remove BoltDB / DATADIR / BATCH_SIZE and the /resetdb, /resetbucket endpoints — persistent memory moves to the JSON cursor
```

</requirements>

<constraints>
- Module path is `github.com/bborbe/github-vuln-watcher`. The scaffold's Makefile targets stay as they are except the `run` target edits in step 9.
- **Do NOT touch `k8s/*.yaml`.** The stale `DATADIR` env entry there is inert (struct-tag config ignores unknown envs) and is dropped by the separate deploy step, NOT by this prompt; the `/data` volume must be retained as the home of `CURSOR_PATH`.
- Do NOT modify `pkg/handler/healthz.go`, `pkg/handler/test-loglevel.go`, `pkg/handler/sentry-alert.go`, or the scaffold's `pkg/mathutil/` — existing handlers and their behavior must not regress (spec Constraints).
- `POLL_INTERVAL` default is `12h` and the hard ceiling is 24h — the startup validation in step 7.3 is the enforcement. Do NOT add any other tunable or opt-out flag.
- No `os/exec` in this prompt — the scan subprocess stage arrives in a later prompt.
- Never use `fmt.Errorf`. All errors go through `github.com/bborbe/errors` (`errors.Wrap`, `errors.Wrapf`, `errors.Errorf`) and carry `ctx`.
- Metrics register through the injected `prometheus.Registerer` only — never a package-level `init()`.
- Never hand-edit anything under `mocks/` — `make precommit` regenerates that directory from scratch.
- Tests use Ginkgo/Gomega; counterfeiter fakes come from `//counterfeiter:generate` directives.
- Keep every line under 100 characters (`golines --max-len=100` runs in `make precommit`) and every function under 80 lines / 50 statements (`funlen`).
- Every new `.go` file starts with the BSD license header block used by the existing files (`make precommit` runs `addlicense`, but write it yourself so the diff is stable).
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
grep -n 'default:"12h"' main.go
```
Expect at least one line (the `POLL_INTERVAL` default — acceptance criterion 6 evidence).

```
grep -n 'github_vuln_watcher' pkg/metrics.go
```
Expect at least one line (the metric namespace — spec Verification).

```
grep -n 'DefaultCursorPath' pkg/cursor.go
grep -n '/data/cursor.json' main.go
```
Each expects at least one line.

```
grep -rn 'boltkv\|BATCH_SIZE\|DATADIR' --include='*.go' --exclude='*_test.go' .
```
Expect zero matches (the key-value store is gone).

```
go test -mod=mod ./...
```
Must exit 0 (includes the trigger burst test and the endpoint-contract test).
</verification>
