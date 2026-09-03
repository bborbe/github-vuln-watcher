// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package factory

import (
	"context"
	"net/http"
	"time"

	libhttp "github.com/bborbe/http"
	"github.com/bborbe/log"
	libsentry "github.com/bborbe/sentry"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/bborbe/github-vuln-watcher/pkg"
	"github.com/bborbe/github-vuln-watcher/pkg/handler"
)

// CreateTestLoglevelHandler creates an HTTP handler that tests different glog verbosity levels.
func CreateTestLoglevelHandler() http.Handler {
	return handler.NewTestLoglevelHandler()
}

// CreateSentryAlertHandler creates an HTTP handler that sends test alerts to Sentry.
func CreateSentryAlertHandler(sentryClient libsentry.Client) http.Handler {
	return handler.NewSentryAlertHandler(sentryClient)
}

// CreateHealthzHandler creates an HTTP handler that serves the canonical
// `/healthz` liveness response (HTTP 200, body `{"status":"ok"}`,
// Content-Type: application/json).
func CreateHealthzHandler() http.Handler {
	return handler.NewHealthzHandler()
}

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
