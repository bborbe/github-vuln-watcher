// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/bborbe/errors"
	"github.com/bborbe/run"
	"github.com/golang/glog"

	"github.com/bborbe/github-vuln-watcher/pkg"
)

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

func (h *triggerHandler) ServeHTTP(
	ctx context.Context,
	resp http.ResponseWriter,
	req *http.Request,
) error {
	forceStr := req.URL.Query().Get("force")
	force := forceStr == "true" || forceStr == "1"
	if !h.gate.TryAcquire() {
		glog.Warningf("trigger rejected: a poll cycle is already running")
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(http.StatusConflict)
		return json.NewEncoder(resp).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "CONFLICT",
				"message": "a poll cycle is already running",
			},
		})
	}
	if err := h.runner.Run(run.CatchPanic(func(ctx context.Context) error {
		defer h.gate.Release()
		if err := h.watcher.Poll(ctx, force); err != nil {
			return errors.Wrapf(ctx, err, "forced poll cycle failed force=%t", force)
		}
		return nil
	})); err != nil {
		h.gate.Release()
		// the returned error is logged by the httpAdapter wrapper — do not log twice.
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(http.StatusInternalServerError)
		return json.NewEncoder(resp).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "INTERNAL",
				"message": "failed to start poll cycle",
			},
		})
	}
	glog.Warningf("forced poll cycle accepted force=%t", force)
	resp.Header().Set("Content-Type", "application/json")
	resp.WriteHeader(http.StatusAccepted)
	return json.NewEncoder(resp).Encode(map[string]interface{}{
		"status": "accepted",
	})
}
