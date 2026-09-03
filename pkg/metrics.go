// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg

import (
	"github.com/prometheus/client_golang/prometheus"
)

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

	// IncVulnsDetected adds n vuln markers found across a cycle (no labels).
	IncVulnsDetected(n int)
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
	PublishStatuses = []string{
		"create",
		"error",
	}
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
func NewMetrics(registerer prometheus.Registerer) Metrics {
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}
	pollCycle := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricNamespace,
		Name:      "poll_cycle_total",
		Help:      "Total number of poll cycles by result",
	}, []string{"result"})
	published := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricNamespace,
		Name:      "published_total",
		Help:      "Total number of published CreateTaskCommands by status",
	}, []string{"status"})
	reposScanned := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricNamespace,
		Name:      "repos_scanned_total",
		Help:      "Total number of repos scanned across all cycles",
	})
	filterSkipped := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricNamespace,
		Name:      "filter_skipped_total",
		Help:      "Total number of repos skipped by the filter chain by reason",
	}, []string{"reason"})
	vulnsDetected := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricNamespace,
		Name:      "vulns_detected_total",
		Help:      "Total number of vuln markers detected",
	})
	registerer.MustRegister(
		pollCycle,
		published,
		reposScanned,
		filterSkipped,
		vulnsDetected,
	)
	for _, label := range PollCycleResults {
		pollCycle.WithLabelValues(label).Add(0)
	}
	for _, label := range PublishStatuses {
		published.WithLabelValues(label).Add(0)
	}
	for _, label := range FilterSkipReasons {
		filterSkipped.WithLabelValues(label).Add(0)
	}
	return &metricsImpl{
		pollCycle:     pollCycle,
		published:     published,
		reposScanned:  reposScanned,
		filterSkipped: filterSkipped,
		vulnsDetected: vulnsDetected,
	}
}

type metricsImpl struct {
	pollCycle     *prometheus.CounterVec
	published     *prometheus.CounterVec
	reposScanned  prometheus.Counter
	filterSkipped *prometheus.CounterVec
	vulnsDetected prometheus.Counter
}

// IncPollCycle increments the poll_cycle_total counter for the given result.
func (m *metricsImpl) IncPollCycle(result string) {
	m.pollCycle.WithLabelValues(result).Inc()
}

// IncPublished increments the published_total counter for the given status.
func (m *metricsImpl) IncPublished(status string) {
	m.published.WithLabelValues(status).Inc()
}

// IncReposScanned adds n repos scanned in one cycle.
func (m *metricsImpl) IncReposScanned(n int) {
	m.reposScanned.Add(float64(n))
}

// IncFilterSkipped increments the filter_skipped_total counter for the given reason.
func (m *metricsImpl) IncFilterSkipped(reason string) {
	m.filterSkipped.WithLabelValues(reason).Inc()
}

// IncVulnsDetected adds n vuln markers found across a cycle.
func (m *metricsImpl) IncVulnsDetected(n int) {
	m.vulnsDetected.Add(float64(n))
}
