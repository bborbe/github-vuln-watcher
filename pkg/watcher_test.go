// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg_test

import (
	"context"

	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bborbe/github-vuln-watcher/pkg"
)

var _ = ginkgo.Describe("Watcher", func() {
	var (
		ctx      context.Context
		watcher  pkg.Watcher
		registry *prometheus.Registry
	)

	ginkgo.BeforeEach(func() {
		ctx = context.Background()
		registry = prometheus.NewRegistry()
		watcher = pkg.NewWatcher(pkg.NewMetrics(registry), "/tmp/cursor.json", "bborbe")
	})

	ginkgo.It("one Poll increments the success poll cycle counter to exactly 1", func() {
		Expect(watcher.Poll(ctx, false)).To(Succeed())
		Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
			map[string]string{"result": "success"})).To(Equal(1.0))
	})

	ginkgo.It("a second Poll increments it to 2", func() {
		Expect(watcher.Poll(ctx, false)).To(Succeed())
		Expect(watcher.Poll(ctx, true)).To(Succeed())
		Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
			map[string]string{"result": "success"})).To(Equal(2.0))
	})
})
