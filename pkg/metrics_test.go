// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg_test

import (
	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bborbe/github-vuln-watcher/pkg"
)

func gatherMetricValue(
	registry *prometheus.Registry,
	name string,
	labels map[string]string,
) float64 {
	families, err := registry.Gather()
	Expect(err).NotTo(HaveOccurred())
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			labelMatch := true
			for _, lp := range metric.GetLabel() {
				if want, ok := labels[lp.GetName()]; !ok || want != lp.GetValue() {
					labelMatch = false
				}
			}
			if labelMatch {
				return metric.GetCounter().GetValue()
			}
		}
	}
	return 0
}

var _ = ginkgo.Describe("Metrics", func() {
	var (
		registry *prometheus.Registry
		metrics  pkg.Metrics
	)

	ginkgo.BeforeEach(func() {
		registry = prometheus.NewRegistry()
		metrics = pkg.NewMetrics(registry)
	})

	ginkgo.It("exposes all four metric families after construction", func() {
		families, err := registry.Gather()
		Expect(err).NotTo(HaveOccurred())
		names := make([]string, 0, len(families))
		for _, family := range families {
			names = append(names, family.GetName())
		}
		Expect(names).To(ContainElement("github_vuln_watcher_poll_cycle_total"))
		Expect(names).To(ContainElement("github_vuln_watcher_published_total"))
		Expect(names).To(ContainElement("github_vuln_watcher_repos_scanned_total"))
		Expect(names).To(ContainElement("github_vuln_watcher_filter_skipped_total"))
	})

	ginkgo.It("pre-initialises every label value to 0", func() {
		for _, label := range pkg.PollCycleResults {
			Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
				map[string]string{"result": label})).To(Equal(0.0))
		}
		for _, label := range pkg.PublishStatuses {
			Expect(gatherMetricValue(registry, "github_vuln_watcher_published_total",
				map[string]string{"status": label})).To(Equal(0.0))
		}
		for _, label := range pkg.FilterSkipReasons {
			Expect(gatherMetricValue(registry, "github_vuln_watcher_filter_skipped_total",
				map[string]string{"reason": label})).To(Equal(0.0))
		}
		Expect(gatherMetricValue(registry, "github_vuln_watcher_repos_scanned_total", nil)).
			To(Equal(0.0))
	})

	ginkgo.It("IncFilterSkipped moves only the given reason series to 1", func() {
		metrics.IncFilterSkipped("scope")
		Expect(gatherMetricValue(registry, "github_vuln_watcher_filter_skipped_total",
			map[string]string{"reason": "scope"})).To(Equal(1.0))
		for _, label := range pkg.FilterSkipReasons {
			if label == "scope" {
				continue
			}
			Expect(gatherMetricValue(registry, "github_vuln_watcher_filter_skipped_total",
				map[string]string{"reason": label})).To(Equal(0.0))
		}
	})

	ginkgo.It("IncPollCycle moves the given result series to 1", func() {
		metrics.IncPollCycle("success")
		Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
			map[string]string{"result": "success"})).To(Equal(1.0))
	})

	ginkgo.It("IncReposScanned adds to the plain counter", func() {
		metrics.IncReposScanned(3)
		Expect(gatherMetricValue(registry, "github_vuln_watcher_repos_scanned_total", nil)).
			To(Equal(3.0))
	})

	ginkgo.It(
		"two registries each get their own collectors without package-level registration",
		func() {
			registry2 := prometheus.NewRegistry()
			metrics2 := pkg.NewMetrics(registry2)
			metrics.IncPollCycle("success")
			Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
				map[string]string{"result": "success"})).To(Equal(1.0))
			Expect(gatherMetricValue(registry2, "github_vuln_watcher_poll_cycle_total",
				map[string]string{"result": "success"})).To(Equal(0.0))
			metrics2.IncPollCycle("success")
			Expect(gatherMetricValue(registry2, "github_vuln_watcher_poll_cycle_total",
				map[string]string{"result": "success"})).To(Equal(1.0))
		},
	)
})
