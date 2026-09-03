// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg_test

import (
	"context"
	stderrors "errors"

	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bborbe/github-vuln-watcher/mocks"
	"github.com/bborbe/github-vuln-watcher/pkg"
)

var _ = ginkgo.Describe("TaskPublisher", func() {
	var (
		ctx       context.Context
		registry  *prometheus.Registry
		metrics   pkg.Metrics
		sender    *mocks.CreateCommandSender
		publisher pkg.TaskPublisher
		candidate pkg.Candidate
	)

	ginkgo.BeforeEach(func() {
		ctx = context.Background()
		registry = prometheus.NewRegistry()
		metrics = pkg.NewMetrics(registry)
		sender = &mocks.CreateCommandSender{}
		publisher = pkg.NewTaskPublisher(sender, metrics, pkg.TaskConfig{Stage: "dev"})
		candidate = pkg.Candidate{
			Repo:    pkg.Repo{Owner: "bborbe", Name: "demo", DefaultBranch: "master"},
			HeadSHA: "0123456789abcdef0123456789abcdef01234567",
			VulnIDs: []string{"GO-2024-1234", "GO-2024-5678"},
		}
	})

	ginkgo.It("returns true and counts a create on a successful send", func() {
		sender.SendCommandReturns(nil)

		Expect(publisher.PublishCreate(ctx, candidate)).To(BeTrue())

		Expect(sender.SendCommandCallCount()).To(Equal(1))
		_, cmd := sender.SendCommandArgsForCall(0)
		Expect(cmd.Frontmatter["task_type"]).To(Equal("github-update-go"))
		Expect(cmd.Frontmatter["vulns"]).
			To(Equal([]string{"GO-2024-1234", "GO-2024-5678"}))
		Expect(gatherMetricValue(registry, "github_vuln_watcher_published_total",
			map[string]string{"status": "create"})).To(Equal(1.0))
		Expect(gatherMetricValue(registry, "github_vuln_watcher_published_total",
			map[string]string{"status": "error"})).To(Equal(0.0))
	})

	ginkgo.It("returns false and counts an error on a failed send", func() {
		sender.SendCommandReturns(stderrors.New("kafka down"))

		Expect(publisher.PublishCreate(ctx, candidate)).To(BeFalse())

		Expect(gatherMetricValue(registry, "github_vuln_watcher_published_total",
			map[string]string{"status": "error"})).To(Equal(1.0))
		Expect(gatherMetricValue(registry, "github_vuln_watcher_published_total",
			map[string]string{"status": "create"})).To(Equal(0.0))
	})
})
