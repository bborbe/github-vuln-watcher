// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg_test

import (
	"context"
	stderrors "errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bborbe/github-vuln-watcher/mocks"
	"github.com/bborbe/github-vuln-watcher/pkg"
	"github.com/bborbe/github-vuln-watcher/pkg/filter"
)

var _ = ginkgo.Describe("Watcher", func() {
	var (
		ctx         context.Context
		watcher     pkg.Watcher
		registry    *prometheus.Registry
		metrics     pkg.Metrics
		ghClient    *mocks.GitHubClient
		scanner     *mocks.Scanner
		publisher   *mocks.TaskPublisher
		cycleFilter filter.TaskCreationFilter
		cursorPath  string
	)

	ginkgo.BeforeEach(func() {
		ctx = context.Background()
		registry = prometheus.NewRegistry()
		metrics = pkg.NewMetrics(registry)
		ghClient = &mocks.GitHubClient{}
		scanner = &mocks.Scanner{}
		publisher = &mocks.TaskPublisher{}
		publisher.PublishCreateReturns(true)
		cycleFilter = filter.TaskCreationFilterList{
			filter.NewRepoAllowlistFilter(nil),
			filter.NewAutoUpdateFilter(),
			filter.NewGoModPresentFilter(),
		}
		cursorPath = filepath.Join(ginkgo.GinkgoT().TempDir(), "cursor.json")
		watcher = pkg.NewWatcher(
			ghClient,
			scanner,
			publisher,
			metrics,
			cursorPath,
			"bborbe",
			cycleFilter,
		)
	})

	ginkgo.It(
		"one Poll with no repos increments the success poll cycle counter to exactly 1",
		func() {
			Expect(watcher.Poll(ctx, false)).To(Succeed())
			Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
				map[string]string{"result": "success"})).To(Equal(1.0))
		},
	)

	ginkgo.It("a second Poll increments it to 2", func() {
		Expect(watcher.Poll(ctx, false)).To(Succeed())
		Expect(watcher.Poll(ctx, true)).To(Succeed())
		Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
			map[string]string{"result": "success"})).To(Equal(2.0))
	})

	ginkgo.It("skips repos without go.mod with no_gomod and completes with success", func() {
		ghClient.ListReposReturns([]pkg.Repo{
			{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
			{Owner: "bborbe", Name: "repo-b", DefaultBranch: "main"},
			{Owner: "bborbe", Name: "repo-c", DefaultBranch: "main"},
		}, nil)
		ghClient.GetGoModStub = func(_ context.Context, repo pkg.Repo) ([]byte, error) {
			if repo.Name == "repo-a" {
				return []byte("module example.com/x\n"), nil
			}
			return nil, nil
		}
		ghClient.GetMaintainerConfigReturns(filter.GrantedConsent, nil)

		Expect(watcher.Poll(ctx, false)).To(Succeed())
		Expect(gatherMetricValue(registry, "github_vuln_watcher_filter_skipped_total",
			map[string]string{"reason": "no_gomod"})).To(Equal(2.0))
		Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
			map[string]string{"result": "success"})).To(Equal(1.0))
	})

	ginkgo.It("aborts with rate_limited when ListRepos is rate limited", func() {
		ghClient.ListReposReturns(nil, pkg.ErrRateLimited)

		Expect(watcher.Poll(ctx, false)).To(Succeed())
		Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
			map[string]string{"result": "rate_limited"})).To(Equal(1.0))
		Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
			map[string]string{"result": "success"})).To(Equal(0.0))
	})

	ginkgo.It("aborts with github_error when ListRepos fails otherwise", func() {
		ghClient.ListReposReturns(nil, stderrors.New("network down"))

		Expect(watcher.Poll(ctx, false)).To(Succeed())
		Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
			map[string]string{"result": "github_error"})).To(Equal(1.0))
		Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
			map[string]string{"result": "success"})).To(Equal(0.0))
	})

	ginkgo.It(
		"aborts the whole cycle with rate_limited when GetMaintainerConfig is rate limited",
		func() {
			ghClient.ListReposReturns([]pkg.Repo{
				{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
			}, nil)
			ghClient.GetGoModReturns([]byte("module example.com/x\n"), nil)
			ghClient.GetMaintainerConfigReturns(filter.Consent(""), pkg.ErrRateLimited)

			Expect(watcher.Poll(ctx, false)).To(Succeed())
			Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
				map[string]string{"result": "rate_limited"})).To(Equal(1.0))
			Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
				map[string]string{"result": "success"})).To(Equal(0.0))
		},
	)

	ginkgo.It("drops a repo whose go.mod fetch fails and completes with success", func() {
		ghClient.ListReposReturns([]pkg.Repo{
			{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
		}, nil)
		ghClient.GetGoModReturns(nil, stderrors.New("network down"))

		Expect(watcher.Poll(ctx, false)).To(Succeed())
		Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
			map[string]string{"result": "success"})).To(Equal(1.0))
		Expect(gatherMetricValue(registry, "github_vuln_watcher_filter_skipped_total",
			map[string]string{"reason": "no_gomod"})).To(Equal(0.0))
	})

	ginkgo.It(
		"drops a repo whose maintainer config fetch fails and completes with success",
		func() {
			ghClient.ListReposReturns([]pkg.Repo{
				{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
			}, nil)
			ghClient.GetGoModReturns([]byte("module example.com/x\n"), nil)
			ghClient.GetMaintainerConfigReturns(filter.Consent(""), stderrors.New("network down"))

			Expect(watcher.Poll(ctx, false)).To(Succeed())
			Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
				map[string]string{"result": "success"})).To(Equal(1.0))
		},
	)

	ginkgo.It(
		"scans a consenting repo with a vuln signal and completes with success",
		func() {
			ghClient.ListReposReturns([]pkg.Repo{
				{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
			}, nil)
			ghClient.GetGoModReturns([]byte("module example.com/x\n"), nil)
			ghClient.GetMaintainerConfigReturns(filter.GrantedConsent, nil)
			scanner.ScanReturns(pkg.ScanResult{
				HeadSHA: strings.Repeat("a", 40),
				VulnIDs: []string{"GO-2024-1234"},
			}, nil)

			Expect(watcher.Poll(ctx, false)).To(Succeed())
			Expect(scanner.ScanCallCount()).To(Equal(1))
			Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
				map[string]string{"result": "success"})).To(Equal(1.0))
			Expect(gatherMetricValue(registry, "github_vuln_watcher_repos_scanned_total", nil)).
				To(Equal(1.0))
		},
	)

	ginkgo.It(
		"runs the pre-clone gates before the scan so a no-gomod repo is never scanned",
		func() {
			ghClient.ListReposReturns([]pkg.Repo{
				{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
			}, nil)
			ghClient.GetGoModReturns(nil, nil)
			ghClient.GetMaintainerConfigReturns(filter.GrantedConsent, nil)

			Expect(watcher.Poll(ctx, false)).To(Succeed())
			Expect(gatherMetricValue(registry, "github_vuln_watcher_filter_skipped_total",
				map[string]string{"reason": "no_gomod"})).To(Equal(1.0))
			Expect(scanner.ScanCallCount()).To(Equal(0))
		},
	)

	ginkgo.It("skips with gate_timeout when the scan times out", func() {
		ghClient.ListReposReturns([]pkg.Repo{
			{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
		}, nil)
		ghClient.GetGoModReturns([]byte("module example.com/x\n"), nil)
		ghClient.GetMaintainerConfigReturns(filter.GrantedConsent, nil)
		scanner.ScanReturns(pkg.ScanResult{}, pkg.ErrGateTimeout)

		Expect(watcher.Poll(ctx, false)).To(Succeed())
		Expect(gatherMetricValue(registry, "github_vuln_watcher_filter_skipped_total",
			map[string]string{"reason": "gate_timeout"})).To(Equal(1.0))
	})

	ginkgo.It("skips with clone_failed when the clone fails", func() {
		ghClient.ListReposReturns([]pkg.Repo{
			{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
		}, nil)
		ghClient.GetGoModReturns([]byte("module example.com/x\n"), nil)
		ghClient.GetMaintainerConfigReturns(filter.GrantedConsent, nil)
		scanner.ScanReturns(pkg.ScanResult{}, pkg.ErrCloneFailed)

		Expect(watcher.Poll(ctx, false)).To(Succeed())
		Expect(gatherMetricValue(registry, "github_vuln_watcher_filter_skipped_total",
			map[string]string{"reason": "clone_failed"})).To(Equal(1.0))
	})

	ginkgo.It("skips with scan_failed on a generic scan error", func() {
		ghClient.ListReposReturns([]pkg.Repo{
			{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
		}, nil)
		ghClient.GetGoModReturns([]byte("module example.com/x\n"), nil)
		ghClient.GetMaintainerConfigReturns(filter.GrantedConsent, nil)
		scanner.ScanReturns(pkg.ScanResult{}, stderrors.New("boom"))

		Expect(watcher.Poll(ctx, false)).To(Succeed())
		Expect(gatherMetricValue(registry, "github_vuln_watcher_filter_skipped_total",
			map[string]string{"reason": "scan_failed"})).To(Equal(1.0))
	})

	ginkgo.It("skips with already_clean when the scan finds no markers", func() {
		ghClient.ListReposReturns([]pkg.Repo{
			{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
		}, nil)
		ghClient.GetGoModReturns([]byte("module example.com/x\n"), nil)
		ghClient.GetMaintainerConfigReturns(filter.GrantedConsent, nil)
		scanner.ScanReturns(pkg.ScanResult{}, nil)

		Expect(watcher.Poll(ctx, false)).To(Succeed())
		Expect(gatherMetricValue(registry, "github_vuln_watcher_filter_skipped_total",
			map[string]string{"reason": "already_clean"})).To(Equal(1.0))
	})

	ginkgo.It(
		"emits exactly one publish per consenting repo with markers",
		func() {
			ghClient.ListReposReturns([]pkg.Repo{
				{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
			}, nil)
			ghClient.GetGoModReturns([]byte("module example.com/x\n"), nil)
			ghClient.GetMaintainerConfigReturns(filter.GrantedConsent, nil)
			scanner.ScanReturns(pkg.ScanResult{
				HeadSHA: strings.Repeat("a", 40),
				VulnIDs: []string{"GO-2024-1234"},
			}, nil)

			Expect(watcher.Poll(ctx, false)).To(Succeed())

			Expect(publisher.PublishCreateCallCount()).To(Equal(1))
			_, published := publisher.PublishCreateArgsForCall(0)
			Expect(published.VulnIDs).To(Equal([]string{"GO-2024-1234"}))
			Expect(gatherMetricValue(registry, "github_vuln_watcher_vulns_detected_total", nil)).
				To(Equal(1.0))
			Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
				map[string]string{"result": "success"})).To(Equal(1.0))
		},
	)

	ginkgo.It("never publishes for a repo with zero markers", func() {
		ghClient.ListReposReturns([]pkg.Repo{
			{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
		}, nil)
		ghClient.GetGoModReturns([]byte("module example.com/x\n"), nil)
		ghClient.GetMaintainerConfigReturns(filter.GrantedConsent, nil)
		scanner.ScanReturns(pkg.ScanResult{}, nil)

		Expect(watcher.Poll(ctx, false)).To(Succeed())

		Expect(publisher.PublishCreateCallCount()).To(Equal(0))
		Expect(gatherMetricValue(registry, "github_vuln_watcher_vulns_detected_total", nil)).
			To(Equal(0.0))
	})

	ginkgo.It("does not abort the cycle when a publish fails", func() {
		publisher.PublishCreateReturns(false)
		ghClient.ListReposReturns([]pkg.Repo{
			{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
		}, nil)
		ghClient.GetGoModReturns([]byte("module example.com/x\n"), nil)
		ghClient.GetMaintainerConfigReturns(filter.GrantedConsent, nil)
		scanner.ScanReturns(pkg.ScanResult{
			HeadSHA: strings.Repeat("a", 40),
			VulnIDs: []string{"GO-2024-1234"},
		}, nil)

		Expect(watcher.Poll(ctx, false)).To(Succeed())

		Expect(publisher.PublishCreateCallCount()).To(Equal(1))
		Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
			map[string]string{"result": "success"})).To(Equal(1.0))
	})

	ginkgo.It("counts every marker on vulns_detected_total, not just one per repo", func() {
		ghClient.ListReposReturns([]pkg.Repo{
			{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
		}, nil)
		ghClient.GetGoModReturns([]byte("module example.com/x\n"), nil)
		ghClient.GetMaintainerConfigReturns(filter.GrantedConsent, nil)
		scanner.ScanReturns(pkg.ScanResult{
			HeadSHA: strings.Repeat("a", 40),
			VulnIDs: []string{"GO-2024-1234", "GO-2024-5678"},
		}, nil)

		Expect(watcher.Poll(ctx, false)).To(Succeed())

		Expect(gatherMetricValue(registry, "github_vuln_watcher_vulns_detected_total", nil)).
			To(Equal(2.0))
	})

	ginkgo.It(
		"persists the emitted identifier and dedups an unchanged finding set next cycle",
		func() {
			ghClient.ListReposReturns([]pkg.Repo{
				{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
			}, nil)
			ghClient.GetGoModReturns([]byte("module example.com/x\n"), nil)
			ghClient.GetMaintainerConfigReturns(filter.GrantedConsent, nil)
			scanner.ScanReturns(pkg.ScanResult{
				HeadSHA: strings.Repeat("a", 40),
				VulnIDs: []string{"GO-2024-1234"},
			}, nil)

			Expect(watcher.Poll(ctx, false)).To(Succeed())
			Expect(publisher.PublishCreateCallCount()).To(Equal(1))

			data, err := os.ReadFile(cursorPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(data)).To(ContainSubstring("last_emitted_task_identifier"))

			Expect(watcher.Poll(ctx, false)).To(Succeed())
			Expect(publisher.PublishCreateCallCount()).To(Equal(1))
			Expect(gatherMetricValue(registry,
				"github_vuln_watcher_filter_skipped_total",
				map[string]string{"reason": "finding_set_unchanged"})).To(Equal(1.0))
		},
	)

	ginkgo.It("re-files an unchanged finding set on a forced cycle", func() {
		ghClient.ListReposReturns([]pkg.Repo{
			{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
		}, nil)
		ghClient.GetGoModReturns([]byte("module example.com/x\n"), nil)
		ghClient.GetMaintainerConfigReturns(filter.GrantedConsent, nil)
		scanner.ScanReturns(pkg.ScanResult{
			HeadSHA: strings.Repeat("a", 40),
			VulnIDs: []string{"GO-2024-1234"},
		}, nil)

		Expect(watcher.Poll(ctx, false)).To(Succeed())
		Expect(publisher.PublishCreateCallCount()).To(Equal(1))

		Expect(watcher.Poll(ctx, true)).To(Succeed())
		Expect(publisher.PublishCreateCallCount()).To(Equal(2))
		Expect(gatherMetricValue(registry,
			"github_vuln_watcher_filter_skipped_total",
			map[string]string{"reason": "finding_set_unchanged"})).To(Equal(0.0))
	})

	ginkgo.It("cold-starts from a corrupt cursor file and renames it to .corrupt", func() {
		Expect(os.WriteFile(cursorPath, []byte("{not json"), 0o600)).To(Succeed())
		ghClient.ListReposReturns([]pkg.Repo{
			{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
		}, nil)
		ghClient.GetGoModReturns([]byte("module example.com/x\n"), nil)
		ghClient.GetMaintainerConfigReturns(filter.GrantedConsent, nil)
		scanner.ScanReturns(pkg.ScanResult{
			HeadSHA: strings.Repeat("a", 40),
			VulnIDs: []string{"GO-2024-1234"},
		}, nil)

		Expect(watcher.Poll(ctx, false)).To(Succeed())
		Expect(cursorPath + ".corrupt").To(BeAnExistingFile())
		Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
			map[string]string{"result": "success"})).To(Equal(1.0))
	})

	ginkgo.It("counts scan_error when the cursor file cannot be read", func() {
		dir := filepath.Join(ginkgo.GinkgoT().TempDir(), "cursor-dir")
		Expect(os.MkdirAll(dir, 0o750)).To(Succeed())
		watcher = pkg.NewWatcher(
			ghClient, scanner, publisher, metrics, dir, "bborbe", cycleFilter,
		)

		Expect(watcher.Poll(ctx, false)).To(Succeed())
		Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
			map[string]string{"result": "scan_error"})).To(Equal(1.0))
	})

	ginkgo.It(
		"does not advance the cursor entry on a failed publish and re-emits next cycle",
		func() {
			sender := &mocks.CreateCommandSender{}
			sender.SendCommandReturns(stderrors.New("kafka down"))
			realPublisher := pkg.NewTaskPublisher(
				sender,
				metrics,
				pkg.TaskConfig{Stage: "dev"},
			)
			watcher = pkg.NewWatcher(
				ghClient,
				scanner,
				realPublisher,
				metrics,
				cursorPath,
				"bborbe",
				cycleFilter,
			)
			ghClient.ListReposReturns([]pkg.Repo{
				{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
			}, nil)
			ghClient.GetGoModReturns([]byte("module example.com/x\n"), nil)
			ghClient.GetMaintainerConfigReturns(filter.GrantedConsent, nil)
			scanner.ScanReturns(pkg.ScanResult{
				HeadSHA: strings.Repeat("a", 40),
				VulnIDs: []string{"GO-2024-1234"},
			}, nil)

			Expect(watcher.Poll(ctx, false)).To(Succeed())
			Expect(gatherMetricValue(registry, "github_vuln_watcher_published_total",
				map[string]string{"status": "error"})).To(Equal(1.0))

			data, err := os.ReadFile(cursorPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(data)).NotTo(ContainSubstring("last_emitted_task_identifier"))

			Expect(watcher.Poll(ctx, false)).To(Succeed())
			Expect(sender.SendCommandCallCount()).To(Equal(2))
		},
	)

	ginkgo.It("counts scan_error when the cursor cannot be saved", func() {
		badPath := filepath.Join(
			ginkgo.GinkgoT().TempDir(),
			"nonexistent-dir",
			"cursor.json",
		)
		watcher = pkg.NewWatcher(
			ghClient, scanner, publisher, metrics, badPath, "bborbe", cycleFilter,
		)

		Expect(watcher.Poll(ctx, false)).To(Succeed())
		Expect(gatherMetricValue(registry, "github_vuln_watcher_poll_cycle_total",
			map[string]string{"result": "scan_error"})).To(Equal(1.0))
	})
})
