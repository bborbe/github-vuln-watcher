// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg_test

import (
	"context"
	stderrors "errors"
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
		ghClient    *mocks.GitHubClient
		scanner     *mocks.Scanner
		cycleFilter filter.TaskCreationFilter
	)

	ginkgo.BeforeEach(func() {
		ctx = context.Background()
		registry = prometheus.NewRegistry()
		ghClient = &mocks.GitHubClient{}
		scanner = &mocks.Scanner{}
		cycleFilter = filter.TaskCreationFilterList{
			filter.NewRepoAllowlistFilter(nil),
			filter.NewAutoUpdateFilter(),
			filter.NewGoModPresentFilter(),
		}
		watcher = pkg.NewWatcher(
			ghClient,
			scanner,
			pkg.NewMetrics(registry),
			"/tmp/cursor.json",
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
})
