// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bborbe/agent/command/task"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bborbe/github-vuln-watcher/mocks"
	"github.com/bborbe/github-vuln-watcher/pkg"
	"github.com/bborbe/github-vuln-watcher/pkg/factory"
	"github.com/bborbe/github-vuln-watcher/pkg/filter"
)

// writeDispatchFixtureRepo creates a real git repo at a temp path.
// maintainer is written to .maintainer.yaml (skip by passing ""); markers is
// the vuln-marker list the repo's own `make vulncheck` gate prints before
// exiting 1 (empty list = gate exits 0).
func writeDispatchFixtureRepo(
	name string,
	maintainer string,
	markers []string,
) string {
	dir := filepath.Join(GinkgoT().TempDir(), name)
	Expect(os.MkdirAll(dir, 0o755)).To(Succeed())
	if maintainer != "" {
		Expect(os.WriteFile(
			filepath.Join(dir, ".maintainer.yaml"),
			[]byte(maintainer), 0o644,
		)).To(Succeed())
	}
	Expect(os.WriteFile(
		filepath.Join(dir, "go.mod"),
		[]byte("module example.com/fixture\n\ngo 1.24.0\n"), 0o644,
	)).To(Succeed())
	var vulncheck string
	if len(markers) == 0 {
		vulncheck = "vulncheck:\n\t@echo \"no vulns\"\n"
	} else {
		var b strings.Builder
		b.WriteString("vulncheck:\n")
		for _, m := range markers {
			fmt.Fprintf(&b,
				"\t@echo \"%s\\tgithub.com/example/mod@v1.0.0 -> v1.0.1\\tsummary\"\n",
				m)
		}
		b.WriteString("\t@exit 1\n")
		vulncheck = b.String()
	}
	makefile := vulncheck + "check:\n\t@echo \"check ok\"\n"
	Expect(os.WriteFile(
		filepath.Join(dir, "Makefile"),
		[]byte(makefile), 0o644,
	)).To(Succeed())
	runGit := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
		out, err := cmd.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), "git %v: %s", args, out)
	}
	runGit("init", "-b", "master")
	runGit("add", ".")
	runGit("commit", "-m", "init")
	return dir
}

func metricValue(reg *prometheus.Registry, name string, labels map[string]string) float64 {
	mfs, err := reg.Gather()
	Expect(err).NotTo(HaveOccurred())
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			match := true
			for _, lp := range m.GetLabel() {
				if labels[lp.GetName()] != lp.GetValue() {
					match = false
				}
			}
			if match {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

type dispatchHarness struct {
	watcher    pkg.Watcher
	scanner    *mocks.Scanner
	sent       []task.CreateCommand
	cursorPath string
	scanRoot   string
	registry   *prometheus.Registry
	metrics    pkg.Metrics
}

func newDispatchHarness(repos []pkg.Repo, allowlist []string) *dispatchHarness {
	registry := prometheus.NewRegistry()
	metrics := pkg.NewMetrics(registry)
	h := &dispatchHarness{
		cursorPath: filepath.Join(GinkgoT().TempDir(), "cursor.json"),
		scanRoot:   filepath.Join(GinkgoT().TempDir(), "scans"),
		registry:   registry,
		metrics:    metrics,
	}
	Expect(os.MkdirAll(h.scanRoot, 0o750)).To(Succeed())

	ghClient := &mocks.GitHubClient{}
	ghClient.ListReposReturns(repos, nil)
	ghClient.GetGoModStub = func(_ context.Context, _ pkg.Repo) ([]byte, error) {
		return []byte("module example.com/fixture\n\ngo 1.24.0\n"), nil
	}
	ghClient.GetMaintainerConfigStub = func(
		_ context.Context,
		repo pkg.Repo,
	) (filter.Consent, error) {
		switch repo.Name {
		case "fixture-repo":
			return filter.GrantedConsent, nil
		case "opted-out-repo":
			return filter.RefusedConsent, nil
		default:
			return filter.UndecidedConsent, nil
		}
	}

	realScanner := pkg.NewScanner(time.Minute, h.scanRoot, []string{"vulncheck", "check"})
	h.scanner = &mocks.Scanner{}
	h.scanner.ScanStub = realScanner.Scan // real clone + real make, call-counted

	sender := &mocks.CreateCommandSender{}
	sender.SendCommandStub = func(_ context.Context, cmd task.CreateCommand) error {
		h.sent = append(h.sent, cmd)
		return nil
	}
	publisher := pkg.NewTaskPublisher(sender, metrics, pkg.TaskConfig{Stage: "dev"})

	h.watcher = pkg.NewWatcher(
		ghClient,
		h.scanner,
		publisher,
		metrics,
		h.cursorPath,
		"fixture-owner",
		factory.CreateStaticFilters(allowlist),
	)
	return h
}

// BeforeSuite tees the GinkgoWriter to stdout so the fixture evidence lines
// printed via GinkgoWriter below are visible under `go test -v` (Ginkgo
// buffers the writer otherwise). Registered once — TeeTo accumulates writers,
// so calling it per-spec would duplicate every evidence line.
var _ = BeforeSuite(func() {
	GinkgoWriter.TeeTo(os.Stdout)
})

var _ = Describe("dispatch round-trip", func() {
	var (
		h          *dispatchHarness
		fixtureDir string
	)

	BeforeEach(func() {
		fixtureDir = writeDispatchFixtureRepo(
			"fixture-repo",
			"goUpdate:\n  autoUpdate: true\n",
			[]string{"GO-2024-1234", "GO-2024-5678"},
		)
		repo := pkg.Repo{
			Owner: "fixture-owner", Name: "fixture-repo", DefaultBranch: "master",
			CloneURL: fixtureDir,
		}
		h = newDispatchHarness([]pkg.Repo{repo}, nil)
	})

	It("publishes exactly one create-task per finding set and dedups the next cycle", func() {
		Expect(h.watcher.Poll(context.Background(), false)).To(Succeed())

		Expect(h.sent).To(HaveLen(1))
		cmd := h.sent[0]
		Expect(cmd.Frontmatter).To(HaveLen(12))
		Expect(cmd.Frontmatter["task_type"]).To(Equal("github-update-go"))
		Expect(cmd.Frontmatter["assignee"]).To(Equal("github-update-go-agent"))
		Expect(cmd.Frontmatter["phase"]).To(Equal("planning"))
		Expect(cmd.Frontmatter["status"]).To(Equal("in_progress"))
		Expect(cmd.Frontmatter["stage"]).To(Equal("dev"))
		Expect(cmd.Frontmatter["repo"]).To(Equal("fixture-owner/fixture-repo"))
		Expect(cmd.Frontmatter["clone_url"]).
			To(Equal("git@github.com:fixture-owner/fixture-repo.git"))
		Expect(cmd.Frontmatter["vuln_count"]).To(Equal(2))

		ref, ok := cmd.Frontmatter["ref"].(string)
		Expect(ok).To(BeTrue())
		Expect(ref).To(MatchRegexp(`^[0-9a-f]{40}$`))
		headCmd := exec.Command("git", "-C", fixtureDir, "rev-parse", "HEAD")
		headOut, err := headCmd.Output()
		Expect(err).NotTo(HaveOccurred())
		Expect(ref).To(Equal(strings.TrimSpace(string(headOut))))

		Expect(cmd.Frontmatter["vulns"]).
			To(Equal([]string{"GO-2024-1234", "GO-2024-5678"}))

		taskID, ok := cmd.Frontmatter["task_identifier"].(string)
		Expect(ok).To(BeTrue())
		Expect(taskID).To(MatchRegexp(
			`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
		))
		Expect(taskID[14]).To(Equal(uint8('5')))

		Expect(cmd.Validate(context.Background())).To(Succeed())

		Expect(cmd.Title).
			To(Equal("Update Go fixture-owner-fixture-repo " + ref[:7]))
		Expect(cmd.Title).NotTo(ContainSubstring("/"))

		Expect(cmd.Body).To(ContainSubstring("# Update Go: fixture-owner/fixture-repo"))
		Expect(cmd.Body).To(ContainSubstring(
			"**Vulnerabilities:** GO-2024-1234  ·  GO-2024-5678"))
		Expect(cmd.Body).To(ContainSubstring("**HEAD:** " + ref[:7]))
		Expect(cmd.Body).To(ContainSubstring(
			"**Repo:** [fixture-owner/fixture-repo](https://github.com/fixture-owner/fixture-repo)",
		))

		Expect(metricValue(h.registry, "github_vuln_watcher_published_total",
			map[string]string{"status": "create"})).To(Equal(1.0))
		Expect(metricValue(h.registry, "github_vuln_watcher_vulns_detected_total", nil)).
			To(Equal(2.0))
		Expect(metricValue(h.registry, "github_vuln_watcher_poll_cycle_total",
			map[string]string{"result": "success"})).To(Equal(1.0))

		data, err := os.ReadFile(h.cursorPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(data)).To(ContainSubstring("last_emitted_task_identifier"))

		entries, err := os.ReadDir(h.scanRoot)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(BeEmpty())

		Expect(h.watcher.Poll(context.Background(), false)).To(Succeed())
		Expect(h.sent).To(HaveLen(1))
		Expect(metricValue(h.registry, "github_vuln_watcher_filter_skipped_total",
			map[string]string{"reason": "finding_set_unchanged"})).To(Equal(1.0))
		Expect(metricValue(h.registry, "github_vuln_watcher_published_total",
			map[string]string{"status": "create"})).To(Equal(1.0))

		Expect(os.WriteFile(h.cursorPath, []byte("{not json"), 0o600)).To(Succeed())
		Expect(h.watcher.Poll(context.Background(), false)).To(Succeed())
		Expect(h.cursorPath + ".corrupt").To(BeAnExistingFile())
		Expect(metricValue(h.registry, "github_vuln_watcher_poll_cycle_total",
			map[string]string{"result": "success"})).To(Equal(3.0))

		GinkgoWriter.Printf("fixture vuln marker: %v\n", cmd.Frontmatter["vulns"])
		GinkgoWriter.Printf("filter_skipped_total finding_set_unchanged=%v\n",
			metricValue(h.registry, "github_vuln_watcher_filter_skipped_total",
				map[string]string{"reason": "finding_set_unchanged"}))
	})

	It("re-files an unchanged finding set on a forced cycle", func() {
		Expect(h.watcher.Poll(context.Background(), false)).To(Succeed())
		Expect(h.sent).To(HaveLen(1))

		Expect(h.watcher.Poll(context.Background(), true)).To(Succeed())
		Expect(h.sent).To(HaveLen(2))
		Expect(metricValue(h.registry, "github_vuln_watcher_filter_skipped_total",
			map[string]string{"reason": "finding_set_unchanged"})).To(Equal(0.0))
	})
})

var _ = Describe("pre-clone inventory gates", func() {
	var h *dispatchHarness

	BeforeEach(func() {
		allowlist := filter.ParseRepoAllowlist(
			"github.com/fixture-owner/fixture-repo," +
				"github.com/fixture-owner/no-maintainer-repo," +
				"github.com/fixture-owner/opted-out-repo",
		)
		repos := []pkg.Repo{
			{
				Owner: "fixture-owner", Name: "fixture-repo",
				DefaultBranch: "master",
				CloneURL: writeDispatchFixtureRepo(
					"fixture-repo",
					"goUpdate:\n  autoUpdate: true\n",
					[]string{"GO-2024-1234", "GO-2024-5678"},
				),
			},
			{
				Owner: "fixture-owner", Name: "no-maintainer-repo",
				DefaultBranch: "master",
				CloneURL:      writeDispatchFixtureRepo("no-maintainer-repo", "", nil),
			},
			{
				Owner: "fixture-owner", Name: "opted-out-repo",
				DefaultBranch: "master",
				CloneURL: writeDispatchFixtureRepo(
					"opted-out-repo",
					"goUpdate:\n  autoUpdate: false\n",
					nil,
				),
			},
			{
				Owner: "fixture-owner", Name: "out-of-scope-repo",
				DefaultBranch: "master",
				CloneURL: writeDispatchFixtureRepo(
					"out-of-scope-repo",
					"goUpdate:\n  autoUpdate: true\n",
					nil,
				),
			},
		}
		h = newDispatchHarness(repos, allowlist)
	})

	It("skips ineligible repos before any clone with the named reasons", func() {
		Expect(h.watcher.Poll(context.Background(), false)).To(Succeed())

		Expect(metricValue(h.registry, "github_vuln_watcher_filter_skipped_total",
			map[string]string{"reason": "auto_update_disabled"})).To(Equal(2.0))
		Expect(metricValue(h.registry, "github_vuln_watcher_filter_skipped_total",
			map[string]string{"reason": "scope"})).To(Equal(1.0))
		Expect(metricValue(h.registry, "github_vuln_watcher_filter_skipped_total",
			map[string]string{"reason": "no_gomod"})).To(Equal(0.0))

		Expect(h.scanner.ScanCallCount()).To(Equal(1))
		_, scannedRepo := h.scanner.ScanArgsForCall(0)
		Expect(scannedRepo.Key()).To(Equal("github.com/fixture-owner/fixture-repo"))

		Expect(h.sent).To(HaveLen(1))
		Expect(metricValue(h.registry, "github_vuln_watcher_published_total",
			map[string]string{"status": "create"})).To(Equal(1.0))

		GinkgoWriter.Printf("filter_skipped_total auto_update_disabled=%v scope=%v\n",
			metricValue(h.registry, "github_vuln_watcher_filter_skipped_total",
				map[string]string{"reason": "auto_update_disabled"}),
			metricValue(h.registry, "github_vuln_watcher_filter_skipped_total",
				map[string]string{"reason": "scope"}))
	})
})
