// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg_test

import (
	"context"
	stderrors "errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/bborbe/github-vuln-watcher/pkg"
)

// writeFixtureRepo creates a real git repo at a temp path whose Makefile is
// exactly makefile. Returns the repo path (usable as a Repo.CloneURL).
func writeFixtureRepo(makefile string) string {
	dir := filepath.Join(ginkgo.GinkgoT().TempDir(), "fixture")
	Expect(os.MkdirAll(dir, 0o755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.com/fixture\n\ngo 1.24.0\n"), 0o644)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "Makefile"),
		[]byte(makefile), 0o644)).To(Succeed())
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

var _ = ginkgo.Describe("Scanner", func() {
	var (
		ctx         context.Context
		gateTimeout time.Duration
		tempDir     string
		scanner     pkg.Scanner
	)

	ginkgo.BeforeEach(func() {
		ctx = context.Background()
		gateTimeout = 60 * time.Second
		tempDir = ""
	})

	ginkgo.JustBeforeEach(func() {
		scanner = pkg.NewScanner(gateTimeout, tempDir)
	})

	ginkgo.It(
		"returns the canonical marker list from a repo whose vulncheck gate exits 1",
		func() {
			dir := writeFixtureRepo(
				"vulncheck:\n" +
					"\t@echo \"GO-2024-5678\\tgithub.com/example/mod2@v1.2.0 -> v1.2.1\\tsummary\"\n" +
					"\t@echo \"GO-2024-1234\\tgithub.com/example/mod@v1.0.0 -> v1.0.1\\tsummary\"\n" +
					"\t@exit 1\n" +
					"check:\n" +
					"\t@echo \"check ok\"\n",
			)
			result, err := scanner.Scan(ctx, pkg.Repo{
				Owner:    "fixture-owner",
				Name:     "fixture-repo",
				CloneURL: dir,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.VulnIDs).To(Equal([]string{"GO-2024-1234", "GO-2024-5678"}))
			Expect(result.HeadSHA).To(MatchRegexp(`^[0-9a-f]{40}$`))
		},
	)

	ginkgo.It("extracts CVE markers too", func() {
		dir := writeFixtureRepo(
			"vulncheck:\n" +
				"\t@echo \"CVE-2025-1234\\tgithub.com/example/mod@v1.0.0\\tsummary\"\n" +
				"\t@exit 1\n" +
				"check:\n" +
				"\t@echo \"check ok\"\n",
		)
		result, err := scanner.Scan(ctx, pkg.Repo{Owner: "o", Name: "n", CloneURL: dir})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.VulnIDs).To(Equal([]string{"CVE-2025-1234"}))
	})

	ginkgo.It("dedupes repeated markers", func() {
		dir := writeFixtureRepo(
			"vulncheck:\n" +
				"\t@echo \"GO-2024-5678\\tgithub.com/example/mod@v1.2.0 -> v1.2.1\\tsummary\"\n" +
				"\t@echo \"GO-2024-5678\\tgithub.com/example/mod@v1.2.0 -> v1.2.1\\tsummary\"\n" +
				"\t@exit 1\n" +
				"check:\n" +
				"\t@echo \"check ok\"\n",
		)
		result, err := scanner.Scan(ctx, pkg.Repo{Owner: "o", Name: "n", CloneURL: dir})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.VulnIDs).To(Equal([]string{"GO-2024-5678"}))
	})

	ginkgo.It("already_clean when both gates are green", func() {
		dir := writeFixtureRepo(
			"vulncheck:\n" +
				"\t@echo \"no vulns\"\n" +
				"check:\n" +
				"\t@echo \"check ok\"\n",
		)
		result, err := scanner.Scan(ctx, pkg.Repo{Owner: "o", Name: "n", CloneURL: dir})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.VulnIDs).To(BeEmpty())
		Expect(result.HeadSHA).To(BeEmpty())
	})

	ginkgo.It("scan_failed on a red gate with no markers", func() {
		dir := writeFixtureRepo(
			"vulncheck:\n" +
				"\t@echo \"lint error\"\n" +
				"\t@exit 1\n" +
				"check:\n" +
				"\t@echo \"check ok\"\n",
		)
		_, err := scanner.Scan(ctx, pkg.Repo{Owner: "o", Name: "n", CloneURL: dir})
		Expect(stderrors.Is(err, pkg.ErrScanFailed)).To(BeTrue())
	})

	ginkgo.It("scan_failed when a make target is missing", func() {
		dir := writeFixtureRepo(
			"check:\n" +
				"\t@echo \"check ok\"\n",
		)
		_, err := scanner.Scan(ctx, pkg.Repo{Owner: "o", Name: "n", CloneURL: dir})
		Expect(stderrors.Is(err, pkg.ErrScanFailed)).To(BeTrue())
	})

	ginkgo.It("clone_failed on a bad clone URL", func() {
		_, err := scanner.Scan(ctx, pkg.Repo{
			CloneURL: filepath.Join(ginkgo.GinkgoT().TempDir(), "does-not-exist"),
		})
		Expect(stderrors.Is(err, pkg.ErrCloneFailed)).To(BeTrue())
	})

	ginkgo.Context("with a short gate timeout", func() {
		ginkgo.BeforeEach(func() {
			gateTimeout = 100 * time.Millisecond
		})

		ginkgo.It("gate_timeout kills a hanging gate", func() {
			dir := writeFixtureRepo(
				"vulncheck:\n" +
					"\t@sleep 100\n" +
					"check:\n" +
					"\t@echo \"check ok\"\n",
			)
			_, err := scanner.Scan(ctx, pkg.Repo{Owner: "o", Name: "n", CloneURL: dir})
			Expect(stderrors.Is(err, pkg.ErrGateTimeout)).To(BeTrue())
		})
	})

	ginkgo.Context("with a dedicated temp root", func() {
		var tempRoot string

		ginkgo.BeforeEach(func() {
			tempRoot = filepath.Join(ginkgo.GinkgoT().TempDir(), "scans")
			Expect(os.MkdirAll(tempRoot, 0o755)).To(Succeed())
			tempDir = tempRoot
		})

		ginkgo.It("removes the clone directory after the scan", func() {
			dir := writeFixtureRepo(
				"vulncheck:\n" +
					"\t@echo \"no vulns\"\n" +
					"check:\n" +
					"\t@echo \"check ok\"\n",
			)
			_, err := scanner.Scan(ctx, pkg.Repo{Owner: "o", Name: "n", CloneURL: dir})
			Expect(err).NotTo(HaveOccurred())
			entries, err := os.ReadDir(tempRoot)
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(BeEmpty())
		})
	})

	ginkgo.It("gate subprocess sees only the allowlisted environment", func() {
		ginkgo.GinkgoT().Setenv("VULN_WATCHER_SECRET", "s3cr3t")
		dir := writeFixtureRepo(
			"vulncheck:\n" +
				"\t@test -z \"$$VULN_WATCHER_SECRET\" && echo \"no-secret-leak\"\n" +
				"check:\n" +
				"\t@echo \"check ok\"\n",
		)
		result, err := scanner.Scan(ctx, pkg.Repo{Owner: "o", Name: "n", CloneURL: dir})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.VulnIDs).To(BeEmpty())
	})
})
