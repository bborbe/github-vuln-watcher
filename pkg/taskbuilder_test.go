// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg_test

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/bborbe/github-vuln-watcher/pkg"
)

var _ = ginkgo.Describe("BuildCreateCommand", func() {
	headSHA := "0123456789abcdef0123456789abcdef01234567"

	fixedCandidate := func() pkg.Candidate {
		return pkg.Candidate{
			Repo:    pkg.Repo{Owner: "bborbe", Name: "demo", DefaultBranch: "master"},
			HeadSHA: headSHA,
			VulnIDs: []string{"GO-2024-1234", "GO-2024-5678"},
		}
	}

	ginkgo.It("emits exactly the frozen 12-key frontmatter contract", func() {
		cmd := pkg.BuildCreateCommand(fixedCandidate(), pkg.TaskConfig{Stage: "dev"})
		Expect(cmd.Frontmatter).To(HaveLen(12))
	})

	ginkgo.It("passes the CreateCommand validator", func() {
		cmd := pkg.BuildCreateCommand(fixedCandidate(), pkg.TaskConfig{Stage: "dev"})
		Expect(cmd.Validate(context.Background())).To(Succeed())
	})

	ginkgo.It("stamps the 10 consumer keys byte-identical to the sibling", func() {
		cmd := pkg.BuildCreateCommand(fixedCandidate(), pkg.TaskConfig{Stage: "dev"})
		Expect(cmd.Frontmatter["task_type"]).To(Equal("github-update-go"))
		Expect(cmd.Frontmatter["assignee"]).To(Equal("github-update-go-agent"))
		Expect(cmd.Frontmatter["phase"]).To(Equal("planning"))
		Expect(cmd.Frontmatter["status"]).To(Equal("in_progress"))
		Expect(cmd.Frontmatter["stage"]).To(Equal("dev"))
		Expect(cmd.Frontmatter["repo"]).To(Equal("bborbe/demo"))
		Expect(cmd.Frontmatter["clone_url"]).
			To(Equal("git@github.com:bborbe/demo.git"))
		Expect(cmd.Frontmatter["ref"]).To(Equal(headSHA))
		Expect(cmd.Frontmatter["vuln_count"]).To(Equal(2))
		Expect(cmd.Frontmatter["vulns"]).
			To(Equal([]string{"GO-2024-1234", "GO-2024-5678"}))
	})

	ginkgo.It("derives a UUID5 task identifier in the frontmatter", func() {
		cmd := pkg.BuildCreateCommand(fixedCandidate(), pkg.TaskConfig{Stage: "dev"})
		taskIDStr, ok := cmd.Frontmatter["task_identifier"].(string)
		Expect(ok).To(BeTrue())
		taskID := uuid.MustParse(taskIDStr)
		Expect(taskID.Version().String()).To(Equal("VERSION_5"))
	})

	ginkgo.It("uses the frozen dash-form title in both title and frontmatter", func() {
		cmd := pkg.BuildCreateCommand(fixedCandidate(), pkg.TaskConfig{Stage: "dev"})
		Expect(cmd.Frontmatter["title"]).To(Equal("Update Go bborbe-demo 0123456"))
		Expect(cmd.Frontmatter["title"]).To(Equal(cmd.Title))
		Expect(strings.Contains(cmd.Title, "/")).To(BeFalse())
	})

	ginkgo.It("builds the frozen body byte-identically", func() {
		cmd := pkg.BuildCreateCommand(fixedCandidate(), pkg.TaskConfig{Stage: "dev"})
		Expect(cmd.Body).To(Equal(
			"# Update Go: bborbe/demo\n\n" +
				"**Vulnerabilities:** GO-2024-1234  ·  GO-2024-5678\n" +
				"**HEAD:** 0123456\n" +
				"**Repo:** [bborbe/demo](https://github.com/bborbe/demo)\n",
		))
	})

	ginkgo.It("emits a single-marker vuln line without a middot", func() {
		c := fixedCandidate()
		c.VulnIDs = []string{"GO-2024-1234"}
		cmd := pkg.BuildCreateCommand(c, pkg.TaskConfig{Stage: "dev"})
		Expect(cmd.Body).To(ContainSubstring(
			"**Vulnerabilities:** GO-2024-1234\n",
		))
	})

	ginkgo.It("is deterministic across repeated builds", func() {
		a := pkg.BuildCreateCommand(fixedCandidate(), pkg.TaskConfig{Stage: "dev"})
		b := pkg.BuildCreateCommand(fixedCandidate(), pkg.TaskConfig{Stage: "dev"})
		Expect(a).To(Equal(b))
	})

	ginkgo.It("stamps the stage config from the task config", func() {
		cmd := pkg.BuildCreateCommand(fixedCandidate(), pkg.TaskConfig{Stage: "prod"})
		Expect(cmd.Frontmatter["stage"]).To(Equal("prod"))
	})
})
