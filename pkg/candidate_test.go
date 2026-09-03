// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg_test

import (
	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/bborbe/github-vuln-watcher/pkg"
	"github.com/bborbe/github-vuln-watcher/pkg/filter"
)

var _ = ginkgo.Describe("Candidate", func() {
	ginkgo.It("ShortSHA returns the first 7 chars of a long HEAD SHA", func() {
		c := pkg.Candidate{HeadSHA: "0123456789abcdef"}
		Expect(c.ShortSHA()).To(Equal("0123456"))
	})

	ginkgo.It("ShortSHA returns the full value when shorter than 7 chars", func() {
		c := pkg.Candidate{HeadSHA: "abc"}
		Expect(c.ShortSHA()).To(Equal("abc"))
	})

	ginkgo.It("FilterCandidate projects RepoKey, HeadSHA, GoModPresent and Consent", func() {
		c := pkg.Candidate{
			Repo:         pkg.Repo{Owner: "bborbe", Name: "repo-a", DefaultBranch: "main"},
			HeadSHA:      "0123456789abcdef",
			GoModPresent: true,
			Consent:      filter.GrantedConsent,
		}
		fc := c.FilterCandidate()
		Expect(fc.RepoKey).To(Equal("github.com/bborbe/repo-a"))
		Expect(fc.HeadSHA).To(Equal("0123456789abcdef"))
		Expect(fc.GoModPresent).To(BeTrue())
		Expect(fc.Consent).To(Equal(filter.GrantedConsent))
		Expect(fc.TaskIdentifier).To(Equal(""))
	})
})
