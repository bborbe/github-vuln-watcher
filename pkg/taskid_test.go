// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg_test

import (
	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/bborbe/github-vuln-watcher/pkg"
)

var _ = ginkgo.Describe("DeriveVulnTaskID", func() {
	baseIDs := []string{"GO-2024-1234", "GO-2024-5678", "CVE-2024-9999"}

	ginkgo.It("returns an identical UUID for the same (owner, repo, ids) twice", func() {
		a := pkg.DeriveVulnTaskID("bborbe", "demo", baseIDs)
		b := pkg.DeriveVulnTaskID("bborbe", "demo", baseIDs)
		Expect(a).To(Equal(b))
	})

	ginkgo.It("is order-insensitive across the vuln ID list", func() {
		reordered := []string{"CVE-2024-9999", "GO-2024-1234", "GO-2024-5678"}
		Expect(pkg.DeriveVulnTaskID("bborbe", "demo", baseIDs)).
			To(Equal(pkg.DeriveVulnTaskID("bborbe", "demo", reordered)))
	})

	ginkgo.It("is insensitive to duplicate vuln IDs (deduped internally)", func() {
		duplicated := []string{
			"GO-2024-1234",
			"GO-2024-5678",
			"CVE-2024-9999",
			"GO-2024-1234",
		}
		Expect(pkg.DeriveVulnTaskID("bborbe", "demo", baseIDs)).
			To(Equal(pkg.DeriveVulnTaskID("bborbe", "demo", duplicated)))
	})

	ginkgo.It("changes when a different vuln ID is in the list", func() {
		other := []string{"GO-2024-1234", "GO-2024-5678", "CVE-2024-0001"}
		Expect(pkg.DeriveVulnTaskID("bborbe", "demo", baseIDs)).
			NotTo(Equal(pkg.DeriveVulnTaskID("bborbe", "demo", other)))
	})

	ginkgo.It("changes when the repo differs", func() {
		Expect(pkg.DeriveVulnTaskID("bborbe", "demo", baseIDs)).
			NotTo(Equal(pkg.DeriveVulnTaskID("bborbe", "other", baseIDs)))
	})

	ginkgo.It("changes when the owner differs", func() {
		Expect(pkg.DeriveVulnTaskID("bborbe", "demo", baseIDs)).
			NotTo(Equal(pkg.DeriveVulnTaskID("acme", "demo", baseIDs)))
	})

	ginkgo.It("produces a UUID5", func() {
		Expect(pkg.DeriveVulnTaskID("bborbe", "demo", baseIDs).Version().String()).
			To(Equal("VERSION_5"))
	})

	ginkgo.It(
		"does not involve the HEAD SHA: repeated calls over the same ids agree",
		func() {
			// DeriveVulnTaskID takes no sha argument — the seed is (repo,
			// sorted vuln ids) only, so an unchanged finding set must always
			// yield the same identifier.
			Expect(pkg.DeriveVulnTaskID("bborbe", "demo", baseIDs)).
				To(Equal(pkg.DeriveVulnTaskID("bborbe", "demo", baseIDs)))
		},
	)
})
