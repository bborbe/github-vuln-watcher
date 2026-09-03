// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg_test

import (
	"context"
	"os"
	"path/filepath"

	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/bborbe/github-vuln-watcher/pkg"
)

var _ = ginkgo.Describe("Cursor", func() {
	var (
		ctx  context.Context
		path string
	)

	ginkgo.BeforeEach(func() {
		ctx = context.Background()
		path = filepath.Join(ginkgo.GinkgoT().TempDir(), "cursor.json")
	})

	ginkgo.It("round-trips the Repos map through Save then Load", func() {
		c := &pkg.Cursor{
			Repos: map[string]*pkg.RepoState{
				"github.com/bborbe/repo-a": {
					LastEmittedTaskIdentifier: "a1b2c3d4-e5f6-4a5b-8c9d-0123456789ab",
				},
			},
		}
		Expect(pkg.SaveCursor(ctx, path, c)).To(Succeed())

		loaded, err := pkg.LoadCursor(ctx, path)
		Expect(err).NotTo(HaveOccurred())
		Expect(loaded.Repos).To(HaveLen(1))
		Expect(loaded.Repos["github.com/bborbe/repo-a"].LastEmittedTaskIdentifier).
			To(Equal("a1b2c3d4-e5f6-4a5b-8c9d-0123456789ab"))
	})

	ginkgo.It("cold-starts with an empty non-nil map when the file is missing", func() {
		c, err := pkg.LoadCursor(ctx, path)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Repos).NotTo(BeNil())
		Expect(c.Repos).To(BeEmpty())
	})

	ginkgo.It("renames corrupt JSON to <path>.corrupt and cold-starts", func() {
		Expect(os.WriteFile(path, []byte("{not json"), 0o600)).To(Succeed())

		c, err := pkg.LoadCursor(ctx, path)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Repos).NotTo(BeNil())
		Expect(c.Repos).To(BeEmpty())
		Expect(path + ".corrupt").To(BeAnExistingFile())
	})

	ginkgo.It("errors when the path is a directory (unreadable)", func() {
		dir := filepath.Join(ginkgo.GinkgoT().TempDir(), "cursor-dir")
		Expect(os.MkdirAll(dir, 0o750)).To(Succeed())

		_, err := pkg.LoadCursor(ctx, dir)
		Expect(err).To(HaveOccurred())
	})

	ginkgo.It("leaves no .tmp file after a successful save", func() {
		c := &pkg.Cursor{Repos: map[string]*pkg.RepoState{}}
		Expect(pkg.SaveCursor(ctx, path, c)).To(Succeed())
		Expect(path + ".tmp").NotTo(BeAnExistingFile())
	})

	ginkgo.It("errors when the rename fails and removes the tmp file", func() {
		dir := filepath.Join(ginkgo.GinkgoT().TempDir(), "cursor-target-dir")
		Expect(os.MkdirAll(dir, 0o750)).To(Succeed())

		c := &pkg.Cursor{Repos: map[string]*pkg.RepoState{}}
		Expect(pkg.SaveCursor(ctx, dir, c)).To(HaveOccurred())
		Expect(dir + ".tmp").NotTo(BeAnExistingFile())
	})
})
