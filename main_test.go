// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main_test

import (
	"os"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/gexec"

	"github.com/bborbe/github-vuln-watcher/pkg"
)

var _ = Describe("Main", func() {
	It("Compiles", func() {
		var err error
		_, err = gexec.Build(".", "-mod=mod", "-buildvcs=false")
		Expect(err).NotTo(HaveOccurred())
	})

	It("defaults the cursor path to the PVC mount point", func() {
		Expect(pkg.DefaultCursorPath).To(Equal("/data/cursor.json"))
	})

	It("does not declare the removed scaffold flags", func() {
		source, err := os.ReadFile("main.go")
		Expect(err).NotTo(HaveOccurred())
		text := string(source)
		Expect(text).NotTo(ContainSubstring("DATADIR"))
		Expect(text).NotTo(ContainSubstring("BATCH_SIZE"))
		Expect(text).To(ContainSubstring(`default:"12h"`))
	})

	It("wires the scan token source into the watcher", func() {
		source, err := os.ReadFile("main.go")
		Expect(err).NotTo(HaveOccurred())
		text := string(source)
		Expect(text).To(ContainSubstring("tokenSource := auth.NewTokenSource(creds)"))
		Expect(text).To(MatchRegexp(`(?s)CreateWatcher\(.*?tokenSource,\s*\)`))
	})

	It("passes the configured target vault into the watcher factory", func() {
		source, err := os.ReadFile("main.go")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(source)).
			To(MatchRegexp(`(?s)CreateWatcher\(.*?a\.TargetVault.*?tokenSource,\s*\)`))
	})

	It("names the configured target vault in the startup log", func() {
		source, err := os.ReadFile("main.go")
		Expect(err).NotTo(HaveOccurred())
		text := string(source)
		Expect(text).To(ContainSubstring("vault=%s"))
		Expect(text).To(MatchRegexp(`(?s)Infof\([^)]*vault=%s[^)]*a\.TargetVault[^)]*\)`))
	})
})

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6@v6.12.2 -generate
func TestSuite(t *testing.T) {
	time.Local = time.UTC
	format.TruncatedDiff = false
	RegisterFailHandler(Fail)
	suiteConfig, reporterConfig := GinkgoConfiguration()
	suiteConfig.Timeout = 60 * time.Second
	RunSpecs(t, "Main Suite", suiteConfig, reporterConfig)
}
