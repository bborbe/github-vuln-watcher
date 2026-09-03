// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filter_test

import (
	"context"

	"github.com/bborbe/maintainer/repoallowlist"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/bborbe/github-vuln-watcher/pkg/filter"
)

var _ = Describe("NewRepoAllowlistFilter", func() {
	It("skips a candidate outside the allowlist with scope", func() {
		f := filter.NewRepoAllowlistFilter([]string{"github.com/bborbe/a"})
		Expect(f.Skip(filter.Candidate{RepoKey: "github.com/bborbe/b"})).To(Equal("scope"))
	})

	It("passes a candidate inside the allowlist", func() {
		f := filter.NewRepoAllowlistFilter([]string{"github.com/bborbe/a"})
		Expect(f.Skip(filter.Candidate{RepoKey: "github.com/bborbe/a"})).To(Equal(""))
	})

	It("an empty allowlist allows everything through", func() {
		f := filter.NewRepoAllowlistFilter(nil)
		Expect(f.Skip(filter.Candidate{RepoKey: "github.com/bborbe/a"})).To(Equal(""))
	})
})

var _ = Describe("ParseRepoAllowlist", func() {
	It("splits, trims and drops empty entries", func() {
		Expect(filter.ParseRepoAllowlist("github.com/bborbe/a, github.com/bborbe/b ,, ")).
			To(Equal([]string{"github.com/bborbe/a", "github.com/bborbe/b"}))
	})

	It("returns nil on empty input", func() {
		Expect(filter.ParseRepoAllowlist("")).To(BeNil())
	})

	It("validates clean entries with the library validator", func() {
		ctx := context.Background()
		allowlist := filter.ParseRepoAllowlist("github.com/bborbe/a, github.com/bborbe/b")
		Expect(repoallowlist.Validate(ctx, allowlist)).To(Succeed())
	})

	It("rejects malformed entries with the library validator", func() {
		ctx := context.Background()
		allowlist := filter.ParseRepoAllowlist("github.com/bborbe/a, github.com/*/*")
		Expect(repoallowlist.Validate(ctx, allowlist)).To(HaveOccurred())
	})
})

var _ = Describe("NewAutoUpdateFilter", func() {
	It("passes an explicitly granted consent", func() {
		f := filter.NewAutoUpdateFilter()
		Expect(f.Skip(filter.Candidate{Consent: filter.GrantedConsent})).To(Equal(""))
	})

	It("skips a refused consent with auto_update_disabled", func() {
		f := filter.NewAutoUpdateFilter()
		Expect(
			f.Skip(filter.Candidate{Consent: filter.RefusedConsent}),
		).To(Equal("auto_update_disabled"))
	})

	It("skips an undecided consent with auto_update_disabled", func() {
		f := filter.NewAutoUpdateFilter()
		Expect(
			f.Skip(filter.Candidate{Consent: filter.UndecidedConsent}),
		).To(Equal("auto_update_disabled"))
	})

	It("skips the zero-value consent with auto_update_disabled", func() {
		f := filter.NewAutoUpdateFilter()
		Expect(f.Skip(filter.Candidate{})).To(Equal("auto_update_disabled"))
	})
})

var _ = Describe("NewGoModPresentFilter", func() {
	It("skips a repo without go.mod with no_gomod", func() {
		f := filter.NewGoModPresentFilter()
		Expect(f.Skip(filter.Candidate{GoModPresent: false})).To(Equal("no_gomod"))
	})

	It("passes a repo with go.mod", func() {
		f := filter.NewGoModPresentFilter()
		Expect(f.Skip(filter.Candidate{GoModPresent: true})).To(Equal(""))
	})
})

var _ = Describe("TaskCreationFilterList", func() {
	It("short-circuits on the first non-empty reason", func() {
		list := filter.TaskCreationFilterList{
			filter.NewGoModPresentFilter(),
			filter.NewAutoUpdateFilter(),
		}
		// GoModPresent=false fires "no_gomod" before the consent gate is reached.
		Expect(list.Skip(filter.Candidate{GoModPresent: false, Consent: filter.GrantedConsent})).
			To(Equal("no_gomod"))
		// Consent gate fires when go.mod is present but consent is not granted.
		Expect(list.Skip(filter.Candidate{GoModPresent: true, Consent: filter.UndecidedConsent})).
			To(Equal("auto_update_disabled"))
	})

	It("an empty list never skips", func() {
		list := filter.TaskCreationFilterList{}
		Expect(list.Skip(filter.Candidate{})).To(Equal(""))
	})
})

// cursorReaderStub is a hand-written CursorReader fake for the filter unit
// tests — the production reader (pkg.NewCursorReader) is exercised by the
// watcher integration tests.
type cursorReaderStub struct {
	lastEmitted map[string]string
}

func (s *cursorReaderStub) LastEmittedTaskIdentifier(repoKey string) string {
	return s.lastEmitted[repoKey]
}

var _ = Describe("NewFindingSetUnchangedFilter", func() {
	var cursor *cursorReaderStub
	var f filter.TaskCreationFilter

	BeforeEach(func() {
		cursor = &cursorReaderStub{
			lastEmitted: map[string]string{
				"github.com/bborbe/repo-a": "11111111-2222-4333-8444-555555555555",
			},
		}
		f = filter.NewFindingSetUnchangedFilter(cursor)
	})

	It("skips a candidate whose task identifier equals the recorded one", func() {
		Expect(f.Skip(filter.Candidate{
			RepoKey:        "github.com/bborbe/repo-a",
			TaskIdentifier: "11111111-2222-4333-8444-555555555555",
		})).To(Equal("finding_set_unchanged"))
	})

	It("passes a candidate with a different task identifier", func() {
		Expect(f.Skip(filter.Candidate{
			RepoKey:        "github.com/bborbe/repo-a",
			TaskIdentifier: "99999999-8888-4777-8666-555555555555",
		})).To(Equal(""))
	})

	It("never skips on an empty task identifier", func() {
		Expect(f.Skip(filter.Candidate{
			RepoKey:        "github.com/bborbe/repo-a",
			TaskIdentifier: "",
		})).To(Equal(""))
	})

	It("passes a repo the cursor has never seen", func() {
		Expect(f.Skip(filter.Candidate{
			RepoKey:        "github.com/bborbe/repo-b",
			TaskIdentifier: "11111111-2222-4333-8444-555555555555",
		})).To(Equal(""))
	})
})

var _ = Describe("ParseConsent", func() {
	It("returns granted for explicit boolean true", func() {
		consent, err := filter.ParseConsent(context.Background(),
			[]byte("goUpdate:\n  autoUpdate: true\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(consent).To(Equal(filter.GrantedConsent))
	})

	It("returns refused for explicit boolean false", func() {
		consent, err := filter.ParseConsent(context.Background(),
			[]byte("goUpdate:\n  autoUpdate: false\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(consent).To(Equal(filter.RefusedConsent))
	})

	It("returns granted for True and TRUE", func() {
		for _, raw := range []string{"True", "TRUE"} {
			consent, err := filter.ParseConsent(context.Background(),
				[]byte("goUpdate:\n  autoUpdate: "+raw+"\n"))
			Expect(err).NotTo(HaveOccurred())
			Expect(consent).To(Equal(filter.GrantedConsent))
		}
	})

	It("returns undecided for a quoted string", func() {
		consent, err := filter.ParseConsent(context.Background(),
			[]byte("goUpdate:\n  autoUpdate: \"true\"\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(consent).To(Equal(filter.UndecidedConsent))
	})

	It("returns undecided for a YAML yes", func() {
		consent, err := filter.ParseConsent(context.Background(),
			[]byte("goUpdate:\n  autoUpdate: yes\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(consent).To(Equal(filter.UndecidedConsent))
	})

	It("returns undecided for an integer value", func() {
		consent, err := filter.ParseConsent(context.Background(),
			[]byte("goUpdate:\n  autoUpdate: 1\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(consent).To(Equal(filter.UndecidedConsent))
	})

	It("returns undecided for an empty document", func() {
		consent, err := filter.ParseConsent(context.Background(), []byte("\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(consent).To(Equal(filter.UndecidedConsent))
	})

	It("returns undecided when the goUpdate section is missing", func() {
		consent, err := filter.ParseConsent(context.Background(),
			[]byte("someOtherKey: value\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(consent).To(Equal(filter.UndecidedConsent))
	})

	It("returns an error for malformed YAML", func() {
		consent, err := filter.ParseConsent(context.Background(), []byte("{{{"))
		Expect(err).To(HaveOccurred())
		Expect(consent).To(Equal(filter.Consent("")))
	})

	It("returns undecided for empty bytes", func() {
		consent, err := filter.ParseConsent(context.Background(), nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(consent).To(Equal(filter.UndecidedConsent))
	})
})
