// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package factory_test

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bborbe/github-vuln-watcher/mocks"
	"github.com/bborbe/github-vuln-watcher/pkg"
	"github.com/bborbe/github-vuln-watcher/pkg/factory"
	"github.com/bborbe/github-vuln-watcher/pkg/filter"
)

var _ = Describe("Factory", func() {
	It("registers exactly the expected route table", func() {
		ctx := context.Background()
		watcher := &mocks.Watcher{}
		gate := pkg.NewCycleGate()
		triggerHandler := factory.CreateTriggerHandler(ctx, watcher, gate)
		router := factory.CreateRouter(ctx, triggerHandler, nil)

		var paths []string
		err := router.Walk(
			func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
				path, err := route.GetPathTemplate()
				if err != nil {
					return err
				}
				paths = append(paths, path)
				return nil
			},
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(paths).To(ConsistOf(
			"/healthz",
			"/readiness",
			"/metrics",
			"/trigger",
			"/setloglevel/{level}",
			"/gc",
			"/testloglevel",
			"/sentryalert",
		))
		Expect(paths).NotTo(ContainElement("/resetdb"))
		Expect(paths).NotTo(ContainElement("/resetbucket/foo"))
	})

	It("CreateWatcher returns a non-nil Watcher", func() {
		watcher := factory.CreateWatcher(
			&http.Client{},
			pkg.NewMetrics(prometheus.NewRegistry()),
			"/tmp/c.json",
			"bborbe",
			factory.CreateStaticFilters(nil),
		)
		Expect(watcher).NotTo(BeNil())
	})
})

var _ = Describe("CreateStaticFilters", func() {
	It("passes a fully-qualifying candidate with an empty allowlist", func() {
		f := factory.CreateStaticFilters(nil)
		Expect(f.Skip(filter.Candidate{
			RepoKey:      "github.com/bborbe/x",
			GoModPresent: true,
			Consent:      filter.GrantedConsent,
		})).To(Equal(""))
	})

	It("fires the consent gate before the go.mod gate in frozen chain order", func() {
		f := factory.CreateStaticFilters(nil)
		// With allow-all scope, an undecided consent fires auto_update_disabled
		// even though go.mod is absent.
		Expect(f.Skip(filter.Candidate{
			RepoKey:      "github.com/bborbe/x",
			GoModPresent: false,
			Consent:      filter.UndecidedConsent,
		})).To(Equal("auto_update_disabled"))
	})

	It("fires no_gomod once consent is granted and go.mod is absent", func() {
		f := factory.CreateStaticFilters(nil)
		Expect(f.Skip(filter.Candidate{
			RepoKey:      "github.com/bborbe/x",
			GoModPresent: false,
			Consent:      filter.GrantedConsent,
		})).To(Equal("no_gomod"))
	})

	It("skips a refused consent with auto_update_disabled despite go.mod presence", func() {
		f := factory.CreateStaticFilters(nil)
		Expect(f.Skip(filter.Candidate{
			RepoKey:      "github.com/bborbe/x",
			GoModPresent: true,
			Consent:      filter.RefusedConsent,
		})).To(Equal("auto_update_disabled"))
	})

	It(
		"skips with scope for a repo outside a non-empty allowlist regardless of other fields",
		func() {
			f := factory.CreateStaticFilters([]string{"github.com/bborbe/a"})
			Expect(f.Skip(filter.Candidate{
				RepoKey:      "github.com/bborbe/other",
				GoModPresent: true,
				Consent:      filter.GrantedConsent,
			})).To(Equal("scope"))
		},
	)
})
