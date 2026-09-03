// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package factory_test

import (
	"context"

	"github.com/gorilla/mux"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bborbe/github-vuln-watcher/mocks"
	"github.com/bborbe/github-vuln-watcher/pkg"
	"github.com/bborbe/github-vuln-watcher/pkg/factory"
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
			pkg.NewMetrics(prometheus.NewRegistry()),
			"/tmp/c.json",
			"bborbe",
		)
		Expect(watcher).NotTo(BeNil())
	})
})
