// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bborbe/github-vuln-watcher/pkg"
	"github.com/bborbe/github-vuln-watcher/pkg/factory"
)

type fakeWatcher struct {
	forceCalls chan bool
}

func (f *fakeWatcher) Poll(ctx context.Context, force bool) error {
	f.forceCalls <- force
	return nil
}

var metricsOnce sync.Once

func registerMetrics() {
	metricsOnce.Do(func() {
		pkg.NewMetrics(prometheus.DefaultRegisterer)
	})
}

var _ = Describe("HTTPServer", func() {
	var (
		server      *httptest.Server
		watcherFake *fakeWatcher
		gate        pkg.CycleGate
	)

	BeforeEach(func() {
		registerMetrics()
		watcherFake = &fakeWatcher{forceCalls: make(chan bool, 10)}
		gate = pkg.NewCycleGate()
		baseCtx := context.Background()
		triggerHandler := factory.CreateTriggerHandler(baseCtx, watcherFake, gate)
		router := factory.CreateRouter(baseCtx, triggerHandler, nil)
		server = httptest.NewServer(router)
	})

	AfterEach(func() {
		server.Close()
	})

	It("serves /healthz with 200", func() {
		resp, err := http.Get(server.URL + "/healthz")
		Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
	})

	It("serves /readiness with 200", func() {
		resp, err := http.Get(server.URL + "/readiness")
		Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
	})

	It("serves /metrics with every pre-initialised series at 0", func() {
		resp, err := http.Get(server.URL + "/metrics")
		Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		bodyBytes, err := io.ReadAll(resp.Body)
		Expect(err).NotTo(HaveOccurred())
		body := string(bodyBytes)
		for _, label := range pkg.PollCycleResults {
			Expect(body).To(ContainSubstring(
				fmt.Sprintf(`github_vuln_watcher_poll_cycle_total{result="%s"} 0`, label)))
		}
		for _, label := range pkg.PublishStatuses {
			Expect(body).To(ContainSubstring(
				fmt.Sprintf(`github_vuln_watcher_published_total{status="%s"} 0`, label)))
		}
		for _, label := range pkg.FilterSkipReasons {
			Expect(body).To(ContainSubstring(
				fmt.Sprintf(`github_vuln_watcher_filter_skipped_total{reason="%s"} 0`, label)))
		}
		Expect(body).To(ContainSubstring("github_vuln_watcher_repos_scanned_total 0"))
	})

	It("accepts POST /trigger with 202 and polls with force=false", func() {
		resp, err := http.Post(server.URL+"/trigger", "application/json", nil)
		Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusAccepted))
		Eventually(watcherFake.forceCalls).Should(Receive(Equal(false)))
	})

	It("accepts POST /trigger?force=true with 202 and polls with force=true", func() {
		resp, err := http.Post(server.URL+"/trigger?force=true", "application/json", nil)
		Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusAccepted))
		Eventually(watcherFake.forceCalls).Should(Receive(Equal(true)))
	})

	It("returns 409 for POST /trigger while a cycle is already running", func() {
		Expect(gate.TryAcquire()).To(BeTrue())
		resp, err := http.Post(server.URL+"/trigger", "application/json", nil)
		Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusConflict))
	})

	It("serves /setloglevel/2 with 200", func() {
		resp, err := http.Get(server.URL + "/setloglevel/2")
		Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
	})

	It("returns 404 for the removed key-value-store endpoints", func() {
		resp, err := http.Get(server.URL + "/resetdb")
		Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusNotFound))

		resp, err = http.Get(server.URL + "/resetbucket/foo")
		Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
	})
})
