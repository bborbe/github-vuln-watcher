// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package handler_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bborbe/github-vuln-watcher/mocks"
	"github.com/bborbe/github-vuln-watcher/pkg"
	"github.com/bborbe/github-vuln-watcher/pkg/factory"
	"github.com/bborbe/github-vuln-watcher/pkg/handler"
)

func countStatuses(statuses []int, status int) int {
	count := 0
	for _, s := range statuses {
		if s == status {
			count++
		}
	}
	return count
}

func metricValue(registry *prometheus.Registry, name string, labels map[string]string) float64 {
	families, err := registry.Gather()
	Expect(err).NotTo(HaveOccurred())
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			match := true
			for _, lp := range metric.GetLabel() {
				if want, ok := labels[lp.GetName()]; !ok || want != lp.GetValue() {
					match = false
				}
			}
			if match {
				return metric.GetCounter().GetValue()
			}
		}
	}
	return 0
}

var _ = Describe("TriggerHandler", func() {
	var (
		httpHandler http.Handler
		watcher     *mocks.Watcher
		gate        pkg.CycleGate
	)

	BeforeEach(func() {
		watcher = &mocks.Watcher{}
		gate = pkg.NewCycleGate()
		httpHandler = handler.NewTriggerHandlerHTTPAdapter(context.Background(), watcher, gate)
	})

	It("accepts a forced cycle with 202 and polls without force by default", func() {
		req := httptest.NewRequest("POST", "/trigger", nil)
		resp := httptest.NewRecorder()

		httpHandler.ServeHTTP(resp, req)

		Expect(resp.Code).To(Equal(http.StatusAccepted))
		Expect(resp.Body.String()).To(ContainSubstring(`{"status":"accepted"}`))
		Eventually(func() int { return watcher.PollCallCount() }).Should(Equal(1))
		_, force := watcher.PollArgsForCall(0)
		Expect(force).To(BeFalse())
	})

	It("passes force=true when requested", func() {
		req := httptest.NewRequest("POST", "/trigger?force=true", nil)
		resp := httptest.NewRecorder()

		httpHandler.ServeHTTP(resp, req)

		Expect(resp.Code).To(Equal(http.StatusAccepted))
		Eventually(func() bool {
			if watcher.PollCallCount() == 0 {
				return false
			}
			_, force := watcher.PollArgsForCall(0)
			return force
		}).Should(BeTrue())
	})

	It("returns 409 when a cycle is already running", func() {
		Expect(gate.TryAcquire()).To(BeTrue())

		req := httptest.NewRequest("POST", "/trigger", nil)
		resp := httptest.NewRecorder()

		httpHandler.ServeHTTP(resp, req)

		Expect(resp.Code).To(Equal(http.StatusConflict))
		Expect(resp.Body.String()).To(ContainSubstring("a poll cycle is already running"))
		Expect(watcher.PollCallCount()).To(Equal(0))
	})

	It("ignores unknown query parameters such as repo", func() {
		req := httptest.NewRequest("POST", "/trigger?force=true&repo=attacker/repo", nil)
		resp := httptest.NewRecorder()

		httpHandler.ServeHTTP(resp, req)

		Expect(resp.Code).To(Equal(http.StatusAccepted))
		Eventually(func() bool {
			if watcher.PollCallCount() == 0 {
				return false
			}
			_, force := watcher.PollArgsForCall(0)
			return force
		}).Should(BeTrue())

		source, err := os.ReadFile("trigger_handler.go")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(source)).NotTo(ContainSubstring(`"repo"`))
	})

	It("runs the cycle under the base context, not the request context", func() {
		ctx, cancel := context.WithCancel(context.Background())
		req := httptest.NewRequest("POST", "/trigger", nil).WithContext(ctx)
		resp := httptest.NewRecorder()

		httpHandler.ServeHTTP(resp, req)
		Expect(resp.Code).To(Equal(http.StatusAccepted))

		cancel()
		Eventually(func() int { return watcher.PollCallCount() }).Should(Equal(1))
	})

	Describe("burst of concurrent /trigger calls", func() {
		It("runs exactly one cycle", func() {
			registry := prometheus.NewRegistry()
			metrics := pkg.NewMetrics(registry)
			release := make(chan struct{})
			var pollCalls int32
			watcher := &mocks.Watcher{}
			watcher.PollStub = func(ctx context.Context, force bool) error {
				atomic.AddInt32(&pollCalls, 1)
				<-release // hold the single cycle slot so the other triggers see it busy
				metrics.IncPollCycle("success")
				return nil
			}
			gate := pkg.NewCycleGate()
			handler := factory.CreateTriggerHandler(context.Background(), watcher, gate)
			server := httptest.NewServer(handler)
			defer server.Close()

			const n = 5
			statuses := make([]int, n)
			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					resp, err := http.Post(server.URL+"/trigger", "application/json", nil)
					Expect(err).NotTo(HaveOccurred())
					statuses[i] = resp.StatusCode
					_ = resp.Body.Close()
				}(i)
			}
			Eventually(func() int { return int(atomic.LoadInt32(&pollCalls)) }).
				Should(Equal(1))
			close(release)
			wg.Wait()

			Expect(atomic.LoadInt32(&pollCalls)).To(Equal(int32(1)))
			Expect(countStatuses(statuses, http.StatusAccepted)).To(Equal(1))
			Expect(countStatuses(statuses, http.StatusConflict)).To(Equal(n - 1))
			// the single cycle that ran counted its outcome (Eventually: the cycle runs in a
			// BackgroundRunner goroutine — the metric lands after release, not before wg.Wait)
			Eventually(func() float64 {
				return metricValue(registry, "github_vuln_watcher_poll_cycle_total",
					map[string]string{"result": "success"})
			}).Should(Equal(1.0))
		})
	})
})
