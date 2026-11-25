// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/bborbe/github-vuln-watcher/pkg"
)

// recordingTransport records the host of every request it sees and answers
// with a canned 200, so a client can be pointed at a host that does not
// resolve.
type recordingTransport struct {
	hosts []string
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.hosts = append(t.hosts, req.URL.Host)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(
			strings.NewReader(`{"total_count":0,"repositories":[]}`),
		),
		Request: req,
	}, nil
}

var _ = Describe("GitHubClient transport chain", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})

	It("retries a 429 with Retry-After: 0 and succeeds on the second call", func() {
		var calls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"message":"secondary rate limit"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"total_count":0,"repositories":[]}`))
		}))
		defer server.Close()

		client := pkg.NewGitHubClient(server.Client(), server.URL+"/")
		repos, err := client.ListRepos(ctx, "bborbe")
		Expect(err).NotTo(HaveOccurred())
		Expect(repos).To(BeEmpty())
		Expect(calls).To(Equal(2))
	})

	It("uses the configured apiBaseURL as the request host", func() {
		recorder := &recordingTransport{}
		client := pkg.NewGitHubClient(
			&http.Client{Transport: recorder},
			"http://stub.invalid/",
		)

		_, err := client.ListRepos(ctx, "bborbe")
		Expect(err).NotTo(HaveOccurred())
		Expect(recorder.hosts).To(Equal([]string{"stub.invalid"}))
	})

	It("keeps the default base URL when apiBaseURL does not parse", func() {
		recorder := &recordingTransport{}
		client := pkg.NewGitHubClient(
			&http.Client{Transport: recorder},
			"://bad",
		)

		_, err := client.ListRepos(ctx, "bborbe")
		Expect(err).NotTo(HaveOccurred())
		Expect(recorder.hosts).To(Equal([]string{"api.github.com"}))
	})
})
