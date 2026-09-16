// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/bborbe/github-vuln-watcher/pkg/auth"
)

// generateTestPEMKey returns a throwaway 2048-bit RSA private key in the PEM
// form the App credential arrives in. It is generated per test run so no key
// material is ever committed.
func generateTestPEMKey() []byte {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
}

var testPEMKey = generateTestPEMKey()

// mintRequest is the subset of the installation-token request the specs assert
// on. It is copied out of the handler rather than sharing the *http.Request, so
// the read after Token returns is race-free without a mutex.
type mintRequest struct {
	Method        string
	Path          string
	ContentType   string
	Authorization string
}

// recordingServer returns an httptest server that records the first request it
// receives and answers it with respond. The recorded request arrives on the
// returned channel.
func recordingServer(respond http.HandlerFunc) (*httptest.Server, chan mintRequest) {
	requests := make(chan mintRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requests <- mintRequest{
			Method:        r.Method,
			Path:          r.URL.Path,
			ContentType:   r.Header.Get("Content-Type"),
			Authorization: r.Header.Get("Authorization"),
		}:
		default:
		}
		respond(w, r)
	}))
	return server, requests
}

// tokenResponse writes the successful installation-token exchange response.
func tokenResponse(w http.ResponseWriter, _ *http.Request) {
	expiresAt := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"token":"ghs_minted","expires_at":%q}`, expiresAt)
}

var _ = Describe("NewTokenSource", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})

	It("mints through the real App credential exchange and returns the token", func() {
		server, requests := recordingServer(tokenResponse)
		defer server.Close()

		source := auth.NewTokenSource(auth.Credentials{
			AppID:          12345,
			InstallationID: 67890,
			PEMKey:         testPEMKey,
			BaseURL:        server.URL,
		})

		token, err := source.Token(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).To(Equal("ghs_minted"))

		var recorded mintRequest
		Eventually(requests).Should(Receive(&recorded))
		Expect(recorded.Method).To(Equal(http.MethodPost))
		Expect(recorded.Path).To(Equal("/app/installations/67890/access_tokens"))
		Expect(recorded.ContentType).To(Equal("application/json"))

		// The bearer value is a signed JWT: three dot-separated segments. This
		// is what proves the App credential path (JWT signing plus the
		// installation-token exchange) works, not merely that a struct was
		// populated.
		Expect(recorded.Authorization).To(HavePrefix("Bearer "))
		segments := strings.Split(strings.TrimPrefix(recorded.Authorization, "Bearer "), ".")
		Expect(segments).To(HaveLen(3))
	})

	It("returns an error and no token when the token exchange fails", func() {
		server, _ := recordingServer(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		defer server.Close()

		source := auth.NewTokenSource(auth.Credentials{
			AppID:          12345,
			InstallationID: 67890,
			PEMKey:         testPEMKey,
			BaseURL:        server.URL,
		})

		token, err := source.Token(ctx)
		Expect(err).To(HaveOccurred())
		Expect(token).To(BeEmpty())
	})

	It("returns an error without panicking when the API is unreachable", func() {
		server, _ := recordingServer(tokenResponse)
		baseURL := server.URL
		server.Close()

		source := auth.NewTokenSource(auth.Credentials{
			AppID:          12345,
			InstallationID: 67890,
			PEMKey:         testPEMKey,
			BaseURL:        baseURL,
		})

		var token string
		var err error
		Expect(func() {
			token, err = source.Token(ctx)
		}).ToNot(Panic())
		Expect(err).To(HaveOccurred())
		Expect(token).To(BeEmpty())
	})

	It("rejects an invalid config without contacting any server, never echoing the PEM", func() {
		for _, creds := range []auth.Credentials{
			{},
			{AppID: 1, InstallationID: 1, PEMKey: []byte("not-a-real-key")},
		} {
			token, err := auth.NewTokenSource(creds).Token(ctx)
			Expect(err).To(HaveOccurred())
			Expect(token).To(BeEmpty())
			Expect(err.Error()).NotTo(ContainSubstring("not-a-real-key"))
			if len(creds.PEMKey) > 0 {
				Expect(err.Error()).NotTo(ContainSubstring(string(creds.PEMKey)))
			}
		}
	})

	It("honours context cancellation instead of hanging on a stalled mint", func() {
		var once sync.Once
		entered := make(chan struct{})
		release := make(chan struct{})
		server, _ := recordingServer(func(w http.ResponseWriter, r *http.Request) {
			once.Do(func() { close(entered) })
			select {
			case <-r.Context().Done():
			case <-release:
			case <-time.After(30 * time.Second):
			}
		})
		defer func() {
			close(release)
			server.Close()
		}()

		source := auth.NewTokenSource(auth.Credentials{
			AppID:          12345,
			InstallationID: 67890,
			PEMKey:         testPEMKey,
			BaseURL:        server.URL,
		})

		mintCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()

		start := time.Now()
		token, err := source.Token(mintCtx)
		elapsed := time.Since(start)

		Expect(err).To(HaveOccurred())
		Expect(token).To(BeEmpty())
		// The request must have reached the handler (otherwise this would be a
		// connection error, not a cancellation) and the mint must have returned
		// on the cancellation rather than on the handler's own timeout.
		Expect(entered).To(BeClosed())
		Expect(elapsed).To(BeNumerically("<", 20*time.Second))
	})
})
