// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/bborbe/github-vuln-watcher/pkg"
	"github.com/bborbe/github-vuln-watcher/pkg/filter"
)

var _ = Describe("GitHubClient", func() {
	var (
		ctx       context.Context
		client    pkg.GitHubClient
		server    *httptest.Server
		serverURL string
		handler   http.HandlerFunc
		reqCount  int
	)

	BeforeEach(func() {
		ctx = context.Background()
		reqCount = 0
		handler = nil
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqCount++
			if handler != nil {
				handler(w, r)
				return
			}
			http.Error(w, "no handler registered: "+r.URL.Path, http.StatusInternalServerError)
		}))
		serverURL = server.URL
		client = pkg.NewGitHubClient(server.Client())
		Expect(pkg.SetBaseURL(client, serverURL+"/")).To(Succeed())
	})

	AfterEach(func() {
		server.Close()
	})

	Describe("ListRepos", func() {
		It("paginates via the Link header and drops out-of-scope repos", func() {
			handler = func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/installation/repositories":
					switch r.URL.Query().Get("page") {
					case "", "1":
						w.Header().Set("Link", fmt.Sprintf(
							`<%s/installation/repositories?page=2&per_page=100>; rel="next"`,
							serverURL,
						))
						writeJSON(w, map[string]interface{}{
							"total_count": 5,
							"repositories": []map[string]interface{}{
								{
									"name":           "repo-a",
									"default_branch": "master",
									"archived":       false,
									"private":        false,
									"owner":          map[string]interface{}{"login": "bborbe"},
								},
								{
									"name":           "old-stuff",
									"default_branch": "master",
									"archived":       true,
									"private":        false,
									"owner":          map[string]interface{}{"login": "bborbe"},
								},
								{
									"name":           "other-org",
									"default_branch": "main",
									"archived":       false,
									"private":        false,
									"owner": map[string]interface{}{
										"login": "someone-else",
									},
								},
								{
									"name":           "",
									"default_branch": "main",
									"archived":       false,
									"private":        false,
									"owner":          map[string]interface{}{"login": "bborbe"},
								},
								{
									"name":           "weird name!",
									"default_branch": "main",
									"archived":       false,
									"private":        false,
									"owner":          map[string]interface{}{"login": "bborbe"},
								},
							},
						})
					case "2":
						writeJSON(w, map[string]interface{}{
							"total_count": 5,
							"repositories": []map[string]interface{}{
								{
									"name":           "repo-b",
									"default_branch": "main",
									"archived":       false,
									"private":        false,
									"owner":          map[string]interface{}{"login": "bborbe"},
								},
								{
									"name":           "repo-c",
									"default_branch": "main",
									"archived":       false,
									"private":        true,
									"owner":          map[string]interface{}{"login": "bborbe"},
								},
							},
						})
					default:
						http.Error(
							w,
							"unexpected page: "+r.URL.Query().Get("page"),
							http.StatusInternalServerError,
						)
					}
				default:
					http.Error(w, "unexpected route: "+r.URL.Path, http.StatusInternalServerError)
				}
			}

			repos, err := client.ListRepos(ctx, "bborbe")
			Expect(err).NotTo(HaveOccurred())
			Expect(repos).To(HaveLen(3))
			Expect(repos[0].Name).To(Equal("repo-a"))
			Expect(repos[0].DefaultBranch).To(Equal("master"))
			Expect(repos[1].Name).To(Equal("repo-b"))
			Expect(repos[1].DefaultBranch).To(Equal("main"))
			Expect(repos[2].Name).To(Equal("repo-c"))
			Expect(reqCount).To(Equal(2))
		})

		It("returns ErrRateLimited on a primary rate-limit response", func() {
			handler = func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/installation/repositories" {
					http.Error(w, "unexpected route: "+r.URL.Path, http.StatusInternalServerError)
					return
				}
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", "1893456000")
				w.WriteHeader(http.StatusForbidden)
				writeJSON(w, map[string]interface{}{
					"message":           "API rate limit exceeded",
					"documentation_url": "https://docs.github.com/rest/using-the-rest-api/rate-limits-for-the-rest-api",
				})
			}

			repos, err := client.ListRepos(ctx, "bborbe")
			Expect(repos).To(BeNil())
			Expect(err).To(MatchError(pkg.ErrRateLimited))
		})
	})

	Describe("GetGoMod", func() {
		It("returns decoded bytes for a found go.mod", func() {
			handler = func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/bborbe/repo-a/contents/go.mod" {
					http.Error(w, "unexpected route: "+r.URL.Path, http.StatusInternalServerError)
					return
				}
				Expect(r.URL.Query().Get("ref")).To(Equal("master"))
				writeContentJSON(
					w,
					"go.mod",
					[]byte("module github.com/bborbe/example\n\ngo 1.21\n"),
				)
			}

			content, err := client.GetGoMod(
				ctx,
				pkg.Repo{Owner: "bborbe", Name: "repo-a", DefaultBranch: "master"},
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(content)).To(Equal("module github.com/bborbe/example\n\ngo 1.21\n"))
		})

		It("returns nil bytes on 404", func() {
			handler = func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/bborbe/repo-a/contents/go.mod" {
					http.Error(w, "unexpected route: "+r.URL.Path, http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusNotFound)
				writeJSON(w, map[string]interface{}{"message": "Not Found"})
			}

			content, err := client.GetGoMod(
				ctx,
				pkg.Repo{Owner: "bborbe", Name: "repo-a", DefaultBranch: "master"},
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(content).To(BeNil())
		})

		It("returns ErrRateLimited on a primary rate-limit response", func() {
			handler = func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/bborbe/repo-a/contents/go.mod" {
					http.Error(w, "unexpected route: "+r.URL.Path, http.StatusInternalServerError)
					return
				}
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", "1893456000")
				w.WriteHeader(http.StatusForbidden)
				writeJSON(w, map[string]interface{}{
					"message":           "API rate limit exceeded",
					"documentation_url": "https://docs.github.com/rest/using-the-rest-api/rate-limits-for-the-rest-api",
				})
			}

			content, err := client.GetGoMod(
				ctx,
				pkg.Repo{Owner: "bborbe", Name: "repo-a", DefaultBranch: "master"},
			)
			Expect(content).To(BeNil())
			Expect(err).To(MatchError(pkg.ErrRateLimited))
		})

		It("returns a wrapped error for an oversized file", func() {
			handler = func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/bborbe/repo-a/contents/go.mod" {
					http.Error(w, "unexpected route: "+r.URL.Path, http.StatusInternalServerError)
					return
				}
				writeJSON(w, map[string]interface{}{
					"name":     "go.mod",
					"path":     "go.mod",
					"size":     2 * 1024 * 1024,
					"encoding": "base64",
					"content":  base64.StdEncoding.EncodeToString([]byte("module x\n")),
				})
			}

			content, err := client.GetGoMod(
				ctx,
				pkg.Repo{Owner: "bborbe", Name: "repo-a", DefaultBranch: "master"},
			)
			Expect(content).To(BeNil())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("too large"))
		})

		It("returns a wrapped error on a 5xx response, not ErrRateLimited", func() {
			handler = func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/bborbe/repo-a/contents/go.mod" {
					http.Error(w, "unexpected route: "+r.URL.Path, http.StatusInternalServerError)
					return
				}
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}

			content, err := client.GetGoMod(
				ctx,
				pkg.Repo{Owner: "bborbe", Name: "repo-a", DefaultBranch: "master"},
			)
			Expect(content).To(BeNil())
			Expect(err).To(HaveOccurred())
			Expect(err).NotTo(MatchError(pkg.ErrRateLimited))
			Expect(err.Error()).To(ContainSubstring("get go.mod"))
		})
	})

	Describe("GetMaintainerConfig", func() {
		It("returns GrantedConsent for explicit autoUpdate: true", func() {
			handler = func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/bborbe/repo-a/contents/.maintainer.yaml" {
					http.Error(w, "unexpected route: "+r.URL.Path, http.StatusInternalServerError)
					return
				}
				Expect(r.URL.Query().Get("ref")).To(Equal("master"))
				writeContentJSON(w, ".maintainer.yaml", []byte("goUpdate:\n  autoUpdate: true\n"))
			}

			consent, err := client.GetMaintainerConfig(
				ctx,
				pkg.Repo{Owner: "bborbe", Name: "repo-a", DefaultBranch: "master"},
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(consent).To(Equal(filter.GrantedConsent))
		})

		It("returns UndecidedConsent on 404", func() {
			handler = func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/bborbe/repo-a/contents/.maintainer.yaml" {
					http.Error(w, "unexpected route: "+r.URL.Path, http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusNotFound)
				writeJSON(w, map[string]interface{}{"message": "Not Found"})
			}

			consent, err := client.GetMaintainerConfig(
				ctx,
				pkg.Repo{Owner: "bborbe", Name: "repo-a", DefaultBranch: "master"},
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(consent).To(Equal(filter.UndecidedConsent))
		})

		It("returns an error for malformed YAML", func() {
			handler = func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/bborbe/repo-a/contents/.maintainer.yaml" {
					http.Error(w, "unexpected route: "+r.URL.Path, http.StatusInternalServerError)
					return
				}
				writeContentJSON(w, ".maintainer.yaml", []byte("{{{"))
			}

			consent, err := client.GetMaintainerConfig(
				ctx,
				pkg.Repo{Owner: "bborbe", Name: "repo-a", DefaultBranch: "master"},
			)
			Expect(err).To(HaveOccurred())
			Expect(consent).To(Equal(filter.Consent("")))
		})

		It("returns ErrRateLimited on a primary rate-limit response", func() {
			handler = func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/bborbe/repo-a/contents/.maintainer.yaml" {
					http.Error(w, "unexpected route: "+r.URL.Path, http.StatusInternalServerError)
					return
				}
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", "1893456000")
				w.WriteHeader(http.StatusForbidden)
				writeJSON(w, map[string]interface{}{
					"message":           "API rate limit exceeded",
					"documentation_url": "https://docs.github.com/rest/using-the-rest-api/rate-limits-for-the-rest-api",
				})
			}

			consent, err := client.GetMaintainerConfig(
				ctx,
				pkg.Repo{Owner: "bborbe", Name: "repo-a", DefaultBranch: "master"},
			)
			Expect(consent).To(Equal(filter.Consent("")))
			Expect(err).To(MatchError(pkg.ErrRateLimited))
		})

		It("returns a wrapped error for an oversized file", func() {
			handler = func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/bborbe/repo-a/contents/.maintainer.yaml" {
					http.Error(w, "unexpected route: "+r.URL.Path, http.StatusInternalServerError)
					return
				}
				writeJSON(w, map[string]interface{}{
					"name":     ".maintainer.yaml",
					"path":     ".maintainer.yaml",
					"size":     2 * 1024 * 1024,
					"encoding": "base64",
					"content": base64.StdEncoding.EncodeToString(
						[]byte("goUpdate:\n  autoUpdate: true\n"),
					),
				})
			}

			consent, err := client.GetMaintainerConfig(
				ctx,
				pkg.Repo{Owner: "bborbe", Name: "repo-a", DefaultBranch: "master"},
			)
			Expect(consent).To(Equal(filter.Consent("")))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("too large"))
		})
	})
})

func writeJSON(w http.ResponseWriter, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "marshal body", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func writeContentJSON(w http.ResponseWriter, name string, content []byte) {
	writeJSON(w, map[string]interface{}{
		"name":     name,
		"path":     name,
		"size":     len(content),
		"encoding": "base64",
		"content":  base64.StdEncoding.EncodeToString(content),
	})
}
