// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg

import (
	"context"
	stderrors "errors"
	"net/http"
	"regexp"

	"github.com/bborbe/errors"
	"github.com/golang/glog"
	gogithub "github.com/google/go-github/v84/github"

	"github.com/bborbe/github-vuln-watcher/pkg/filter"
)

// ErrRateLimited is returned when the GitHub API responds with a primary or
// abuse rate-limit error. Callers abort the whole cycle on this sentinel
// (poll_cycle_total{result="rate_limited"}) rather than retrying in a loop.
var ErrRateLimited = stderrors.New("github rate limited")

// maxContentBytes caps every file this client decodes. The contents of go.mod
// and .maintainer.yaml in any observed repo are attacker-controlled, so the
// API-reported Size is checked BEFORE decoding.
const maxContentBytes = 1024 * 1024

// maxListPages bounds repo-list pagination so a self-referential or
// misbehaving `next` link cannot loop the cycle forever.
const maxListPages = 100

// repoNameCharset is the character set allowed in repo owner and name before
// either enters frontmatter or the cursor. This is the single choke point, so
// every later layer gets validated names.
var repoNameCharset = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

//counterfeiter:generate -o ../mocks/github_client.go --fake-name GitHubClient . GitHubClient

// GitHubClient is the read-only upstream surface for the vuln-drift watcher.
// Nothing in this interface writes to an observed repository.
type GitHubClient interface {
	// ListRepos returns the non-archived repositories under owner that the
	// authenticated GitHub App installation can access — public AND private.
	// Enumeration goes through GET /installation/repositories
	// (Apps.ListRepos), NOT GET /users/{u}/repos, because the latter silently
	// omits private repos under an installation token. Pagination is internal
	// and capped at maxListPages; the returned slice is the full set.
	ListRepos(ctx context.Context, owner string) ([]Repo, error)

	// GetGoMod returns the raw bytes of go.mod at HEAD of repo's default
	// branch. Returns (nil, nil) when the file does not exist (HTTP 404) —
	// the caller maps a nil slice to skip reason "no_gomod". Returns
	// (nil, ErrRateLimited) on rate limiting. Every other failure (network,
	// 5xx, oversize, base64 decode) returns a wrapped error and drops the repo.
	GetGoMod(ctx context.Context, repo Repo) ([]byte, error)

	// GetMaintainerConfig returns the parsed consent verdict from
	// `.maintainer.yaml` at HEAD of repo's default branch.
	//
	//   - (filter.GrantedConsent, nil) — autoUpdate is explicitly boolean true.
	//   - (filter.RefusedConsent, nil) — autoUpdate is explicitly boolean false.
	//   - (filter.UndecidedConsent, nil) — the file is absent (HTTP 404), the
	//     goUpdate section is absent, the autoUpdate key is absent, or the key
	//     holds any non-boolean value.
	//   - (filter.Consent(""), ErrRateLimited) on primary or abuse rate limiting.
	//   - (filter.Consent(""), wrapped error) on every other failure including
	//     5xx, oversize files, base64 decode failures, and YAML parse failures.
	//
	// Malformed YAML MUST NOT be silently treated as UndecidedConsent — it is
	// an error so the repo is dropped from the cycle rather than recorded as a
	// consent verdict.
	GetMaintainerConfig(ctx context.Context, repo Repo) (filter.Consent, error)
}

// NewGitHubClient returns the production GitHubClient backed by the given
// HTTP client (authenticated via GitHub App installation token).
func NewGitHubClient(httpClient *http.Client) GitHubClient {
	return &githubClient{client: gogithub.NewClient(httpClient)}
}

type githubClient struct {
	client *gogithub.Client
}

// isRateLimitError reports whether err is a primary or abuse rate-limit
// response from the GitHub API.
func isRateLimitError(err error) bool {
	var rl *gogithub.RateLimitError
	var arl *gogithub.AbuseRateLimitError
	return stderrors.As(err, &rl) || stderrors.As(err, &arl)
}

// isNotFound reports whether err is an HTTP 404 from the GitHub API.
func isNotFound(err error) bool {
	var ghErr *gogithub.ErrorResponse
	if !stderrors.As(err, &ghErr) {
		return false
	}
	return ghErr.Response != nil && ghErr.Response.StatusCode == http.StatusNotFound
}

// wrapRateLimitErr returns ErrRateLimited on a rate-limit response and wraps
// every other error with the given message.
func wrapRateLimitErr(ctx context.Context, err error, msg string, args ...interface{}) error {
	if isRateLimitError(err) {
		return ErrRateLimited
	}
	return errors.Wrapf(ctx, err, msg, args...)
}

// mapGitHubRepos projects installation repos into the watcher's Repo value
// type, dropping repos outside the watcher's scope: archived repos, repos
// whose owner is not the configured owner, repos with an empty name, and
// repos whose owner or name carries a character outside [a-zA-Z0-9_.-].
func mapGitHubRepos(repos []*gogithub.Repository, owner string) []Repo {
	result := make([]Repo, 0, len(repos))
	for _, repo := range repos {
		if repo == nil {
			continue
		}
		if repo.GetArchived() {
			continue
		}
		repoOwner := repo.GetOwner().GetLogin()
		if repoOwner != owner {
			continue
		}
		name := repo.GetName()
		if name == "" {
			continue
		}
		if !repoNameCharset.MatchString(repoOwner) || !repoNameCharset.MatchString(name) {
			continue
		}
		result = append(result, Repo{
			Owner:         owner,
			Name:          name,
			DefaultBranch: repo.GetDefaultBranch(),
		})
	}
	return result
}

// ListRepos enumerates the installation's accessible repos under owner,
// paginating through Apps.ListRepos up to maxListPages pages.
func (c *githubClient) ListRepos(ctx context.Context, owner string) ([]Repo, error) {
	var (
		raw     []*gogithub.Repository
		private int
	)
	opts := &gogithub.ListOptions{PerPage: 100, Page: 1}
	for page := 1; page <= maxListPages; page++ {
		select {
		case <-ctx.Done():
			return nil, errors.Wrapf(ctx, ctx.Err(), "list installation repos owner=%s", owner)
		default:
		}
		list, resp, err := c.client.Apps.ListRepos(ctx, opts)
		if err != nil {
			return nil, wrapRateLimitErr(
				ctx, err, "list installation repos owner=%s page=%d", owner, page,
			)
		}
		if list != nil {
			raw = append(raw, list.Repositories...)
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	for _, repo := range raw {
		if repo.GetPrivate() {
			private++
		}
	}
	repos := mapGitHubRepos(raw, owner)
	glog.V(2).Infof(
		"github-vuln-watcher listed installation repos owner=%s total=%d private=%d in_scope=%d",
		owner, len(raw), private, len(repos),
	)
	return repos, nil
}

// GetGoMod fetches and decodes go.mod at repo's default-branch HEAD.
func (c *githubClient) GetGoMod(ctx context.Context, repo Repo) ([]byte, error) {
	opts := &gogithub.RepositoryContentGetOptions{Ref: repo.DefaultBranch}
	fileContent, _, _, err := c.client.Repositories.GetContents(
		ctx, repo.Owner, repo.Name, "go.mod", opts,
	)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, wrapRateLimitErr(ctx, err, "get go.mod %s", repo.String())
	}
	if fileContent == nil {
		return nil, nil
	}
	if fileContent.GetSize() > maxContentBytes {
		return nil, errors.Errorf(
			ctx, "go.mod %s too large: %d bytes (max %d)",
			repo.String(), fileContent.GetSize(), maxContentBytes,
		)
	}
	decoded, err := fileContent.GetContent()
	if err != nil {
		return nil, errors.Wrapf(ctx, err, "decode go.mod %s", repo.String())
	}
	if len(decoded) > maxContentBytes {
		return nil, errors.Errorf(
			ctx, "go.mod %s decoded to %d bytes (max %d)",
			repo.String(), len(decoded), maxContentBytes,
		)
	}
	return []byte(decoded), nil
}

// GetMaintainerConfig fetches and parses `.maintainer.yaml` at repo's
// default-branch HEAD into the consent verdict.
func (c *githubClient) GetMaintainerConfig(ctx context.Context, repo Repo) (filter.Consent, error) {
	opts := &gogithub.RepositoryContentGetOptions{Ref: repo.DefaultBranch}
	fileContent, _, _, err := c.client.Repositories.GetContents(
		ctx, repo.Owner, repo.Name, ".maintainer.yaml", opts,
	)
	if err != nil {
		if isNotFound(err) {
			return filter.UndecidedConsent, nil
		}
		return filter.Consent(
				"",
			), wrapRateLimitErr(
				ctx,
				err,
				"get .maintainer.yaml %s",
				repo.String(),
			)
	}
	if fileContent == nil {
		return filter.UndecidedConsent, nil
	}
	if fileContent.GetSize() > maxContentBytes {
		return filter.Consent(""), errors.Errorf(
			ctx, ".maintainer.yaml %s too large: %d bytes (max %d)",
			repo.String(), fileContent.GetSize(), maxContentBytes,
		)
	}
	decoded, err := fileContent.GetContent()
	if err != nil {
		return filter.Consent(
				"",
			), errors.Wrapf(
				ctx,
				err,
				"decode .maintainer.yaml %s",
				repo.String(),
			)
	}
	if len(decoded) > maxContentBytes {
		return filter.Consent(""), errors.Errorf(
			ctx, ".maintainer.yaml %s decoded to %d bytes (max %d)",
			repo.String(), len(decoded), maxContentBytes,
		)
	}
	return filter.ParseConsent(ctx, []byte(decoded))
}
