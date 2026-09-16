// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"context"

	"github.com/bborbe/errors"
	"github.com/bborbe/maintainer/githubapp"

	"github.com/bborbe/github-vuln-watcher/pkg"
)

// NewTokenSource returns a token source that mints a GitHub App installation
// access token per call. Construction performs no I/O and never fails: a mint
// error surfaces per call, so one scan's mint failure degrades that scan to an
// unauthenticated clone instead of taking the service down.
//
// There is no cache and no refresh interval. GitHub App installation tokens are
// valid for up to one hour and a single repo's scan is bounded by the scanner's
// 20-minute gate timeout, so a per-scan mint is always fresh.
func NewTokenSource(creds Credentials) pkg.TokenSource {
	return &tokenSource{creds: creds}
}

type tokenSource struct {
	creds Credentials
}

// Token mints one installation access token for a single scan.
//
// The returned value is a live credential: it must never be logged, placed in
// argv, or written to disk. It is deliberately not validated here — MintIAT
// already returns a named error for an invalid config, and duplicating that
// check would drift.
func (t *tokenSource) Token(ctx context.Context) (string, error) {
	token, err := githubapp.MintIAT(ctx, githubapp.Config{
		AppID:          t.creds.AppID,
		InstallationID: t.creds.InstallationID,
		PEM:            t.creds.PEMKey,
		BaseURL:        t.creds.BaseURL,
	})
	if err != nil {
		return "", errors.Wrap(ctx, err, "mint installation token")
	}
	return token, nil
}
