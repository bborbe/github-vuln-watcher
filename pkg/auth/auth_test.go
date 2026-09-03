// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/bborbe/github-vuln-watcher/pkg/auth"
)

var _ = Describe("ResolveGitHubClient", func() {
	var (
		ctx   context.Context
		creds auth.Credentials
	)

	BeforeEach(func() {
		ctx = context.Background()
		creds = auth.Credentials{}
	})

	It(
		"with all three credentials set returns an error (PEM cannot be parsed) rather than a nil client",
		func() {
			creds = auth.Credentials{
				AppID:          12345,
				InstallationID: 67890,
				PEMKey:         []byte("not-a-real-key"),
			}
			client, err := auth.ResolveGitHubClient(ctx, creds)
			Expect(err).To(HaveOccurred())
			Expect(client).To(BeNil())
		},
	)

	It("with only APP_ID set names the missing env vars but never the PEM value", func() {
		creds = auth.Credentials{AppID: 12345}
		client, err := auth.ResolveGitHubClient(ctx, creds)
		Expect(err).To(HaveOccurred())
		Expect(client).To(BeNil())
		Expect(err.Error()).To(ContainSubstring("INSTALLATION_ID"))
		Expect(err.Error()).To(ContainSubstring("PEM_KEY"))
		Expect(err.Error()).NotTo(ContainSubstring("not-a-real-key"))
	})

	It("with only PEMKey set names APP_ID as missing but never the PEM value", func() {
		creds = auth.Credentials{PEMKey: []byte("not-a-real-key")}
		client, err := auth.ResolveGitHubClient(ctx, creds)
		Expect(err).To(HaveOccurred())
		Expect(client).To(BeNil())
		Expect(err.Error()).To(ContainSubstring("APP_ID"))
		Expect(err.Error()).NotTo(ContainSubstring("not-a-real-key"))
	})

	It("with nothing set reports the credentials not configured", func() {
		client, err := auth.ResolveGitHubClient(ctx, auth.Credentials{})
		Expect(err).To(HaveOccurred())
		Expect(client).To(BeNil())
		Expect(err.Error()).To(ContainSubstring("not configured"))
	})

	It("never panics or nil-pointer-dereferences on any partial set", func() {
		Expect(func() {
			_, _ = auth.ResolveGitHubClient(ctx, auth.Credentials{AppID: 1})
			_, _ = auth.ResolveGitHubClient(ctx, auth.Credentials{InstallationID: 1})
			_, _ = auth.ResolveGitHubClient(ctx, auth.Credentials{AppID: 1, PEMKey: []byte("x")})
			_, _ = auth.ResolveGitHubClient(
				ctx,
				auth.Credentials{InstallationID: 1, PEMKey: []byte("x")},
			)
			_, _ = auth.ResolveGitHubClient(ctx, auth.Credentials{})
		}).ToNot(Panic())
	})
})
