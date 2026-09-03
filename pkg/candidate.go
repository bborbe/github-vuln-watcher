// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg

import (
	"github.com/bborbe/github-vuln-watcher/pkg/filter"
)

// Candidate is the watcher's per-repo observation: everything needed to
// (a) decide whether to file a work item and (b) populate the emitted message.
//
// Built per cycle by the Watcher in this order, so partial failures degrade
// gracefully:
//  1. Repo         (from ListRepos)
//  2. GoModPresent (from GetGoMod — false when the repo has no go.mod)
//  3. Consent      (from GetMaintainerConfig)
//  4. HeadSHA      (from the cloned HEAD — scan stage)
//  5. VulnIDs      (from the scan stage classification)
type Candidate struct {
	Repo         Repo
	HeadSHA      string
	GoModPresent bool
	Consent      filter.Consent
	VulnIDs      []string // canonical (deduped, sorted) marker list
}

// ShortSHA returns the first 7 chars of HeadSHA, used in the title and body.
func (c Candidate) ShortSHA() string {
	if len(c.HeadSHA) < 7 {
		return c.HeadSHA
	}
	return c.HeadSHA[:7]
}

// FilterCandidate projects this observation onto the filter package's input.
func (c Candidate) FilterCandidate() filter.Candidate {
	return filter.Candidate{
		RepoKey:        c.Repo.Key(),
		HeadSHA:        c.HeadSHA,
		GoModPresent:   c.GoModPresent,
		Consent:        c.Consent,
		TaskIdentifier: "", // populated by the emit layer once the vuln list is known
	}
}
