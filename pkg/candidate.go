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

// TaskIdentifier returns the deterministic UUID5 of the candidate's finding
// set, or "" when no vulns are known yet. Seeded from (repo, sorted vuln IDs)
// only — never from the HEAD SHA or a timestamp (spec Constraints).
func (c Candidate) TaskIdentifier() string {
	if len(c.VulnIDs) == 0 {
		return ""
	}
	return DeriveVulnTaskID(c.Repo.Owner, c.Repo.Name, c.VulnIDs).String()
}

// FilterCandidate projects this observation onto the filter package's input.
func (c Candidate) FilterCandidate() filter.Candidate {
	return filter.Candidate{
		RepoKey:        c.Repo.Key(),
		HeadSHA:        c.HeadSHA,
		GoModPresent:   c.GoModPresent,
		Consent:        c.Consent,
		TaskIdentifier: c.TaskIdentifier(),
	}
}
