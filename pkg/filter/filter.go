// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package filter implements the TaskCreationFilter chain — the predicates that
// decide whether a vuln-drift work item should be filed for one observed repo.
//
// Pre-scan chain order (frozen; the first non-empty reason wins):
//
//  1. RepoAllowlistFilter  -> "scope"                  — operator-configured scope
//  2. AutoUpdateFilter     -> "auto_update_disabled"   — consent gate (positive opt-in)
//  3. GoModPresentFilter   -> "no_gomod"               — repo has no go.mod
//
// The finding-set dedup filter (FindingSetUnchangedFilter) is NOT part of this
// pre-scan chain: it needs the scan result, so it is evaluated post-scan on a
// second, per-cycle pass (and omitted entirely on a forced cycle).
package filter

//counterfeiter:generate -o ../../mocks/task_creation_filter.go --fake-name TaskCreationFilter . TaskCreationFilter

// Candidate is the filter-evaluation input. It mirrors the watcher's per-repo
// observation as a local type so this package never imports pkg (pkg imports
// filter; the reverse would be an import cycle).
type Candidate struct {
	// RepoKey is the host-qualified key "github.com/<owner>/<name>".
	RepoKey string
	// HeadSHA is the full HEAD SHA of the default branch (populated by the
	// scan stage).
	HeadSHA string
	// GoModPresent is false when the repo has no go.mod at all.
	GoModPresent bool
	// Consent is the verdict of `.maintainer.yaml: goUpdate.autoUpdate`.
	Consent Consent
	// TaskIdentifier is the deterministic UUID5 of the repo's finding set
	// (populated by the emit layer once the vuln list is known; read by the
	// FindingSetUnchangedFilter).
	TaskIdentifier string
}

// TaskCreationFilter decides whether a single Candidate should be skipped.
// Implementations return the metric-label reason for the skip, or "" to pass
// through. Returning the reason (rather than a bool) means the caller never
// re-evaluates the predicates to work out which counter to bump.
type TaskCreationFilter interface {
	// Skip returns the skip reason (metric label) or "" to pass through.
	Skip(candidate Candidate) string
}

// TaskCreationFilterFunc adapts a function to the TaskCreationFilter interface.
type TaskCreationFilterFunc func(candidate Candidate) string

// Skip implements TaskCreationFilter for the function adapter.
func (f TaskCreationFilterFunc) Skip(candidate Candidate) string {
	return f(candidate)
}

// TaskCreationFilterList is a slice composite returning the first non-empty
// reason from its members. An empty slice never skips.
type TaskCreationFilterList []TaskCreationFilter

// Skip returns the first non-empty reason from any contained filter,
// short-circuiting on the first hit.
func (fs TaskCreationFilterList) Skip(candidate Candidate) string {
	for _, f := range fs {
		if reason := f.Skip(candidate); reason != "" {
			return reason
		}
	}
	return ""
}
