// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filter

// NewAutoUpdateFilter is the per-repo trust gate sourced from
// `.maintainer.yaml: goUpdate.autoUpdate`. It is POSITIVE OPT-IN: only
// Consent == GrantedConsent passes. RefusedConsent, UndecidedConsent, and any
// other/invalid Consent value (including the zero value) all return
// "auto_update_disabled" — the vuln watcher does not distinguish "refused"
// from "not answered".
//
// This gate is the only thing that turns this service's attention into agent
// action on somebody else's repository. There is deliberately no flag, env
// var, or code path that disables it or defaults any non-granted value to
// consent.
func NewAutoUpdateFilter() TaskCreationFilter {
	return TaskCreationFilterFunc(func(candidate Candidate) string {
		if candidate.Consent == GrantedConsent {
			return ""
		}
		return "auto_update_disabled"
	})
}
