// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// vulnTaskIDNamespace is the UUID5 namespace for github-update-go vuln-drift
// tasks. Frozen: changing it would break the task controller's dedup and
// re-file every open work item.
var vulnTaskIDNamespace = uuid.MustParse("5c3bcb6b-fb0f-4c61-a4c3-8a17fd037f52")

// DeriveVulnTaskID returns a UUID5 derived deterministically from
// (owner, repo, sorted deduped vuln IDs) via the seed
// "vuln-drift-<owner>-<repo>-<comma-joined-sorted-ids>" (spec Constraints).
// The vuln ID list is canonicalised (deduped + sorted) inside this function,
// so the identifier never depends on caller discipline. It deliberately
// excludes any HEAD SHA or timestamp — an unchanged finding set must always
// yield the same identifier.
func DeriveVulnTaskID(owner, repo string, vulnIDs []string) uuid.UUID {
	seed := fmt.Sprintf(
		"vuln-drift-%s-%s-%s",
		owner,
		repo,
		strings.Join(canonicalVulnIDs(vulnIDs), ","),
	)
	return uuid.NewSHA1(vulnTaskIDNamespace, []byte(seed))
}

// canonicalVulnIDs returns a deduped, lexicographically-sorted copy of ids.
func canonicalVulnIDs(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		seen[id] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
