// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filter

//counterfeiter:generate -o ../../mocks/cursor_reader.go --fake-name CursorReader . CursorReader

// CursorReader is the minimal read surface FindingSetUnchangedFilter needs.
// Declared locally (Hollywood principle) so this package never imports
// pkg.Cursor.
type CursorReader interface {
	// LastEmittedTaskIdentifier returns the recorded task identifier for
	// repoKey, or "" if unseen.
	LastEmittedTaskIdentifier(repoKey string) string
}

// NewFindingSetUnchangedFilter returns "finding_set_unchanged" when the
// Candidate's computed task identifier equals the recorded one for the same
// repo. A cold cursor always passes. This filter is evaluated POST-scan (it
// needs the computed identifier) and is omitted entirely on a forced cycle
// (spec DB 5).
func NewFindingSetUnchangedFilter(cursor CursorReader) TaskCreationFilter {
	return TaskCreationFilterFunc(func(candidate Candidate) string {
		if candidate.TaskIdentifier != "" &&
			candidate.TaskIdentifier == cursor.LastEmittedTaskIdentifier(candidate.RepoKey) {
			return "finding_set_unchanged"
		}
		return ""
	})
}
