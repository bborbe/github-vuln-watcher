// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg

import (
	"context"
	"encoding/json"
	"os"

	"github.com/bborbe/errors"
	"github.com/golang/glog"
)

// DefaultCursorPath is the default persistent-memory location of the JSON
// cursor file. It is mounted from a PVC at /data so the watcher's memory
// survives restarts.
const DefaultCursorPath = "/data/cursor.json"

// Cursor is the per-repo finding-set dedup state.
//
// Concurrency: not safe for concurrent use. Exactly one cycle runs at a time
// (CycleGate), so the file has a single writer — the cycle loads at start and
// saves at end.
type Cursor struct {
	Repos map[string]*RepoState `json:"repos"` // key: Repo.Key(), "github.com/owner/name"
}

// RepoState is the cursor entry per repo.
type RepoState struct {
	// LastEmittedTaskIdentifier is the deterministic task identifier of the
	// last finding set emitted for this repo. A repo whose computed
	// identifier equals this is skipped with reason "finding_set_unchanged".
	LastEmittedTaskIdentifier string `json:"last_emitted_task_identifier"`
}

// LoadCursor reads cursor state from path.
//
//   - Missing file -> fresh empty cursor, nil error (cold start is valid and
//     re-publishes; downstream dedup by deterministic identifier absorbs it).
//   - Corrupt JSON -> the file is renamed to <path>.corrupt and the cycle
//     cold-starts. This re-files repos already reported, which deterministic
//     UUID5 task identifiers dedup downstream; returning an error here would
//     wedge every cycle indefinitely because nothing rewrites a file that
//     fails to load.
//   - Unreadable file (permissions, I/O) -> error. That is an environment
//     fault, not bad content, and the caller counts poll_cycle_total
//     {result="scan_error"}.
func LoadCursor(ctx context.Context, path string) (*Cursor, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is config-controlled
	if os.IsNotExist(err) {
		glog.V(2).Infof("cursor file not found, cold-start path=%s", path)
		return &Cursor{Repos: make(map[string]*RepoState)}, nil
	}
	if err != nil {
		return nil, errors.Wrapf(ctx, err, "read cursor file path=%s", path)
	}
	c := &Cursor{}
	if err := json.Unmarshal(data, c); err != nil {
		bad := path + ".corrupt"
		if rerr := os.Rename(path, bad); rerr != nil {
			glog.Warningf("preserve corrupt cursor failed path=%s err=%v", path, rerr)
		}
		glog.Warningf("cursor corrupt, cold-starting path=%s saved=%s err=%v", path, bad, err)
		return &Cursor{Repos: make(map[string]*RepoState)}, nil
	}
	if c.Repos == nil {
		c.Repos = make(map[string]*RepoState)
	}
	return c, nil
}

// SaveCursor persists cursor state atomically via temp file + rename, so a
// crash mid-write can never leave a half-written file and no .tmp file
// survives a successful save.
func SaveCursor(ctx context.Context, path string, c *Cursor) error {
	data, err := json.Marshal(c)
	if err != nil {
		return errors.Wrapf(ctx, err, "marshal cursor state path=%s", path)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil { // #nosec G306 -- intentional 0600
		return errors.Wrapf(ctx, err, "write cursor tmp path=%s", tmp)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return errors.Wrapf(ctx, err, "rename cursor tmp path=%s", tmp)
	}
	return nil
}
