// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg

import (
	"context"
	stderrors "errors"

	"github.com/golang/glog"

	"github.com/bborbe/github-vuln-watcher/pkg/filter"
)

//counterfeiter:generate -o ../mocks/watcher.go --fake-name Watcher . Watcher

// Watcher scans one GitHub owner for repos with vulnerable dependencies and
// publishes one CreateTaskCommand per qualifying repo.
type Watcher interface {
	// Poll runs one scan cycle. Safe to call repeatedly on an interval.
	//
	// force=true omits the finding-set dedup filter from this cycle (spec DB
	// 5), so an unchanged finding set is re-emitted. Every other gate still
	// applies. The interval loop always passes false; only /trigger passes
	// true.
	Poll(ctx context.Context, force bool) error
}

// NewWatcher wires the cycle's collaborators. taskCreationFilter is the
// cycle-invariant pre-scan chain built at wiring time; the finding-set dedup
// filter is composed in per cycle because it needs a fresh cursor (and is
// omitted on a forced cycle) — that layer arrives in a later prompt.
// scanner is the signal-stage collaborator that clones each consenting repo
// and runs its own vuln gates.
func NewWatcher(
	ghClient GitHubClient,
	scanner Scanner,
	metrics Metrics,
	cursorPath string,
	owner string,
	taskCreationFilter filter.TaskCreationFilter,
) Watcher {
	return &watcher{
		ghClient:           ghClient,
		scanner:            scanner,
		metrics:            metrics,
		cursorPath:         cursorPath,
		owner:              owner,
		taskCreationFilter: taskCreationFilter,
	}
}

type watcher struct {
	ghClient           GitHubClient
	scanner            Scanner
	metrics            Metrics
	cursorPath         string
	owner              string
	taskCreationFilter filter.TaskCreationFilter
}

func (w *watcher) Poll(ctx context.Context, force bool) error {
	repos, err := w.ghClient.ListRepos(ctx, w.owner)
	if err != nil {
		if stderrors.Is(err, ErrRateLimited) {
			w.metrics.IncPollCycle("rate_limited")
			glog.Warningf(
				"poll cycle aborted: rate limited during ListRepos owner=%s",
				w.owner,
			)
		} else {
			w.metrics.IncPollCycle("github_error")
			glog.Warningf(
				"poll cycle aborted: ListRepos owner=%s err=%v",
				w.owner,
				err,
			)
		}
		return nil
	}

	w.metrics.IncReposScanned(len(repos))

	if abortReason := w.processRepos(ctx, repos, w.taskCreationFilter); abortReason != "" {
		w.metrics.IncPollCycle(abortReason)
		return nil
	}

	w.metrics.IncPollCycle("success")
	glog.V(2).Infof("poll cycle complete result=success")
	return nil
}

func (w *watcher) processRepos(
	ctx context.Context,
	repos []Repo,
	cycleFilter filter.TaskCreationFilter,
) string {
	for _, repo := range repos {
		select {
		case <-ctx.Done():
			glog.V(2).Infof(
				"poll cancelled during processRepos at repo=%s",
				repo.Key(),
			)
			return ""
		default:
		}

		candidate, abortReason, dropped := w.gatherCandidate(ctx, repo)
		if abortReason != "" {
			return abortReason
		}
		if dropped {
			continue
		}

		if reason := cycleFilter.Skip(candidate.FilterCandidate()); reason != "" {
			w.metrics.IncFilterSkipped(reason)
			glog.V(2).Infof(
				"repo skipped repo=%s reason=%s",
				repo.Key(),
				reason,
			)
			continue
		}

		// Signal stage: clone + the repo's own gates.
		scanResult, scanErr := w.scanner.Scan(ctx, repo)
		if scanErr != nil {
			reason := classifyScanError(scanErr)
			w.metrics.IncFilterSkipped(reason)
			glog.V(2).Infof(
				"repo skipped repo=%s reason=%s",
				repo.Key(),
				reason,
			)
			continue
		}
		if len(scanResult.VulnIDs) == 0 {
			w.metrics.IncFilterSkipped("already_clean")
			glog.V(2).Infof(
				"repo skipped repo=%s reason=%s",
				repo.Key(),
				"already_clean",
			)
			continue
		}
		candidate.HeadSHA = scanResult.HeadSHA
		candidate.VulnIDs = scanResult.VulnIDs
		// Emit and dedup are added by the remaining spec layers.
	}
	return ""
}

// classifyScanError maps a Scanner error to its metric-label skip reason.
func classifyScanError(err error) string {
	switch {
	case stderrors.Is(err, ErrCloneFailed):
		return "clone_failed"
	case stderrors.Is(err, ErrGateTimeout):
		return "gate_timeout"
	default:
		return "scan_failed"
	}
}

func (w *watcher) gatherCandidate(
	ctx context.Context,
	repo Repo,
) (Candidate, string, bool) {
	goModContent, err := w.ghClient.GetGoMod(ctx, repo)
	if err != nil {
		if stderrors.Is(err, ErrRateLimited) {
			return Candidate{}, "rate_limited", false
		}
		return dropRepo(repo, "go_mod", err)
	}

	consent, err := w.ghClient.GetMaintainerConfig(ctx, repo)
	if err != nil {
		if stderrors.Is(err, ErrRateLimited) {
			return Candidate{}, "rate_limited", false
		}
		return dropRepo(repo, "maintainer_config", err)
	}

	candidate := Candidate{
		Repo:         repo,
		GoModPresent: goModContent != nil,
		Consent:      consent,
	}
	return candidate, "", false
}

// dropRepo logs the always-on per-repo drop line. The phrase
// "repo dropped from cycle" is the operator's grep handle — do not reword it.
func dropRepo(repo Repo, step string, err error) (Candidate, string, bool) {
	glog.Warningf(
		"repo dropped from cycle: owner=%s repo=%s step=%s err=%v",
		repo.Owner,
		repo.Name,
		step,
		err,
	)
	return Candidate{}, "", true
}
