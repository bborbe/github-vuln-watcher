// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg

import (
	"context"

	"github.com/golang/glog"
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

// NewWatcher wires the cycle's collaborators. This prompt's skeleton wires
// only metrics, cursor path and owner; the remaining spec layers add the
// GitHub inventory client, the scan stage, the publisher and the filter chain.
func NewWatcher(
	metrics Metrics,
	cursorPath string,
	owner string,
) Watcher {
	return &watcher{
		metrics:    metrics,
		cursorPath: cursorPath,
		owner:      owner,
	}
}

type watcher struct {
	metrics    Metrics
	cursorPath string
	owner      string
}

func (w *watcher) Poll(ctx context.Context, force bool) error {
	// Skeleton cycle: the scan stages are added by the remaining spec layers.
	w.metrics.IncPollCycle("success")
	glog.V(2).Infof("poll cycle complete result=success")
	return nil
}
