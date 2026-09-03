// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg_test

import (
	"sync"
	"sync/atomic"

	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/bborbe/github-vuln-watcher/pkg"
)

var _ = ginkgo.Describe("CycleGate", func() {
	var gate pkg.CycleGate

	ginkgo.BeforeEach(func() {
		gate = pkg.NewCycleGate()
	})

	ginkgo.It("first TryAcquire succeeds", func() {
		Expect(gate.TryAcquire()).To(BeTrue())
	})

	ginkgo.It("second TryAcquire fails while the slot is held", func() {
		Expect(gate.TryAcquire()).To(BeTrue())
		Expect(gate.TryAcquire()).To(BeFalse())
	})

	ginkgo.It("TryAcquire succeeds again after Release", func() {
		Expect(gate.TryAcquire()).To(BeTrue())
		gate.Release()
		Expect(gate.TryAcquire()).To(BeTrue())
	})

	ginkgo.It("Release without holding the slot is a no-op and does not panic", func() {
		Expect(func() { gate.Release() }).NotTo(Panic())
		Expect(gate.TryAcquire()).To(BeTrue())
	})

	ginkgo.It("two goroutines racing TryAcquire yield exactly one winner", func() {
		var winners int64
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if gate.TryAcquire() {
					atomic.AddInt64(&winners, 1)
				}
			}()
		}
		wg.Wait()
		Expect(atomic.LoadInt64(&winners)).To(Equal(int64(1)))
	})
})
