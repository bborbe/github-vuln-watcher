// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg

// DefaultCursorPath is the default persistent-memory location of the JSON
// cursor file. It is mounted from a PVC at /data so the watcher's memory
// survives restarts.
const DefaultCursorPath = "/data/cursor.json"
