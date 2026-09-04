// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/bborbe/errors"
	"github.com/golang/glog"
)

// ErrCloneFailed is returned when the git clone of a repo fails (exec error
// or non-zero exit). Callers map it to filter reason "clone_failed".
var ErrCloneFailed = stderrors.New("git clone failed")

// ParseGateTargets parses a comma-separated make-target list (the scanner's
// per-repo gate sequence). Whitespace is trimmed and empty entries dropped; an
// empty result falls back to the canonical "vulncheck,check" pair so a missing
// or blank GATE_TARGETS never produces a scanner that runs zero gates.
func ParseGateTargets(raw string) []string {
	if raw == "" {
		return []string{"vulncheck", "check"}
	}
	var targets []string
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		targets = append(targets, entry)
	}
	if len(targets) == 0 {
		return []string{"vulncheck", "check"}
	}
	return targets
}

// ErrGateTimeout is returned when the per-repo time bound expires during the
// clone or one of the repo's gates. Callers map it to "gate_timeout".
var ErrGateTimeout = stderrors.New("gate timed out")

// ErrScanFailed is returned when a gate cannot run, or a gate exits non-zero
// with no vuln markers (a broken repo is not a vuln-drift signal). Callers
// map it to "scan_failed".
var ErrScanFailed = stderrors.New("gate scan failed")

// goMarkerPattern and cveMarkerPattern match the two marker families the
// classification extracts from gate output. The full ID carries a second
// numeric segment (govulncheck OSV IDs are GO-YYYY-NNNN; CVEs are
// CVE-YYYY-NNNN), so both segments are matched.
var (
	goMarkerPattern  = regexp.MustCompile(`GO-\d+-\d+`)
	cveMarkerPattern = regexp.MustCompile(`CVE-\d+-\d+`)
)

// ScanResult is the outcome of scanning one repo: its HEAD SHA and the
// canonical (deduped, sorted) vuln marker list found in the gate output.
type ScanResult struct {
	HeadSHA string
	VulnIDs []string
}

//counterfeiter:generate -o ../mocks/scanner.go --fake-name Scanner . Scanner

// Scanner clones a repo and runs its own vuln gates. It is NOT a vuln
// scanner: suppression (VULNCHECK_IGNORE, .trivyignore, .osv-scanner.toml)
// is applied only by the repo's own gates, never here.
type Scanner interface {
	// Scan clones repo (full clone from repo.CloneURL, never shallow) into
	// an ephemeral directory, runs the repo's own configured gate targets
	// (`make <target>` for each, default `vulncheck` then `check`), and
	// returns the canonical marker list plus the cloned HEAD SHA.
	//
	// Classified errors (callers map to skip reasons):
	//   - ErrCloneFailed  -> "clone_failed"  (git clone exec error or non-zero exit)
	//   - ErrGateTimeout  -> "gate_timeout"  (the per-repo bound expired during clone or a gate)
	//   - ErrScanFailed   -> "scan_failed"   (a gate could not run, or a gate exited non-zero with no markers)
	//   - (ScanResult{}, nil) -> "already_clean" (both gates ran and no markers were found)
	Scan(ctx context.Context, repo Repo) (ScanResult, error)
}

// NewScanner returns a Scanner that clones with the git binary and runs the
// repo's own gates. gateTimeout is the hard bound for the whole per-repo scan
// (clone + all gates) — 20 minutes in production wiring. gateTargets is the
// ordered make-target list to run (production default "vulncheck,check";
// deploy manifests may trim it to "vulncheck" alone when the full `make
// check` compile over a monorepo exceeds the pod memory budget). tempDir is
// the parent for the ephemeral clone directories ("" = system temp; fixture
// tests pass a dedicated root to assert clone-dir cleanup).
func NewScanner(gateTimeout time.Duration, tempDir string, gateTargets []string) Scanner {
	return &scanner{
		gateTimeout: gateTimeout,
		tempDir:     tempDir,
		gateTargets: gateTargets,
	}
}

type scanner struct {
	gateTimeout time.Duration
	tempDir     string
	gateTargets []string
}

// scanEnv is the subprocess environment allowlist. Gate subprocesses run the
// repo's own Makefile, which is attacker-controlled code, so they never
// receive the watcher's full environment (which contains Kafka and GitHub
// credentials). HOME+PATH is all `git` and `make` need.
func scanEnv() []string {
	return []string{
		"HOME=" + os.Getenv("HOME"),
		"PATH=" + os.Getenv("PATH"),
	}
}

// configureSubprocess makes exec.CommandContext's cancellation kill the whole
// process group rather than just the direct child. Killing only the child
// orphans its descendants (e.g. a gate's `sleep`), which keep the command's
// I/O pipes open — CombinedOutput would then block past the gate timeout
// instead of returning. WaitDelay bounds that wait as a last resort.
func configureSubprocess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil &&
			!stderrors.Is(err, syscall.ESRCH) {
			return err
		}
		return os.ErrProcessDone
	}
	cmd.WaitDelay = 5 * time.Second
}

// maxGateOutputBytes bounds the captured stdout+stderr of each gate
// subprocess. The 20-minute timeout bounds duration, not volume — an
// attacker-controlled or supply-chain-compromised Makefile printing
// unbounded output would otherwise exhaust pod memory (deploy manifest ships
// a 50Mi limit). Markers (GO-/CVE- ids) fit far within the cap.
const maxGateOutputBytes = 4 << 20

// cappedWriter discards writes beyond max bytes, bounding memory while
// preserving the leading output the marker classification reads.
type cappedWriter struct {
	buf       *bytes.Buffer
	remaining int
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return len(p), nil
	}
	n := len(p)
	if n > w.remaining {
		n = w.remaining
	}
	w.buf.Write(p[:n])
	w.remaining -= n
	return len(p), nil
}

func (s *scanner) Scan(ctx context.Context, repo Repo) (ScanResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.gateTimeout)
	defer cancel()

	cloneDir, err := os.MkdirTemp(s.tempDir, "github-vuln-watcher-*")
	if err != nil {
		return ScanResult{}, errors.Wrapf(ctx, err, "create clone dir for %s", repo.Key())
	}
	defer func() {
		if err := os.RemoveAll(cloneDir); err != nil {
			glog.Warningf(
				"remove clone dir repo=%s dir=%s err=%v",
				repo.Key(),
				cloneDir,
				err,
			)
		}
	}()

	cloneURL := repo.CloneURL
	if cloneURL == "" {
		// HTTPS, not SSH: the runtime image has no openssh-client and no SSH key
		// (security isolation — gates from cloned repos must never read a key).
		// The fleet is public, so an unauthenticated HTTPS clone works for the
		// scan; the agent authenticates later for the fix.
		cloneURL = fmt.Sprintf("https://github.com/%s/%s.git", repo.Owner, repo.Name)
	}

	// #nosec G204 -- git binary is hardcoded; cloneURL is the repo's own
	// CloneURL or derived from charset-validated owner/name, cloneDir is a
	// fresh MkdirTemp dir.
	clone := exec.CommandContext(ctx, "git", "clone", cloneURL, cloneDir)
	glog.Infof("git clone repo=%s url=%s", repo.Key(), cloneURL)
	clone.Env = scanEnv()
	configureSubprocess(clone)
	out, cerr := clone.CombinedOutput()
	if cerr != nil {
		if ctx.Err() != nil {
			return ScanResult{}, ErrGateTimeout
		}
		glog.Warningf(
			"git clone failed repo=%s err=%v out=%s",
			repo.Key(),
			cerr,
			out,
		)
		return ScanResult{}, ErrCloneFailed
	}
	glog.Infof("git clone ok repo=%s url=%s", repo.Key(), cloneURL)

	var combined bytes.Buffer
	anyGateFailed := false
	for _, target := range s.gateTargets {
		// #nosec G204 -- make binary is hardcoded; target is a fixed loop
		// constant, cloneDir is the ephemeral clone dir.
		gate := exec.CommandContext(ctx, "make", target)
		glog.Infof("run gate repo=%s target=%s", repo.Key(), target)
		gate.Dir = cloneDir
		gate.Env = scanEnv()
		configureSubprocess(gate)
		capw := &cappedWriter{buf: &combined, remaining: maxGateOutputBytes}
		gate.Stdout = capw
		gate.Stderr = capw
		gerr := gate.Run()
		if gerr != nil {
			if ctx.Err() != nil {
				return ScanResult{}, ErrGateTimeout
			}
			// exec-start failure (make missing, no Makefile) and non-zero exit
			// are both recorded here; classification below decides whether this
			// is a vuln-drift signal.
			glog.Warningf("run gate failed repo=%s target=%s err=%v", repo.Key(), target, gerr)
			anyGateFailed = true
		} else {
			glog.Infof("run gate ok repo=%s target=%s", repo.Key(), target)
		}
	}

	markers := extractMarkers(combined.String())
	if len(markers) == 0 {
		if anyGateFailed {
			return ScanResult{}, ErrScanFailed
		}
		return ScanResult{}, nil // both gates green, no markers -> "already_clean"
	}
	headSHA, err := gitHeadSHA(ctx, cloneDir)
	if err != nil {
		return ScanResult{}, ErrScanFailed
	}
	return ScanResult{HeadSHA: headSHA, VulnIDs: markers}, nil
}

// extractMarkers returns the deduped, lexicographically-sorted list of
// GO-<year>-<id> / CVE-<year>-<id> markers in output.
func extractMarkers(output string) []string {
	seen := make(map[string]struct{})
	for _, re := range []*regexp.Regexp{goMarkerPattern, cveMarkerPattern} {
		for _, m := range re.FindAllString(output, -1) {
			seen[m] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// gitHeadSHA returns the full HEAD SHA of the repo in dir.
func gitHeadSHA(ctx context.Context, dir string) (string, error) {
	// #nosec G204 -- git binary is hardcoded; dir is the ephemeral clone dir.
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	glog.Infof("git rev-parse HEAD dir=%s", dir)
	cmd.Dir = dir
	cmd.Env = scanEnv()
	configureSubprocess(cmd)
	out, err := cmd.Output()
	if err != nil {
		glog.Warningf("git rev-parse failed dir=%s err=%v", dir, err)
		return "", err
	}
	sha := strings.TrimSpace(string(out))
	glog.Infof("git rev-parse ok dir=%s sha=%s", dir, sha)
	return sha, nil
}
