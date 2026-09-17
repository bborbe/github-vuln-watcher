// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg_test

import (
	"context"
	"encoding/base64"
	stderrors "errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/bborbe/github-vuln-watcher/mocks"
	"github.com/bborbe/github-vuln-watcher/pkg"
)

// authSentinel is the credential the recording token source mints. It never
// leaves the scanner's clone subprocess, so every assertion below is a
// zero-match check against it (and against its base64 header form).
const authSentinel = "ghs_sentinel"

// authHeaderPayload is the base64 form of the Basic authorization header the
// clone receives. The encoded form contains no part of the literal sentinel,
// so a literal-only search cannot see it — hence both are asserted separately.
func authHeaderPayload() string {
	return base64.StdEncoding.EncodeToString([]byte("x-access-token:" + authSentinel))
}

// gitInvocation is one recorded `git` subprocess: the argv it was called with,
// the environment it actually received, and its working directory.
type gitInvocation struct {
	argv []string
	env  []string
	cwd  string
}

// installRecordingGitShim writes an executable `git` shim into a fresh temp dir
// and prepends that dir to PATH for the rest of the spec. Each shim run records
// its own invocation (argv, env, cwd) into its own directory under recordRoot,
// then delegates to the real git binary.
func installRecordingGitShim(recordRoot string) {
	// Resolve the real binary BEFORE touching PATH: a relative `git` call from
	// inside the shim would recurse into the shim forever.
	realGit, err := exec.LookPath("git")
	Expect(err).NotTo(HaveOccurred())

	shimDir := ginkgo.GinkgoT().TempDir()
	// recordRoot is baked into the script text: the scanner replaces the child
	// environment with its own HOME+PATH allowlist, so no custom variable would
	// survive to the shim. Nothing is passed to the shim via env.
	//
	// $$ is unique per invocation (a fresh shell per call), so no index or lock
	// is needed and no two invocations share a record directory.
	script := "#!/bin/sh\n" +
		"d=\"" + recordRoot + "/$$\"\n" +
		"mkdir -p \"$d\"\n" +
		"printf '%s\\n' \"$@\" > \"$d/argv\"\n" +
		"env > \"$d/env\"\n" +
		"pwd > \"$d/cwd\"\n" +
		"exec \"" + realGit + "\" \"$@\"\n"
	Expect(os.WriteFile(filepath.Join(shimDir, "git"), []byte(script), 0o755)).To(Succeed())
	ginkgo.GinkgoT().Setenv(
		"PATH",
		shimDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
}

// recordedGitInvocations reads every shim record directory under recordRoot.
func recordedGitInvocations(recordRoot string) []gitInvocation {
	entries, err := os.ReadDir(recordRoot)
	Expect(err).NotTo(HaveOccurred())
	invocations := make([]gitInvocation, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(recordRoot, entry.Name())
		invocations = append(invocations, gitInvocation{
			argv: nonEmptyLines(readFileString(filepath.Join(dir, "argv"))),
			env:  nonEmptyLines(readFileString(filepath.Join(dir, "env"))),
			cwd:  strings.TrimSpace(readFileString(filepath.Join(dir, "cwd"))),
		})
	}
	return invocations
}

// cloneInvocation returns the one recorded invocation whose argv[0] is "clone".
// Invocations are identified by argv, never by index: a single scan also runs
// `git rev-parse HEAD`, and the fixture Makefile shells out to git as well.
func cloneInvocation(invocations []gitInvocation) (gitInvocation, bool) {
	for _, invocation := range invocations {
		if len(invocation.argv) > 0 && invocation.argv[0] == "clone" {
			return invocation, true
		}
	}
	return gitInvocation{}, false
}

// tokenSourceReturning builds a TokenSource mock whose Token always returns
// (token, err). Counterfeiter's TokenReturns is a method, not a struct field,
// so it cannot appear in a composite literal.
func tokenSourceReturning(token string, err error) *mocks.TokenSource {
	source := &mocks.TokenSource{}
	source.TokenReturns(token, err)
	return source
}

func readFileString(path string) string {
	data, err := os.ReadFile(path)
	Expect(err).NotTo(HaveOccurred())
	return string(data)
}

func nonEmptyLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// envValue returns the value of the NAME=... entry in env.
func envValue(env []string, name string) (string, bool) {
	prefix := name + "="
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix), true
		}
	}
	return "", false
}

// authFixtureMakefile builds the fixture repo's Makefile. The gate recipes
// write their evidence into evidenceDir, which lives OUTSIDE the clone
// directory: the Makefile itself is checked out inside the clone, so a
// credential pattern inlined here would match its own fixture and the
// "no clone-directory file contains the credential" assertion could never pass.
func authFixtureMakefile(evidenceDir string, realGit string) string {
	probe := func(name string, cmd string) string {
		return "\t@" + cmd + " > " + filepath.Join(evidenceDir, name) + " 2>&1 || true\n"
	}
	grepProbe := func(name string, patternFile string) string {
		return probe(
			name,
			"grep -rlF -e \"$$(cat "+filepath.Join(evidenceDir, patternFile)+")\" .",
		)
	}
	// make-probe is not a gate, and it is deliberately last so the fixture's
	// default goal stays vulncheck. The spec runs it directly, with exactly
	// HOME and PATH in its environment, to discover which variables make
	// itself injects into a recipe on this platform — so the gate-environment
	// allowlist can be derived rather than enumerated.
	return "vulncheck:\n" +
		probe("gate-env-vulncheck.txt", "env | sort") +
		probe("remote-origin-url.txt", realGit+" config --get remote.origin.url") +
		grepProbe("clone-dir-grep-token.txt", "token-form.txt") +
		grepProbe("clone-dir-grep-header.txt", "header-form.txt") +
		// Positive control: the same grep+cat mechanism run against a
		// directory that DOES contain the pattern. Without it, a missing grep
		// binary would make both clone-dir greps fail silently and the
		// "no credential on disk" assertion would pass vacuously.
		probe(
			"grep-control.txt",
			"grep -rlF -e \"$$(cat "+filepath.Join(evidenceDir, "token-form.txt")+")\" "+
				evidenceDir,
		) +
		"\t@echo \"GO-2024-1234\\tgithub.com/example/mod@v1.0.0 -> v1.0.1\\tsummary\"\n" +
		"\t@exit 1\n" +
		"check:\n" +
		probe("gate-env-check.txt", "env | sort") +
		"\t@echo \"check ok\"\n" +
		"make-probe:\n" +
		probe("make-probe.txt", "(env | sort; echo MAKE_PROBE_RAN=1)")
}

// scanCapturingStderr runs fn with glog's WARN/INFO output redirected into a
// temp file, and returns the captured text plus fn's error.
//
// A file is used rather than an os.Pipe: a pipe whose buffer fills would
// deadlock the scan. alsologtostderr is what makes the WARNING reach the
// stderr sink at all; the sink resolves os.Stderr at write time, so swapping
// the variable is enough — no pipe, no goroutine, no buffer limit.
func scanCapturingStderr(fn func(ctx context.Context) error) (string, error) {
	Expect(flag.Set("alsologtostderr", "true")).To(Succeed())
	defer func() {
		Expect(flag.Set("alsologtostderr", "false")).To(Succeed())
	}()

	f, err := os.CreateTemp("", "scan-stderr-*")
	Expect(err).NotTo(HaveOccurred())

	saved := os.Stderr
	os.Stderr = f
	scanErr := fn(context.Background())
	os.Stderr = saved

	Expect(f.Close()).To(Succeed())
	return readFileString(f.Name()), scanErr
}

// makeProbeMarker is the line the make-probe recipe appends after dumping its
// own environment. It is the proof that the probe ran: without it, a missing
// or stale make-probe.txt would be indistinguishable from a capture that
// succeeded and simply found nothing.
const makeProbeMarker = "MAKE_PROBE_RAN"

// authScanFixture is the shared per-spec setup for both describes below: a
// fixture repo whose gates dump their own environment and clone directory
// contents, plus the recording git shim.
type authScanFixture struct {
	fixtureDir  string
	evidenceDir string
	recordRoot  string
	realGit     string
}

func newAuthScanFixture() *authScanFixture {
	realGit, err := exec.LookPath("git")
	Expect(err).NotTo(HaveOccurred())

	evidenceDir := ginkgo.GinkgoT().TempDir()
	recordRoot := ginkgo.GinkgoT().TempDir()

	// The two credential forms are written by the test into the evidence
	// directory (outside the clone) and read at recipe time by `cat`.
	Expect(os.WriteFile(
		filepath.Join(evidenceDir, "token-form.txt"),
		[]byte(authSentinel), 0o600,
	)).To(Succeed())
	Expect(os.WriteFile(
		filepath.Join(evidenceDir, "header-form.txt"),
		[]byte(authHeaderPayload()), 0o600,
	)).To(Succeed())

	// Create the fixture BEFORE installing the shim so fixture-setup git calls
	// are not recorded.
	fixtureDir := writeFixtureRepo(authFixtureMakefile(evidenceDir, realGit))
	installRecordingGitShim(recordRoot)

	return &authScanFixture{
		fixtureDir:  fixtureDir,
		evidenceDir: evidenceDir,
		recordRoot:  recordRoot,
		realGit:     realGit,
	}
}

func (f *authScanFixture) repo() pkg.Repo {
	return pkg.Repo{
		Owner:    "fixture-owner",
		Name:     "fixture-repo",
		CloneURL: f.fixtureDir,
	}
}

func (f *authScanFixture) evidence(name string) string {
	return readFileString(filepath.Join(f.evidenceDir, name))
}

func (f *authScanFixture) evidenceLines(name string) []string {
	return nonEmptyLines(f.evidence(name))
}

func (f *authScanFixture) invocations() []gitInvocation {
	return recordedGitInvocations(f.recordRoot)
}

// probeMakeEnv runs the fixture Makefile's make-probe target with exactly HOME
// and PATH in its environment and returns the set of variable names the recipe
// saw — including makeProbeMarker, which the caller must strip. Everything
// beyond HOME and PATH is make's own contribution on this platform, and that
// contribution differs between GNU make and Apple's make; deriving it here is
// what keeps the gate-environment assertion honest on both.
func (f *authScanFixture) probeMakeEnv() map[string]bool {
	cmd := exec.Command("make", "make-probe")
	cmd.Dir = f.fixtureDir
	cmd.Env = []string{
		"HOME=" + os.Getenv("HOME"),
		"PATH=" + os.Getenv("PATH"),
	}
	out, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "make make-probe: %s", out)

	names := make(map[string]bool)
	for _, line := range nonEmptyLines(
		readFileString(filepath.Join(f.evidenceDir, "make-probe.txt")),
	) {
		names[strings.SplitN(line, "=", 2)[0]] = true
	}
	return names
}

// firstDisallowedEnvVar returns the name of the first entry in observed (a
// list of NAME=value lines) that is not in allowed, or "" when every observed
// name is allowed. This is the anti-widening half of the gate-environment
// assertion: allowed is derived from the real make binary at test time, so a
// variable that is neither HOME, PATH, nor something make introduced still
// fails the check on every platform.
func firstDisallowedEnvVar(observed []string, allowed map[string]bool) string {
	for _, line := range observed {
		name := strings.SplitN(line, "=", 2)[0]
		if !allowed[name] {
			return name
		}
	}
	return ""
}

var _ = ginkgo.Describe("scan-stage clone credentials", func() {
	var (
		fixture     *authScanFixture
		payload     string
		logs        string
		scanErr     error
		invocations []gitInvocation
	)

	ginkgo.BeforeEach(func() {
		payload = authHeaderPayload()
		fixture = newAuthScanFixture()

		scanner := pkg.NewScanner(
			60*time.Second,
			"",
			[]string{"vulncheck", "check"},
			tokenSourceReturning(authSentinel, nil),
		)
		logs, scanErr = scanCapturingStderr(func(ctx context.Context) error {
			_, err := scanner.Scan(ctx, fixture.repo())
			return err
		})
		invocations = fixture.invocations()
	})

	ginkgo.It("passes the credential to the real clone process environment", func() {
		Expect(scanErr).NotTo(HaveOccurred())
		clone, ok := cloneInvocation(invocations)
		Expect(ok).To(BeTrue(), "no recorded git clone invocation")

		Expect(clone.env).To(ContainElement("GIT_CONFIG_COUNT=1"))
		Expect(clone.env).To(ContainElement("GIT_CONFIG_KEY_0=http.extraheader"))

		header, ok := envValue(clone.env, "GIT_CONFIG_VALUE_0")
		Expect(ok).To(BeTrue(), "GIT_CONFIG_VALUE_0 missing from the clone env")
		fields := strings.Fields(header)
		Expect(fields).NotTo(BeEmpty())
		decoded, err := base64.StdEncoding.DecodeString(fields[len(fields)-1])
		Expect(err).NotTo(HaveOccurred())
		Expect(string(decoded)).To(Equal("x-access-token:" + authSentinel))
	})

	ginkgo.It("never puts the credential in the clone URL or in any argv", func() {
		clone, ok := cloneInvocation(invocations)
		Expect(ok).To(BeTrue(), "no recorded git clone invocation")

		Expect(clone.argv).To(HaveLen(3))
		Expect(clone.argv[0]).To(Equal("clone"))
		Expect(clone.argv[1]).To(Equal(fixture.fixtureDir))
		Expect(clone.argv[2]).NotTo(BeEmpty())
		Expect(clone.argv[2]).NotTo(Equal(fixture.fixtureDir))

		for _, invocation := range invocations {
			for _, arg := range invocation.argv {
				Expect(arg).NotTo(ContainSubstring(authSentinel))
				Expect(arg).NotTo(ContainSubstring(payload))
			}
		}
	})

	ginkgo.It("gives the scanned repo's own gates the frozen HOME+PATH allowlist", func() {
		// An exact two-line equality can never pass: make injects its own
		// variables into every recipe's environment, so the gate sees more than
		// two lines. WHICH variables those are is platform-dependent, so the
		// allowed set is derived by running the real make binary on the
		// fixture's make-probe target rather than enumerated here — a hardcoded
		// list is exactly right on the platform it was written on and wrong on
		// the next one. The check itself stays positive: every observed name
		// must be allowed. An absence-only assertion could not catch a widening
		// that introduced a *different* variable (KAFKA_BROKERS, SENTRY_DSN)
		// that no denylist names.
		probed := fixture.probeMakeEnv()
		Expect(probed).To(HaveKey(makeProbeMarker),
			"the make-probe target did not run, so nothing was derived")
		delete(probed, makeProbeMarker)

		allowed := map[string]bool{"HOME": true, "PATH": true}
		beyond := map[string]bool{}
		for name := range probed {
			allowed[name] = true
			if name != "HOME" && name != "PATH" {
				beyond[name] = true
			}
		}
		// The derivation must have produced something: an empty beyond set
		// would mean the probe captured nothing and the check below would be
		// vacuous.
		Expect(beyond).NotTo(BeEmpty(), "the probe derived nothing beyond HOME and PATH")

		for _, name := range []string{"gate-env-vulncheck.txt", "gate-env-check.txt"} {
			lines := fixture.evidenceLines(name)
			Expect(lines).To(ContainElement("HOME=" + os.Getenv("HOME")))
			Expect(lines).To(ContainElement("PATH=" + os.Getenv("PATH")))

			offender := firstDisallowedEnvVar(lines, allowed)
			Expect(offender).To(BeEmpty(), "unexpected env var reached a gate: %s", offender)

			// Positive control: a gate is a make recipe, so it must show at
			// least one of the variables the probe derived. A gate invoked some
			// other way would otherwise satisfy the check above vacuously.
			sawMakeInjected := false
			for _, line := range lines {
				if beyond[strings.SplitN(line, "=", 2)[0]] {
					sawMakeInjected = true
				}
				Expect(line).NotTo(MatchRegexp(`GIT_CONFIG|Authorization`))
				Expect(line).NotTo(ContainSubstring(authSentinel))
				Expect(line).NotTo(ContainSubstring(payload))
			}
			Expect(sawMakeInjected).To(BeTrue(),
				"no make-injected variable reached the gate")
		}
	})

	ginkgo.It("persists nothing credential-bearing into the clone directory", func() {
		origin := strings.TrimSpace(fixture.evidence("remote-origin-url.txt"))
		Expect(origin).To(Equal(fixture.fixtureDir))
		Expect(origin).NotTo(ContainSubstring("@"))
		Expect(origin).NotTo(ContainSubstring(authSentinel))
		Expect(origin).NotTo(ContainSubstring(payload))

		// Positive control first: the grep probes are live and the pattern
		// actually matches, so the two empty results below are real negatives
		// rather than a silently broken probe.
		Expect(fixture.evidence("grep-control.txt")).
			To(ContainSubstring("token-form.txt"))

		Expect(fixture.evidence("clone-dir-grep-token.txt")).To(BeEmpty())
		Expect(fixture.evidence("clone-dir-grep-header.txt")).To(BeEmpty())
	})

	ginkgo.It("never logs the credential, its prefix, or its encoded form", func() {
		// Prove the capture is live first: a capture that silently produced
		// nothing would make every zero-match assertion below vacuous.
		Expect(logs).To(ContainSubstring(
			"git clone ok repo=github.com/fixture-owner/fixture-repo"))

		Expect(logs).NotTo(ContainSubstring(authSentinel))
		Expect(logs).NotTo(ContainSubstring(payload))
		Expect(logs).NotTo(ContainSubstring("ghs_sent"))
	})
})

var _ = ginkgo.Describe("firstDisallowedEnvVar", func() {
	// The derived allowlist is HOME and PATH plus whatever make adds on this
	// platform. The helper must tolerate that second part without tolerating
	// anything else — the two specs below pin both directions.
	ginkgo.It("derived allowlist rejects a variable neither HOME, PATH nor make added", func() {
		allowed := map[string]bool{"HOME": true, "PATH": true, "INJECTED_BY_MAKE": true}
		observed := []string{
			"HOME=/root",
			"PATH=/usr/bin",
			"INJECTED_BY_MAKE=1",
			"KAFKA_BROKERS=broker:9092",
		}
		Expect(firstDisallowedEnvVar(observed, allowed)).To(Equal("KAFKA_BROKERS"))
	})

	ginkgo.It("derived allowlist accepts a variable make added on this platform", func() {
		fixture := newAuthScanFixture()
		probed := fixture.probeMakeEnv()
		Expect(probed).To(HaveKey(makeProbeMarker),
			"the make-probe target did not run, so nothing was derived")
		delete(probed, makeProbeMarker)

		added := ""
		for name := range probed {
			if name != "HOME" && name != "PATH" {
				added = name
				break
			}
		}
		Expect(added).NotTo(BeEmpty(), "the probe derived nothing beyond HOME and PATH")

		observed := []string{"HOME=/root", "PATH=/usr/bin", added + "=1"}
		Expect(firstDisallowedEnvVar(observed, probed)).To(BeEmpty())
	})
})

var _ = ginkgo.Describe("TokenSourceOf", func() {
	ginkgo.It("returns the token source the scanner was built with", func() {
		source := tokenSourceReturning(authSentinel, nil)
		scanner := pkg.NewScanner(time.Minute, "", []string{"vulncheck"}, source)
		Expect(pkg.TokenSourceOf(scanner)).To(BeIdenticalTo(source))
	})

	ginkgo.It("returns nil for an unauthenticated scanner", func() {
		scanner := pkg.NewScanner(time.Minute, "", []string{"vulncheck"}, nil)
		Expect(pkg.TokenSourceOf(scanner)).To(BeNil())
	})

	ginkgo.It("returns nil for a Scanner it did not build", func() {
		Expect(pkg.TokenSourceOf(&mocks.Scanner{})).To(BeNil())
	})
})

var _ = ginkgo.Describe("scan-stage clone fallbacks", func() {
	var (
		fixture *authScanFixture
		payload string
	)

	ginkgo.BeforeEach(func() {
		payload = authHeaderPayload()
		fixture = newAuthScanFixture()
	})

	scan := func(scanner pkg.Scanner, repo pkg.Repo) (string, error) {
		return scanCapturingStderr(func(ctx context.Context) error {
			_, err := scanner.Scan(ctx, repo)
			return err
		})
	}

	scannerFor := func(gateTimeout time.Duration, source pkg.TokenSource) pkg.Scanner {
		return pkg.NewScanner(gateTimeout, "", []string{"vulncheck", "check"}, source)
	}

	ginkgo.It("degrades to today's unauthenticated clone when the mint fails", func() {
		scanner := scannerFor(
			60*time.Second,
			tokenSourceReturning("", stderrors.New("mint boom")),
		)
		logs, err := scan(scanner, fixture.repo())
		Expect(err).NotTo(HaveOccurred())

		clone, ok := cloneInvocation(fixture.invocations())
		Expect(ok).To(BeTrue(), "no recorded git clone invocation")
		Expect(clone.env).NotTo(ContainElement(HavePrefix("GIT_CONFIG_")))

		Expect(logs).To(ContainSubstring("mint installation token failed"))
		Expect(logs).To(ContainSubstring("mint boom"))
		Expect(logs).NotTo(ContainSubstring(authSentinel))
		Expect(logs).NotTo(ContainSubstring(payload))
	})

	ginkgo.It("clones unauthenticated when no token source is configured", func() {
		logs, err := scan(scannerFor(60*time.Second, nil), fixture.repo())
		Expect(err).NotTo(HaveOccurred())

		clone, ok := cloneInvocation(fixture.invocations())
		Expect(ok).To(BeTrue(), "no recorded git clone invocation")
		Expect(clone.env).NotTo(ContainElement(HavePrefix("GIT_CONFIG_")))
		Expect(logs).NotTo(ContainSubstring("mint installation token failed"))
	})

	ginkgo.It("derives the HTTPS URL and still carries the credential", func() {
		// The credential env is attached regardless of the URL's scheme — that
		// is what makes this local-fixture harness meaningful. This clone is
		// never attempted against the real remote, so nothing is asserted about
		// the scan outcome: the shim records the invocation before delegating.
		scanner := scannerFor(
			2*time.Second,
			tokenSourceReturning(authSentinel, nil),
		)
		_, _ = scan(scanner, pkg.Repo{Owner: "fixture-owner", Name: "fixture-repo"})

		clone, ok := cloneInvocation(fixture.invocations())
		Expect(ok).To(BeTrue(), "no recorded git clone invocation")
		Expect(clone.argv).To(HaveLen(3))
		Expect(clone.argv[1]).
			To(Equal("https://github.com/fixture-owner/fixture-repo.git"))
		Expect(clone.env).To(ContainElement("GIT_CONFIG_COUNT=1"))
		Expect(clone.env).To(ContainElement("GIT_CONFIG_KEY_0=http.extraheader"))
	})

	ginkgo.It("bounds the mint with its own timeout", func() {
		// tokenMintTimeout is unexported, so the bound is asserted, not the
		// symbol. The gate timeout is a full minute: if the mint's own 30s bound
		// were dropped, the deadline handed to the token source would be the
		// gate timeout and this assertion would fail. Every other token source
		// in this file ignores its context, so this is the only guard against a
		// hung mint consuming the per-scan budget.
		var (
			calledAt    time.Time
			deadline    time.Time
			hasDeadline bool
		)
		source := &mocks.TokenSource{}
		source.TokenStub = func(ctx context.Context) (string, error) {
			calledAt = time.Now()
			deadline, hasDeadline = ctx.Deadline()
			return "", stderrors.New("mint boom")
		}

		_, err := scan(scannerFor(time.Minute, source), fixture.repo())
		Expect(err).NotTo(HaveOccurred())

		Expect(hasDeadline).To(BeTrue(), "the mint received no deadline")
		Expect(deadline).To(BeTemporally(">", calledAt))
		Expect(deadline.Sub(calledAt)).To(BeNumerically("<=", 30*time.Second))
	})
})
