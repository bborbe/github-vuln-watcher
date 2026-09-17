---
status: completed
summary: Made the gate-environment spec derive make's injected variables from the real make binary at test time (new `make-probe` fixture target + `firstDisallowedEnvVar` helper) instead of hardcoding them, so it passes on macOS and Linux alike; `make precommit` exits 0 and `pkg/scanner.go` is byte-identical.
execution_id: github-vuln-watcher-targetvault-exec-008-fix-gate-env-test-portability
dark-factory-version: dev
created: "2026-09-17"
queued: "2026-09-17T08:17:49Z"
started: "2026-09-17T08:18:06Z"
completed: "2026-09-17T08:23:47Z"
---

<summary>
- One test that guards what the scanned repo's own gates can see in their environment fails on macOS but passes on Linux CI.
- The gate is invoked as `make`, and `make` injects its own bookkeeping variables into every recipe's environment. Which variables it injects is platform-dependent: Apple's make adds MANPATH, Linux's make does not.
- The test lists those variables by hand, so its allowlist is exactly right on Linux and incomplete on macOS. This is a test-portability bug, not a production bug — the scanner really does pass only HOME and PATH, and nothing credential-bearing reaches a gate.
- The cost is not cosmetic: the suite is red on every macOS checkout, and the dark-factory daemon runs its baseline preflight on the host rather than in a container, so a red host suite stops the entire pipeline for this repository.
- The fix is to stop enumerating make's additions and derive them at test time, so the assertion is platform-independent without losing its intent.
- The intent must survive: a variable that is neither HOME, PATH, nor something make itself added must still fail the test. Only the source of the allowed set changes, not the strictness.
- Every existing credential assertion stays byte-identical — this prompt weakens nothing about what must NOT reach a gate.
</summary>

<objective>
Make the gate-environment test pass on macOS as well as Linux, and make it verifiable on Linux, without weakening the property it guards: a gate subprocess sees HOME and PATH and nothing else the scanner did not intend.
</objective>

<context>
Read `docs/dod.md` (this repo's definition of done — wired as the dark-factory validation prompt).

Read these coding plugin docs before writing code (paths are inside the container):
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-testing-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-test-types-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-error-wrapping-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/go-precommit.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/changelog-guide.md`
- `/home/node/.claude/plugins/marketplaces/coding/docs/definition-of-done.md`

Read these repo files before writing code:
- `pkg/scanner_auth_integration_test.go` — the spec `gives the scanned repo's own gates the frozen HOME+PATH allowlist` is the one that fails. Its fixture writes `gate-env-vulncheck.txt` / `gate-env-check.txt` from inside a real `make` recipe.
- `pkg/scanner.go` — `scanEnv()` is the production allowlist the scanner hands every gate, clone and `git rev-parse` subprocess. It returns HOME and PATH only. **Do not change it** — it is correct.
- `pkg/scanner_test.go` — the existing external-test-package fixture pattern (`writeFixtureRepo`). Note it reaches only exported API; there is no export shim for this file.

**Sibling-spec check (already run):** the only other spec asserting the gate environment is `pkg/scanner_test.go:194` ("gate subprocess sees only the allowlisted environment"). It asserts only that `VULN_WATCHER_SECRET` is absent and does not enumerate make's variables, so it passes on macOS today. **Do not change it** — it is not affected by this defect.

The failing evidence, reproduced on macOS (Apple make):

```
[FAILED] unexpected env var reached a gate: MANPATH=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/share/man:...
Expected <map[string]bool | len:6>: {"MAKELEVEL": true, "MAKEFLAGS": true, "MFLAGS": true, "PWD": true, "HOME": true, "PATH": true}
to have key <string>: MANPATH
```

On Linux the same spec passes, which is why CI is green and the defect is invisible there.

Constraint discovered while diagnosing this: the dark-factory daemon's baseline preflight executes on the **host**, not in a container, and on failure it captures only the subprocess's stderr — Ginkgo writes its failure block to stdout, so a failing suite is reported as `make: *** [test] Error 1` with no visible cause. That is why this prompt must make the fix provable from Linux, where the failure does not reproduce.
</context>

<requirements>
1. In `pkg/scanner_auth_integration_test.go`, replace the hardcoded `makeInjected` map with a set **derived at test time**. Derive it by invoking the real `make` binary with exactly `HOME` and `PATH` in its environment (an empty environment plus those two), on a probe target that prints its own environment. Whatever that probe shows beyond HOME and PATH is make's own contribution on this platform. The existing fixture Makefile is the place to add the probe target.

   The probe target must be named `make-probe`, live in the fixture Makefile (`authFixtureMakefile`), write its own environment to `<evidenceDir>/make-probe.txt`, and emit a `MAKE_PROBE_RAN=1` marker line into that file. The failing spec must derive the allowed set by parsing that file, and must assert the parsed set contains `MAKE_PROBE_RAN` (then exclude the marker from the allowed set). A hardcoded literal cannot contain a name that only the probe produces, so this makes the derivation provable on Linux even though the platform difference is not. Run the probe against the fixture Makefile in the fixture directory, with the probe command's `Env` set to exactly `HOME` and `PATH`.
2. Extract the comparison into an unexported helper with exactly this signature: `firstDisallowedEnvVar(observed []string, allowed map[string]bool) string`, returning the offending variable name or `""`. Place it in `pkg/scanner_auth_integration_test.go` or a sibling `_test.go` file in `package pkg_test`. Do **not** add an export shim — `pkg/githubclient_export_test.go` exists to expose *production* symbols to the external test package, and a helper that already lives in the test package needs none.
3. Add specs for the helper covering both directions, both of which must pass on Linux. Title both specs so each title contains the exact token `derived allowlist` (for example `It("derived allowlist rejects a variable neither HOME, PATH nor make added")` and `It("derived allowlist accepts a variable make added on this platform")`) — the verification greps for that token, and it occurs nowhere in the repo today:
   - a variable that is neither HOME, PATH, nor in the derived set **fails** the check — this is the anti-widening property and it must not regress;
   - a variable that IS in the derived set passes — this is the platform tolerance the fix exists for.
4. Keep the existing positive assertions in the failing spec: HOME and PATH must be present with the exact values the scanner passes, and the credential assertions (`GIT_CONFIG`, `Authorization`, the auth sentinel, the payload) must be byte-identical to today.
5. Do not add a literal `MANPATH` (or any other platform-specific variable name) to the test. The whole point is that the set is discovered, not enumerated — a hardcoded addition fixes macOS today and breaks on the next platform.
6. Add a `## Unreleased` entry to `CHANGELOG.md` describing the fix as a test-portability correction, following the file's existing bullet style. `## v0.3.0` is the newest released section (`CHANGELOG.md:8`, below a 7-line preamble); insert the new section above it.
7. The derived set must be non-empty beyond HOME and PATH — assert this in the spec rather than reporting it, so the derivation is proven to have produced something. Additionally, confirm in your final report that the helper rejects a synthetic unknown variable.
</requirements>

<constraints>
- Module path is `github.com/bborbe/github-vuln-watcher`.
- **Do NOT change `pkg/scanner.go`.** `scanEnv()` is correct and the production behaviour must stay byte-identical. This prompt changes a test and adds a test-only helper.
- **Do NOT weaken any assertion.** The credential assertions and the anti-widening property are the reason the spec exists. If the derived-set approach cannot preserve the anti-widening property, stop and say so rather than loosening it.
- Do not hardcode platform variable names (`MANPATH` or otherwise) anywhere in the test or helper.
- The helper returns a string, not an error. Do not introduce `github.com/bborbe/errors` into a test file — subprocess faults are asserted with Gomega (`Expect(err).NotTo(HaveOccurred())`), matching every existing `pkg/*_test.go`.
- Never hand-edit anything under `mocks/`; tests use Ginkgo/Gomega; counterfeiter fakes come from `//counterfeiter:generate` directives.
- Keep every line under 100 characters and every function under 80 lines / 50 statements (`funlen`). Prefer extracting small helpers over growing an existing spec body.
- Every new `.go` file starts with the BSD license header block used by the existing files.
- Do NOT commit — dark-factory handles git.
- Existing tests must still pass.
</constraints>

<verification>
Run from the repo root.

```
make precommit
```

Must exit 0.

```
grep -n 'MANPATH\|makeInjected' pkg/scanner_auth_integration_test.go
```

Must print nothing — neither a hardcoded platform variable name nor the old hardcoded map may survive.

```
grep -n 'make-probe' pkg/scanner_auth_integration_test.go
```

Must return at least one line — the probe target the derivation invokes.

```
grep -c 'os.Getenv' pkg/scanner.go
```

Must print `2` — `scanEnv()` still returns exactly HOME and PATH, so production is unchanged.

```
grep -n 'Unreleased' CHANGELOG.md
```

Must return at least one line.

```
go test -mod=mod ./pkg/... -count=1
```

Must exit 0. Do not pipe this one — the exit status must be the test command's own, not a downstream filter's.

```
go test -mod=mod ./pkg/... -count=1 -v 2>&1 | grep -ic 'derived allowlist'
```

Must print at least `2` — both new helper specs ran rather than being skipped. The token `derived allowlist` occurs nowhere in the repo today, so this cannot pass on an unmodified tree.
</verification>
