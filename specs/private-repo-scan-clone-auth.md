---
status: draft
---

## Summary

- The scan stage clones each consenting repo with an **unauthenticated** HTTPS URL. That works only for public repos, and every repo in the target fleet (`Seibert-Data/*` on the octopus platform) is private — so the watcher currently clones nothing and reports `clone_failed` for every eligible repo.
- This spec makes the scan clone authenticate as the watcher's own **GitHub App installation** (the same App the inventory stage already uses), so private repos become scannable.
- The credential is conveyed to `git` through the clone process's **environment** as an `http.extraheader` value — never in the clone URL, never in argv, never written into the clone directory.
- The isolation boundary that made the clone unauthenticated in the first place is preserved unchanged: the scanned repo's own gates (`make vulncheck` / `make check`) are attacker-controlled code and continue to receive **only** `HOME` and `PATH`.
- With no token source configured the scanner behaves exactly as it does today, so the public-fleet path is untouched.

## Problem

The watcher's threat model treats every scanned repo as hostile: its Makefile runs arbitrary commands as the watcher's user, so the spec freezes the rule that gate subprocesses receive only an allowlisted environment (`HOME`, `PATH`) and that no GitHub credential may reach them. The v0.1.2 clone honored that rule by not authenticating at all — sufficient when the fleet was public.

The fleet is not public. Every repo the watcher is being deployed to scan is private, so the unauthenticated clone fails before any gate runs:

```
git clone url=https://github.com/Seibert-Data/test-dev.git
fatal: could not read Username for 'https://github.com': No such device or address
→ reason=clone_failed
```

The watcher passes its own consent gate, reads `.maintainer.yaml` at HEAD correctly, and then cannot obtain the code it was built to scan. The service is deployed, wired, and metrics-correct while being functionally inert on its target fleet.

The naive fix — embedding the token in the clone URL — is the one that breaks the isolation: `git clone` writes the URL it was given into `<cloneDir>/.git/config` as `remote.origin.url`, where the repo's own Makefile can read it, and git prints the URL in clone-failure output that the watcher logs. This spec chooses a conveyance that leaves no such trace.

## Goal

After this work, the scan stage clones private repos as the watcher's GitHub App installation while the untrusted-code isolation boundary stays intact: the credential exists only in the environment of the `git clone` process, appears in no URL, no argv, no file on disk, and no log line, and the scanned repo's gates still receive exactly `HOME` and `PATH`. A repo that fails to clone for an auth reason is still reported as `clone_failed`, and a watcher with no token source configured still clones public repos unauthenticated exactly as before.

## Non-goals

- **No SSH.** The runtime image ships no `openssh-client` and no key, by design. This spec does not add either.
- **No change to the gate isolation rule.** Gate subprocesses keep the `HOME`+`PATH` allowlist. Widening it is out of scope and would be a regression against the frozen constraint in spec 001.
- **No change to the consent / allowlist / `go.mod` filters**, the cursor, the dedup, or the emit contract.
- **No multi-owner or per-repo credentials.** One App installation per instance, mirroring the inventory stage.
- **No caching layer.** A token is minted per scan. GitHub App installation tokens are valid for up to one hour and a single repo's scan is bounded by the existing 20-minute gate timeout, so a per-scan mint is always fresh.
- **Deployment is out of scope as *work*** — re-pinning the octopus mirror image and re-applying the dev unit belong to the rollout task in the octopus repo. The live proof that this change works against a real private repo is nonetheless an acceptance criterion below, because a spec that passes on unit evidence alone can ship an inert service.

## Acceptance Criteria

- [ ] `make precommit` exits 0 in the repo — evidence: exit code.
- [ ] **The credential reaches the real clone process.** In an integration scan run with a recording `git` shim prepended to `PATH`, the recorded environment of the actual `git clone` subprocess contains `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=http.extraheader`, and a `GIT_CONFIG_VALUE_0` whose base64 payload decodes to `x-access-token:ghs_sentinel` — evidence: the shim's captured environment file, with the value decoded in the assertion. This is the AC that a mint-but-never-wire implementation fails. The shim records each intercepted invocation separately and delegates to the real `git`, so the clone invocation is identified unambiguously — the scanner also invokes `git rev-parse` and `git config` in the same run.
- [ ] The App credentials are threaded from the composition root into the scanner: a factory test asserts that a scanner built with App credentials configured carries a non-nil token source while one built without them carries nil — evidence: the factory test outcome, which is the binding evidence; `grep -rn 'MintIAT' main.go pkg/` returning ≥1 is supporting context only, since a grep is satisfiable by a comment.
- [ ] **Negative — the credential never reaches the clone URL or argv:** in the same integration scan the URL passed to `git clone` equals `repo.CloneURL` when that field is set and the derived `https://github.com/<owner>/<name>.git` form otherwise, and the recorded argv contains zero occurrences of either the literal `ghs_sentinel` or its base64 header form — evidence: captured argv + zero-match assertion.
- [ ] **Negative — the scanned repo's own gates never receive the credential:** a scan-level test captures the environment of each gate subprocess and asserts it equals exactly the `HOME` and `PATH` entries, with zero entries matching `GIT_CONFIG|Authorization` and zero matching either credential form — evidence: captured gate env + zero-match assertion.
- [ ] **Negative — nothing credential-bearing is persisted into the clone directory:** after a real clone, `git -C <cloneDir> config --get remote.origin.url` returns a URL containing neither `@` nor the credential, and `grep -rl` over the clone directory for **both** the literal `ghs_sentinel` and its base64 header form returns 0 lines — evidence: command output + zero grep hits on both forms. The base64 form is asserted separately because the encoded header contains no `ghs_` substring and a literal-only grep cannot see the leak it targets.
- [ ] **Negative — the credential is never logged:** `grep -c` over the scan's captured log output for both the literal `ghs_sentinel` and its base64 header form returns 0 — evidence: zero grep hits on both forms.
- [ ] A mint failure degrades to today's unauthenticated behavior instead of introducing a new failure mode: with a token source that returns an error, a scan of a local fixture repo still clones successfully, the recorded clone environment carries no `GIT_CONFIG_*` key, and a WARN log line names the mint failure — evidence: scan outcome + captured clone env + the log line.
- [ ] With no token source configured, the unauthenticated path is unchanged: the recorded clone environment contains no `GIT_CONFIG_*` key and the existing unauthenticated-path assertions in `pkg/scanner_test.go` are byte-identical to their pre-change content — evidence: captured clone env + `git diff <base> -- pkg/scanner_test.go | grep -c '^-.*Expect'` returns 0, where `<base>` is `git merge-base HEAD origin/master`. A bare `git diff` is empty regardless of file content and would prove nothing.
- [ ] **Post-Deploy (Rung-2):** the deployed octopus dev watcher clones a real private repo — evidence: `kubectldev -n agent logs watcher-github-vuln-0 --since=30m | grep -q 'git clone ok' && echo clone-ok` prints `clone-ok`, where the same command printed nothing before this change. (Prerequisite: the octopus rollout task has re-pinned `agent/images/watcher-github-vuln/Dockerfile` to the release cut from this merge and re-applied the dev unit. This AC is owned jointly; it is listed here because it is the only evidence that the Goal is met. The gate is self-referential — it *is* this AC's evidence — so an empty result cannot distinguish a stale deploy from a fresh deploy with a broken feature; the rollout task's own evidence resolves that ambiguity. It emits a stable token rather than a count because a clone count grows with traffic, so an exact match on a number would refuse verification for a healthy watcher.)
  - `deploy_check:` `kubectldev -n agent logs watcher-github-vuln-0 --since=30m 2>/dev/null | grep -q 'git clone ok' && echo clone-ok`
  - `deploy_target:` `clone-ok`
- [ ] The security rationale survives the spec: `docs/security-model.md` states the `HOME`+`PATH` gate allowlist, why the credential is conveyed through the process environment rather than the clone URL, and the accepted `/proc/<pid>/environ` residual risk — evidence: `grep -c 'HOME' docs/security-model.md` returns ≥1 and the residual-risk sentence is present.

**Scenario coverage:** NO new scenario. The mechanism is reachable by an integration test — a recording `git` shim on `PATH` observes the real subprocess environment, and a local fixture repo exercises a real clone — so unit + integration tests reach the behavior and no scenario is needed.

## Verification

## Container-executable (runs inside the YOLO container at prompt time)

- `make precommit` — format, lint, generate, test, license clean
- `make test` — unit + integration suite passes
- `grep -rc 'x-access-token' pkg/` — returns ≥1, proving the token user form matches the fleet convention

## Operator-executable (runs on the host after PR merge, spec verification ladder)

- `make build` — fresh image builds
- Re-pin `agent/images/watcher-github-vuln/Dockerfile` in the octopus repo to the release cut from this merge, `BRANCH=dev make build upload`, then `BRANCH=dev make apply` — the octopus rollout step, tracked by the rollout task, not by this spec
- `kubectldev -n agent logs watcher-github-vuln-0 --since=30m | grep -E 'git clone ok|clone_failed'` — the live private-repo clone proof; the watcher must log `git clone ok` where it previously logged `clone_failed`. Cluster wrapper verified 2026-09-16: `kubectldev -n agent get sts watcher-github-vuln` returns `1/1`.

## Desired Behavior

1. The scanner accepts an optional token source. When one is configured, each scan mints an installation access token before the clone; when none is configured, the scan proceeds unauthenticated exactly as today. A mint failure is logged at WARN with its cause and falls back to the unauthenticated clone, so public repos are unaffected and private repos report `clone_failed` as they do today.
2. The credential is passed to `git clone` through the process environment using git's environment-configuration interface (`GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_0` / `GIT_CONFIG_VALUE_0`) with `http.extraheader` set to a Basic authorization header whose user is `x-access-token` and whose password is the minted token — and the clone URL itself stays credential-free, equal to `repo.CloneURL` when that field is set and the derived `https://github.com/<owner>/<name>.git` otherwise. The credential environment is attached whenever a token source is configured, regardless of the URL's scheme.
3. The gate subprocesses continue to receive exactly the `HOME` and `PATH` allowlist, with no credential key present.
4. The watcher's composition root builds the token source from the same GitHub App credentials the inventory stage already uses, so one App configuration drives both stages.

## Constraints

- **Credential conveyance is frozen**: environment only, via `http.extraheader`. The credential must never appear in the clone URL, in argv, in any file inside the clone directory, or in any log line. These four are the reason the mechanism was chosen and must not be relaxed for convenience.
- **The gate environment allowlist is frozen** at `HOME` + `PATH`. Adding a credential key to it is a regression, not an implementation choice.
- **No new failure mode**: an unconfigured or failing token source must not make a previously-working scan fail. A mint that hangs is bounded by its own short timeout and treated as a mint failure — it must never consume the 20-minute scan budget, which would surface as a spurious `clone_failed` for a repo whose clone was never attempted.
- **Token user form**: `x-access-token` as the Basic-auth user. This is the fleet convention, evidenced by `github-update-go-agent`'s `injectToken` helper — that reference is informational; the binding part is the user form, not that file.
- **The App auth surface mints nothing today.** `auth.ResolveGitHubClient` returns an authenticated `*http.Client` only; there is no raw-token accessor. Minting is new code, built on the already-vendored `githubapp.MintIAT`, not a reuse of an existing call.
- **A new token-source interface implies a counterfeiter mock** in `mocks/`, per `docs/dod.md`.
- **git version**: the mechanism requires git ≥ 2.31. The runtime image's `alpine:3.24` ships git 2.54.0, verified.
- **No credential is logged, ever** — not the token, not its prefix, not its base64 header form, not a hash of it.
- **CHANGELOG**: `CHANGELOG.md` currently has no `## Unreleased` section (its top section is `## v0.2.2`), so create one above the latest release and add a bullet there — a bullet added to an existing released section would ship inside that release's tag. `.maintainer.yaml` sets `release.autoRelease: true`, so the release bot cuts the version; no tag is created by hand.
- The security rationale this spec encodes (the `HOME`+`PATH` gate allowlist, why the credential is env-conveyed, the accepted residual risk) must outlive the spec in `docs/security-model.md`, since completed specs are immutable and the constraint is load-bearing for every future change to the scanner.
- Existing constructor call sites and tests are updated for the new parameter; a nil token source is the documented "unauthenticated" value.

## Failure Modes

| Trigger | Expected behavior | Detection | Recovery | Reversibility |
|---|---|---|---|---|
| Token mint fails (App creds invalid, API unreachable) | WARN logged with the cause; clone proceeds unauthenticated | the WARN log line | fix the App configuration; public repos were unaffected throughout | reversible |
| Mint hangs | bounded by the mint's own timeout, then treated as a mint failure — the scan budget is not consumed | WARN log line + the scan still cloning | fix the API reachability | reversible |
| GitHub API rate limit / throttling on token mint | mint fails for that scan; WARN logged; the repo reports `clone_failed` this cycle and retries next cycle | WARN log line + `filter_skipped_total{reason="clone_failed"}` | none needed — the next cycle retries; reduce repo count per cycle if it recurs | reversible |
| Token minted but rejected by GitHub (installation lacks repo access) | clone exits non-zero → `clone_failed` for that repo, other repos continue | `filter_skipped_total{reason="clone_failed"}` + clone-failure log | grant the installation access to the repo | reversible |
| git older than 2.31 in the runtime image | the `GIT_CONFIG_*` variables are ignored; clone proceeds unauthenticated | clone fails for private repos with `clone_failed` | upgrade git in the image | reversible |
| Gate reads the credential anyway | not possible by construction — the credential is never written where the gate can read it | a failing negative AC | n/a | n/a |
| Token outlives its 1h validity mid-cycle | not reachable: minted per scan, and one scan is bounded by the 20-minute gate timeout | n/a | n/a | n/a |

## Security / Abuse

This change touches the boundary the original design drew deliberately, so the boundary is restated as the thing being protected.

**Threat**: a scanned repo is hostile. Its Makefile runs arbitrary commands as the watcher's user. If it can read the installation token it can act as the App installation across every repo the App can reach — a privilege escalation from "one repo's CI" to "the installation's whole scope".

**Controls**, each corresponding to a negative acceptance criterion:

1. The credential lives in the environment of the `git clone` process only. The gate subprocess environment is constructed independently and stays at `HOME`+`PATH` — the credential key is never added to it (AC 5).
2. `http.extraheader` through git's environment-configuration interface is not persisted: unlike a URL-embedded token, it is not written to `.git/config`, so the clone directory the gate runs in contains no credential (AC 6).
3. The credential is never placed in argv, so it is not readable from the process table by any process in the container (AC 4).
4. The credential is never logged, so it does not survive in pod logs, log shipping, or Sentry (AC 7).
5. The clone directory is already removed after each scan (existing behavior, unchanged), bounding the window in which any artifact exists at all.

**Residual risk, stated plainly**: the token is a live credential in the clone process's environment for the duration of the clone. A process that could read `/proc/<pid>/environ` as the same user during that window could obtain it. No untrusted code runs during the clone — gates execute after it returns — so reaching that window requires a process the watcher did not start. This is accepted rather than mitigated, because the alternatives (SSH key in the image, credential on disk) are strictly worse and were already rejected by the original design.

## Suggested Decomposition

| # | Prompt focus | Covers DBs | Covers ACs | Depends on |
|---|---|---|---|---|
| 1 | Scanner credential plumbing — token-source interface, credential-bearing clone environment wired into the real clone subprocess, unauthenticated fallback, unit + integration tests | 1-3 | 1, 2, 4-9 | — |
| 2 | Composition root + docs — build the token source from the App credentials, thread it through the watcher factory, `docs/security-model.md`, `example.env`, README, CHANGELOG | 4 | 3, 10, 11 | prompt 1 |

Rationale: prompt 1 is the security-relevant core and carries every negative criterion; prompt 2 is wiring and documentation that cannot land before the interface exists. AC 10 is jointly owned with the octopus rollout task and is not satisfied by either prompt alone.

## Do-Nothing Option

The watcher stays deployed, healthy, and inert. Every eligible repo reports `clone_failed`, the fleet scans nothing, and the rollout task's remaining acceptance criteria (scan, finding, emit, dedup, cursor-restart) cannot be met on any private repo. The cost of doing nothing is the whole feature: a service that passes its own consent gate and then cannot read the code it exists to inspect.
