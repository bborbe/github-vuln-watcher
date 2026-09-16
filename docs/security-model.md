# Security Model — Scan-Stage Clone Credential

This document records the reasoning behind how the signal-stage clone
authenticates, so the decisions survive the specs that produced them.

## The threat

A scanned repo is hostile input. The watcher clones it and then runs the repo's
own Makefile targets (`make vulncheck`, `make check`) — arbitrary commands,
executed as the watcher's user. If that code can read the GitHub App
installation token, it can act as the App installation across every repository
the installation can reach. That is a privilege escalation from "one repo's CI"
to "the installation's whole scope".

## The gate allowlist

Gate subprocesses receive exactly two environment variables: `HOME` and `PATH`,
and nothing else. The credential key is never added to that allowlist. Widening
the allowlist is a regression, not an implementation choice — the gate runs
attacker-controlled code by construction.

## Why the credential travels in the process environment

The installation token reaches `git clone` as an `http.extraheader` git
configuration entry, conveyed through git's environment-configuration interface
(`GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_0` / `GIT_CONFIG_VALUE_0`):

- **Not in the clone URL.** A token embedded in `https://x-access-token:<token>@github.com/...`
  is persisted to `remote.origin.url` in `.git/config`, where the repo's own
  Makefile can read it back, and it appears verbatim in clone-failure output
  that is logged. `http.extraheader` is not persisted to `.git/config`.
- **Not in argv.** The credential is not a command-line argument, so it is not
  readable from the process table.
- **Not logged.** No log statement in the watcher emits the token, a prefix of
  it, its base64 header form, or a hash of it, so the credential does not
  survive in pod logs, log shipping, or Sentry.

## The bounding window

Two independent bounds keep the exposure short:

- The clone directory is removed after each scan, so nothing written during the
  clone outlives the scan.
- The credential is minted per scan with no cache, and a GitHub App
  installation token is valid for at most one hour. A single scan is bounded by
  the existing 20-minute gate timeout, so the credential in flight is always
  fresh and always short-lived.

## Residual risk (accepted, not mitigated)

The token is a live credential in the clone process's environment for the
duration of the clone. A process that could read `/proc/<pid>/environ` as the
same user during that window could obtain it. No untrusted code runs during the
clone — gates execute only after the clone returns — so reaching that window
requires a process the watcher did not start. This risk is accepted rather than
mitigated.

The alternatives were considered and rejected by the original design: an SSH
key baked into the image, or a credential written to disk. Both widen the
exposure window from one clone to the lifetime of the container, and both put
key material where a gate subprocess could read it. The runtime image ships no
`openssh-client` and no key by design.

## Failure behavior

Minting is best-effort and never gates the service. A mint failure is logged at
WARN with its cause and the clone proceeds unauthenticated. Public repositories
are unaffected; private repositories report `clone_failed` exactly as they did
before this change.
