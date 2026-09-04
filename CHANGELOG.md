# Changelog

All notable changes to this project will be documented in this file.

Please choose versions by [Semantic Versioning](http://semver.org/).

* MAJOR version when you make incompatible API changes,
* MINOR version when you add functionality in a backwards-compatible manner, and
* PATCH version when you make backwards-compatible bug fixes.

## v0.2.0

- feat: `GATE_TARGETS` env configures the per-repo make-target sequence (comma-separated, default `vulncheck,check`); deploy manifests can trim it to `vulncheck` alone when the full `make check` compile over a large monorepo exceeds the pod memory budget — the vuln signal comes from `vulncheck`, `check` output is not consumed for emit

## v0.1.2

- fix: scan-stage clone uses HTTPS (`https://github.com/<owner>/<repo>.git`) instead of SSH — the runtime has no openssh-client and no SSH key by design (gates from cloned repos must never read a key), and the public fleet needs no auth for the scan. Emit-contract `clone_url` stays SSH for the agent.
- fix: pre-call + outcome audit log lines around the boundary subprocess calls (git clone, make gate, git rev-parse HEAD) so scan failures are diagnosable from logs

## v0.1.1

- fix: runtime image is deployable — replace scratch runtime with an alpine image carrying git, make, the Go toolchain, and trivy so the watcher can clone repos and run their vuln gates in-pod; publish-only Makefile.docker (semver-tagged), drop stale k8s/ + Makefile.k8s (deployment is the Helm chart)
- fix: run the runtime as non-root `nobody` (uid 65534, matching the k8s manifest) since it executes arbitrary gate scripts from cloned repos; pin trivy to v0.74.0; drop host-scoped `docker image prune` from clean

## v0.1.0

- feat: Add the JSON cursor (atomic tmp+rename persist, corrupt -> .corrupt recovery) and the finding_set_unchanged dedup filter, with a fixture-repo dispatch integration test proving the emit contract, skip-reason deltas and dedup end-to-end
- feat: Emit one github-update-go create-task per finding set under the frozen 12-key contract (vuln_count + sorted vulns payload, dash-form title, deterministic UUID5 task id) via the cqrs create-task command sender, and count publishes on published_total{status=create|error}
- feat: Add the signal stage — ephemeral full clone (env allowlist HOME+PATH) of each consenting repo, run of the repo's own make vulncheck + make check under a hard 20-minute timeout, and GO-/CVE- marker classification with clone_failed / gate_timeout / scan_failed / already_clean outcomes
- feat: Inventory the GitHub owner via the GitHub App installation and gate repos pre-clone by allowlist (scope), .maintainer.yaml goUpdate.autoUpdate consent (auto_update_disabled), and go.mod presence (no_gomod)
- feat: Add github-vuln-watcher service shell with env config surface, single-cycle poll loop (immediate first cycle, 12h default interval, 24h ceiling), /trigger endpoint and four-counter metrics scaffold
- refactor: Remove BoltDB / DATADIR / BATCH_SIZE and the /resetdb, /resetbucket endpoints — persistent memory moves to the JSON cursor

## v0.0.1

- Initial commit
