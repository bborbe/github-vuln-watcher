# github-vuln-watcher

Poll-primary watcher that detects Go vulnerabilities published against unchanged dependencies (no code change → CI drifts red) and emits one `github-update-go` task per affected repo for `github-update-go-agent` to fix. Clones each consenting repo and runs its own vuln gate (`make vulncheck` + `make check`); deterministic `task_identifier` seeded on `(repo, sorted vuln IDs)` prevents re-emission of identical tasks across cycles.

## GitHub App credentials

The scan-stage clone authenticates as the watcher's GitHub App installation,
using the same `APP_ID` / `INSTALLATION_ID` / `PEM_KEY` values the inventory
stage uses (populated from a Kubernetes Secret). A fresh installation token is
minted per scan and handed to `git clone` through the process environment only —
it never enters the clone URL, the cloned repo's `.git/config`, or the gates the
repo runs. With no App credentials configured, the clone runs unauthenticated.
See [docs/security-model.md](docs/security-model.md) for the full reasoning.

## Run locally

```bash
make test
make run
```

## Deploy

```bash
make buca
```
