# github-vuln-watcher

Poll-primary watcher that detects Go vulnerabilities published against unchanged dependencies (no code change → CI drifts red) and emits one `github-update-go` task per affected repo for `github-update-go-agent` to fix. Clones each consenting repo and runs its own vuln gate (`make vulncheck` + `make check`); deterministic `task_identifier` seeded on `(repo, sorted vuln IDs)` prevents re-emission of identical tasks across cycles.

## Run locally

```bash
make test
make run
```

## Deploy

```bash
make buca
```
