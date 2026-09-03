# Changelog

## Unreleased

- feat: Inventory the GitHub owner via the GitHub App installation and gate repos pre-clone by allowlist (scope), .maintainer.yaml goUpdate.autoUpdate consent (auto_update_disabled), and go.mod presence (no_gomod)
- feat: Add github-vuln-watcher service shell with env config surface, single-cycle poll loop (immediate first cycle, 12h default interval, 24h ceiling), /trigger endpoint and four-counter metrics scaffold
- refactor: Remove BoltDB / DATADIR / BATCH_SIZE and the /resetdb, /resetbucket endpoints — persistent memory moves to the JSON cursor

## v0.0.1

- Initial commit
