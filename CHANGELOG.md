# Changelog

## Unreleased

- feat: Add github-vuln-watcher service shell with env config surface, single-cycle poll loop (immediate first cycle, 12h default interval, 24h ceiling), /trigger endpoint and four-counter metrics scaffold
- refactor: Remove BoltDB / DATADIR / BATCH_SIZE and the /resetdb, /resetbucket endpoints — persistent memory moves to the JSON cursor

## v0.0.1

- Initial commit
