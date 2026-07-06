# elastic-detection-parser

A small CLI tool that decodes Elastic Defend alert JSON and explains *why* a binary got flagged — walks the EQL rule condition against the actual process/dll/file event data and shows which parts matched.

On first run it clones [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) locally so it can look up the rule source (`.toml`) behind each detection.

## Usage

```bash
python elastic_analyzer.py <alert.json>
python elastic_analyzer.py <alert.json> --no-pull   # skip git pull on the artifacts repo
python elastic_analyzer.py <alert.json> --no-color  # plain output, no ANSI colors
```

The input can be a single alert object or a JSON array of alerts (a full Kibana export).

## Requirements

- Python 3.11+ (uses `tomllib`)
- `git` on PATH (for the first-run clone of `protections-artifacts`)

No third-party packages required — standard library only.

## Notes

- `protections-artifacts/` is auto-cloned and gitignored, not tracked in this repo.
- `samples/` is gitignored by default since alert JSON can contain sensitive host/user data. Remove that line from `.gitignore` if you want to commit your own sample alerts.

---
Author: PaiN05
