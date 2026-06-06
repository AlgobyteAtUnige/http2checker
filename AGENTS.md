# http2checker — Agent Notes

## Single-file app
- `http2checker.py` is the sole source — no package manager, no dependencies beyond stdlib.
- No tests, no linting, no typecheck, no CI. No `.gitignore`.
- No Makefile, no build step.

## Run
```bash
python3 http2checker.py <domain>
python3 http2checker.py -f domains.txt -k -o results.csv
```

Arguments: `-k` (skip SSL verify), `-f` (batch from file, `#` for comments), `-o` (CSV export).

## Architecture
- Entrypoint: `main()` at line 246. `analizza_dominio()` does all checks per domain.
- Checks: DNS → HTTP HEAD → HTTPS + ALPN (h2) → SSL cert → page title with redirect follow.
- Terminal output truncates long values at fixed column widths; CSV export writes full values.

## License
GPL v3 — see `LICENSE`.
