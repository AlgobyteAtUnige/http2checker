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

Arguments: `-k` (skip SSL verify), `-f` (batch from file, `#` for comments), `-v` (show exception tracebacks), `-o` (CSV export).

## Architecture
- Entrypoint: `main()` at line 267. `analizza_dominio()` at line 116 does all checks per domain.
- Checks: DNS → HTTP HEAD → H2 detection (separate connect with ALPN `['h2', 'http/1.1']`) → HTTPS + SSL cert (ALPN `['http/1.1']` only) → page title with redirect follow.
- H2 detection uses a separate connection to avoid `BadStatusLine` when the server negotiates h2 but then receives an HTTP/1.1 request.
- Terminal output truncates long values at fixed column widths; CSV export writes full values.

## License
GPL v3 — see `LICENSE`.
