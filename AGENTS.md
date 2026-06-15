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
- Entrypoint: `main()`. `analyze_domain()` does all checks per domain.
- Checks: DNS → HTTP HEAD → H2 detection (separate connect with ALPN `['h2', 'http/1.1']`) → HTTPS + SSL cert (ALPN `['http/1.1']` only) → page title with redirect follow.
- H2 detection and HTTPS check use **separate connections** with different ALPN: H2 detection uses `['h2', 'http/1.1']`, HTTPS check uses `['http/1.1']` only. This avoids `BadStatusLine` when the server negotiates h2 but then receives an HTTP/1.1 request.
- Terminal output truncates long values at fixed column widths; CSV export writes full values and flushes after every row (`csv_file.flush()`).
- SSL error classification: `VALID`, `EXPIRED`, `SELF-SIGNED`, `ERR_CERT`, `ERR_HOSTNAME`, `ERR_TLS_VERS`, `TIMEOUT`, `REFUSED`, `NO_HTTPS`, `BYPASS` (with `-k`).

## License
GPL v3 — see `LICENSE`.
