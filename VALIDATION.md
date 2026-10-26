# Validation

Validated locally on 2026-10-26 with Python 3.11.2.

- `python3 -m unittest discover -s tests -v`: **10 tests passed**.
- `python3 demo.py`: all four synthetic scenarios completed.
- AST comparison confirmed that the exported findings engine, STP parser,
  and vendor-prefix lookup retain their source function logic.
- Reviewed the explicit export file list for credential patterns, device MAC
  addresses, non-example IPv4 addresses, internal absolute paths, databases,
  environment files, and private-key material: no matches requiring removal.

Inputs were authored for this showcase. Original captures and original Git
history were not imported. The checks are a targeted review, not a guarantee
that an arbitrary future change contains no sensitive material.

The included CI matrix is configured for Python 3.10, 3.12, and 3.13; the local
run above does not establish that those remote jobs have passed.
