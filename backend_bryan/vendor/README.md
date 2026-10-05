# Vendored detector runtime

This directory contains only the runtime files required by `backend_bryan` to execute the eleVADR detector modules locally.

- `elevadr_modules/` is the bundled 75-module detector Python package.
- Development-only scenario data, package tests, generated results, runner scripts, and packaging metadata from the source `elevadr-analysis-modules` project are intentionally excluded.
- The production `eleVADR/backend/` is not modified or required by this local reference integration.

`backend_bryan` adds this `vendor/` directory to the Python import path automatically, so no `pip install` is required for local testing.
