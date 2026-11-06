# Production Hardening & Deployment #

eleVADR is designed to be capable of running in sensitive,
air-gapped critical infrastructure networks.

## Supported local Windows platform workflow ##

The current authenticated local-platform workflow is documented in the [Operator Guide](operator-guide.md). On a new Windows workstation with Python 3.12+, Node.js 22.22.3+ (Node 22), npm, and Docker Desktop, run:

```powershell
.\first_run_elevadr.bat
```

Then start eleVADR with:

```powershell
.\start_elevadr.bat
```

The first-run helper initializes the localhost-only MongoDB platform runtime, installs locked dependencies, bootstraps the first administrator when needed, and enables authentication. Use `validate_clean_install.bat` to validate an initialized workstation.
