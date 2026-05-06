# eleVADR Container Architecture #

This document explains how the containerized eleVADR implementation
achieves robustness and flexibility.

## Design Principles ##

1. **No Code Duplication**: Docker entrypoint delegates to existing
   application code
1. **Loose Coupling**: Container orchestration is separate from
   analysis logic
1. **Future-Proof**: Changes to analysis workflow do not require Docker
   infrastructure changes

## Component Organization ##

```text
docker-entrypoint.sh          Container orchestration
        ↓
app/main.py                   Application entry point with CLI arguments
        ↓
app/utils/*                   Analysis logic (PcapParser, Analyzer, Report)
```

### docker-entrypoint.sh ###

**Responsibilities:**

- Validates input paths and dependencies
- Copies PCAP to working directory
- Calls `main.py` with appropriate arguments
- Displays formatted output

**Does not:**

- Duplicate analysis logic
- Import Python modules directly
- Hardcode class names or internal structure

**Key code:**

```bash
python3 main.py --pcap "data/uploads/${PCAP_FILENAME}" --output "$REPORT_OUTPUT"
```

### app/main.py ###

**Responsibilities:**

- Parses command-line arguments: `--pcap`, `--output`, and
  `--project-root`
- Accepts configuration via environment variables: `PCAP_INPUT` and
  `REPORT_OUTPUT`
- Executes analysis via `run_analysis()`
- Writes output to file or stdout

**Usage:**

```bash
# Via arguments
python3 main.py --pcap capture.pcap --output report.json

# Via environment variables
PCAP_INPUT=capture.pcap REPORT_OUTPUT=report.json python3 main.py

# Stdout (no --output)
python3 main.py --pcap capture.pcap
```

### app/utils/* ###

**Responsibilities:**

- Core analysis logic: `PcapParser`, `Analyzer`, and `Report`
- Independent of containerization
- Can be imported and used in any context

## Why This Design is Robust ##

### Separation of Concerns ###

| Component            | Responsibility           | Requires updates when       |
| -------------------- | ------------------------ | --------------------------- |
| docker-entrypoint.sh | Container orchestration  | Deployment model changes    |
| main.py              | Entry point and I/O      | Interface requirements vary |
| utils/*              | Analysis logic           | Security features change    |

### No Hardcoded Logic ###

The entrypoint does not contain embedded Python code or duplicate
analysis logic. It simply invokes `main.py` with parameters. Changes to
`PcapParser`, `Analyzer`, or `Report` do not require Docker updates.

### Flexible Configuration ###

Input and output can be specified via:

- Command-line arguments: `--pcap /path/to/file.pcap`
- Environment variables: `PCAP_INPUT=/path/to/file.pcap`

This supports Docker, Kubernetes, CLI, and script usage without code
changes.

### Environment Agnostic ###

The same `main.py` works in:

- Docker containers
- Kubernetes pods
- Local development
- CI/CD pipelines

## Configuration ##

### Environment Variables ###

| Variable        | Default               | Purpose            |
| --------------- | --------------------- | ------------------ |
| `PCAP_INPUT`    | `/input/capture.pcap` | Input PCAP path    |
| `REPORT_OUTPUT` | `/output/report.json` | Output report path |

### Volume Mounts ###

```yaml
/input
/output
```

## Example: Adding New Analysis Features ##

**Scenario:** Modify `Analyzer` to add threat intelligence.

**Required changes:**

- Update `app/utils/analysis.py`
- Modify `app/main.py` if new CLI arguments are needed
- No changes to `docker-entrypoint.sh`
- No changes to Dockerfile
- No changes to Kubernetes manifests

The container infrastructure remains unchanged because it does not depend
on analysis internals.
