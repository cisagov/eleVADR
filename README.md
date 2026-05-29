# EleVADR - OT Network Security Analysis Tool #

![License: CC0](https://img.shields.io/badge/License-CC0-lightgrey.svg)
![Python 3.14+](https://img.shields.io/badge/python-3.14+-blue.svg)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://hub.docker.com/r/cisagov/elevadr-web-backend)
[![GitHub Actions Pipeline Status](https://github.com/cisagov/eleVADR/actions/workflows/build.yml/badge.svg)](https://github.com/cisagov/eleVADR/actions)
[![Open in Dev Containers](https://img.shields.io/static/v1?label=Dev%20Containers&message=Open&color=blue)](https://vscode.dev/redirect?url=vscode://ms-vscode-remote.remote-containers/cloneInVolume?url=https://github.com/cisagov/eleVADR)

EleVADR is a specialized network security analysis engine developed
for the Cybersecurity and Infrastructure Security Agency (CISA). It is
designed to assess Operational Technology (OT) systems by transforming
raw PCAP traffic into actionable security intelligence.

This is part of the larger
[EleVADR operator workflow](https://cisagov.github.io/elevadr-operator).

## Overview ##

eleVADR analyzes OT network traffic to provide comprehensive security
assessments including:

- **Asset discovery:** Identification of network devices, IP addresses,
  MAC addresses, and manufacturers
- **Service detection:** Recognition of network services including
  industrial protocols such as Modbus and DNP3
- **Risk assessment:** Classification of services by security risk
  categories
- **Network segmentation analysis:** Detection of cross-segment
  communications
- **Security findings:** Identification of insecure protocols,
  suspicious outbound connections, and risky services
- **Detailed reporting:** JSON-formatted reports with executive
  summaries and detailed module data
- **Interactive drilldown APIs:** Report-scoped endpoints for filtering
  connections, devices, and services after analysis

## The Modern Workflow ##

To ensure environment parity and avoid "it works on my machine" issues,
EleVADR must be run and developed inside containers.

### 1. Running the App (Production/Testing) ###

Do not attempt to install dependencies locally. Use Docker.

#### Pull from DockerHub ####

A pre-built container for the latest `develop` image is available on
[DockerHub](https://hub.docker.com/r/cisagov/elevadr-web-backend/tags).

#### Run the Container ####

`sudo docker run -i cisagov/elevadr-web-backend`

#### Build Locally ####

```bash
# Build the analysis engine
docker build -t elevadr-analysis .

# Run analysis on a PCAP
docker run --rm \
  -v $(pwd)/pcaps:/input:ro \
  -v $(pwd)/reports:/output \
  elevadr-analysis
```

### 2. Developing the App (Dev Containers) ###

We use VS Code Dev Containers to provide a fully configured
environment, including Zeek, Python 3.14, and all required system
dependencies.

**How to start developing:**

1. Open this folder in **VS Code**.
1. When prompted that the folder contains a Dev Container
   configuration, click **Reopen in Container**.
1. If the prompt does not appear, run `Ctrl+Shift+P` and choose
   `Dev Containers: Rebuild and Reopen in Container`.

**Why Dev Containers?**

- No need to install `pyenv`, `zeek`, or `libpcap` on your host.
- All linting, formatting, and testing tools are pre-installed.
- Your development environment matches the production image.

---

## Core Architecture ##

EleVADR is a data pipeline that transforms raw network traffic into
security intelligence:

**`PCAP`** → **`Zeek`** (Log Generation) → **`Pandas`**
(Data Enrichment) → **`JSON Report`**

- **Language:** Python 3.14 via `uv`
- **Analysis:** Zeek 8.0.5
- **API:** FastAPI
- **Reference data:** Optimized Parquet files generated from JSON

---

## Testing & Validation ##

Once inside the Dev Container, run tests with `pytest`:

```bash
pytest
```

All tests live in `tests/`.

## Attribution ##

Developed for the Cybersecurity and Infrastructure Security Agency
(CISA).
