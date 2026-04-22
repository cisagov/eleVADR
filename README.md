**MAIN PROJECT README AT [elevadr-orchestration](https://github.com/cisa-vulnerability-management/elevadr-orchestration) -- START HERE FOR DEVELOPMENT**

# eleVADR - OT Network Security Analysis Tool

A network security analysis tool developed for the Cybersecurity and Infrastructure Security Agency (CISA) to assess operational technology (OT) systems through PCAP analysis. eleVADR processes network traffic captures using Zeek and conducts backend analysis with pandas to identify assets, services, security risks, and provide actionable remediation guidance.

## Overview

eleVADR analyzes OT network traffic to provide comprehensive security assessments including:

- **Asset Discovery**: Identification of network devices, IP addresses, MAC addresses, and manufacturers
- **Service Detection**: Recognition of network services including industrial protocols (Modbus, DNP3, etc.)
- **Risk Assessment**: Classification of services by security risk categories
- **Network Segmentation Analysis**: Detection of cross-segment communications
- **Security Findings**: Identification of insecure protocols, suspicious outbound connections, and risky services
- **Detailed Reporting**: JSON-formatted reports with executive summaries and detailed module data
- **Interactive Drilldown APIs**: Report-scoped endpoints for filtering connections, devices, and services after analysis

## Key Features

### Analysis Capabilities

- **Traffic Analysis**: Processes network flows to classify connection types (unicast, multicast, broadcast), directions (inbound, outbound, lateral), and protocols
- **Endpoint Profiling**: Identifies and profiles devices including manufacturer information, IP assignments, service usage, and OT classification
- **Service Classification**: Maps ports to services and categorizes by information type and risk level
- **OT Device Detection**: Identifies devices using industrial protocols or communicating with OT hosts
- **Cross-Segment Detection**: Flags OT devices communicating across network segments (a common security concern)

### Report Modules

The tool generates comprehensive reports with the following modules:

1. **Device Panel**: Total hosts, OT hosts, cross-segment OT communications
2. **Service Panel**: Known services, OT-specific protocols, risky services, unknown services
3. **Service Risk Breakdown**: Categorization and counts of services by risk category
4. **Service Count Panel**: Connection frequency analysis per service
5. **Suspicious Outbound Connections**: External communications from OT devices
6. **OT Manufacturers**: Distribution of OT device manufacturers
7. **OT Services**: Detailed list of industrial protocols detected
8. **Connection Success Panel**: Successful vs unsuccessful Zeek connection-state summary and sample detail rows

## Prerequisites

### Required Software

- **Python 3.10+**
- **Zeek Network Security Monitor** (formerly Bro)
- **pip** (Python package manager)

### System Requirements

- macOS, Linux, or Windows (with WSL recommended)
- Sufficient disk space for PCAP files and Zeek logs
- Minimum 4GB RAM recommended for processing large PCAP files

## Installation

### 1. Install Zeek

#### macOS (using Homebrew)
```bash
brew install zeek
```

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install zeek
```

#### CentOS/RHEL
```bash
sudo yum install zeek
```

#### From Source
Visit [https://zeek.org/get-zeek/](https://zeek.org/get-zeek/) for detailed installation instructions.

### 2. Clone the Repository

```bash
git clone <repository-url>
cd eleVADR
```

### 3. Set Up Python Environment

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

Install required Python packages:

```bash
pip install -r requirements.txt
```

### 4. Verify Installation

Check that Zeek is properly installed:

```bash
zeek --version
```

## Configuration

### Directory Structure

The application expects the following directory structure (created automatically if missing):

```
eleVADR/src
├── app/
│   ├── data/
│   │   ├── assessor_data/      # Reference data (ports, risks, manufacturers)
│   │   ├── uploads/            # PCAP files to analyze
│   │   ├── zeek_scripts/       # Custom Zeek scripts
│   │   └── zeeks/              # Zeek output logs
│   ├── utils/
│   │   ├── analysis.py         # Core analysis logic
│   │   ├── report.py           # Report generation
│   │   └── utils.py            # Utility functions
│   └── main.py                 # Main entry point
```

### Reference Data Files

The following JSON files in `app/data/assessor_data/` provide enrichment data:

- **ports.json**: Port-to-service mappings
- **port_risk.json**: Service risk categorizations (converts to parquet)
- **latest_oui_lookup.json**: MAC address OUI to manufacturer mappings
- **CONST.yml**: ICS manufacturer keywords and insecure protocol definitions

These files must be present for the tool to function. Generate the OUI lookup file using:

```bash
python app/utils/download_and_parse_oui.py
```

## Usage

### Docker Usage (Recommended)

The easiest way to use eleVADR is with Docker, which bundles all dependencies including Zeek.

#### Quick Start with Docker

1. **Build the Docker image:**

```bash
docker build -t elevadr:latest .
```

2. **Run analysis on a PCAP file:**

```bash
# Create directories for input/output
mkdir -p pcaps reports

# Copy your PCAP file
cp /path/to/your/capture.pcap pcaps/capture.pcap

# Run the analysis
docker run --rm \
  -v $(pwd)/pcaps:/input:ro \
  -v $(pwd)/reports:/output \
  elevadr:latest
```

3. **View the report:**

```bash
cat reports/report.json
```

#### Using Docker Compose

For easier management, use docker-compose:

```bash
# Place your PCAP in ./pcaps/capture.pcap
cp /path/to/your/capture.pcap pcaps/capture.pcap

# Run analysis
docker-compose up elevadr

# Optional: Start web server to browse reports
docker-compose --profile web-server up -d report-server
# Access reports at http://localhost:8080
```

#### Custom Configuration

You can override default paths using environment variables:

```bash
docker run --rm \
  -v $(pwd)/pcaps:/input:ro \
  -v $(pwd)/reports:/output \
  -e PCAP_INPUT=/input/my-capture.pcap \
  -e REPORT_OUTPUT=/output/my-report.json \
  elevadr:latest
```

### Kubernetes Deployment

For scalable, production deployments, use Kubernetes to process multiple PCAPs in parallel.

#### Prerequisites

- Kubernetes cluster (local with minikube/kind, or cloud-based)
- kubectl configured
- Container registry (Docker Hub, GCR, ECR, etc.)

#### Deployment Steps

1. **Build and push the image:**

```bash
# Build image
docker build -t your-registry/elevadr:latest .

# Push to registry
docker push your-registry/elevadr:latest
```

2. **Update image reference in k8s/kustomization.yaml:**

```yaml
images:
  - name: elevadr
    newName: your-registry/elevadr
    newTag: latest
```

3. **Deploy to Kubernetes:**

```bash
# Apply all manifests
kubectl apply -k k8s/

# Verify deployment
kubectl get all -n elevadr
```

4. **Upload PCAP for analysis:**

```bash
# Copy PCAP to the input PVC
kubectl cp /path/to/capture.pcap elevadr/elevadr-analysis-xxxxx:/input/capture.pcap

# Or create a pod to upload files
kubectl run -n elevadr pcap-uploader --image=busybox --rm -it --restart=Never -- sh
# Then use kubectl cp to transfer files
```

5. **Monitor job progress:**

```bash
# Watch job status
kubectl get jobs -n elevadr -w

# View logs
kubectl logs -n elevadr job/elevadr-analysis -f

# Get report
kubectl cp elevadr/elevadr-analysis-xxxxx:/output/report.json ./report.json
```

#### Scaling with Kubernetes

**Process Multiple PCAPs in Parallel:**

```bash
# Create multiple jobs from template
for pcap in *.pcap; do
  kubectl create job -n elevadr "analysis-${pcap%.pcap}" \
    --from=cronjob/elevadr-scheduled-analysis
done
```

**Horizontal Scaling:**

Modify k8s/job.yaml to use `parallelism` and `completions`:

```yaml
spec:
  parallelism: 5      # Run 5 pods in parallel
  completions: 10     # Process 10 total jobs
```

**Scheduled Analysis with CronJob:**

Enable the CronJob in k8s/kustomization.yaml:

```yaml
resources:
  - cronjob.yaml  # Uncomment this line
```

**Resource Optimization:**

Adjust CPU/memory in k8s/job.yaml based on PCAP size:

```yaml
resources:
  requests:
    memory: "2Gi"   # Minimum needed
    cpu: "1000m"
  limits:
    memory: "8Gi"   # Maximum allowed
    cpu: "4000m"
```

#### Storage Options for Kubernetes

**Option 1: Persistent Volume Claims (Default)**
- Uses PVCs defined in k8s/pvc.yaml
- Suitable for shared storage across multiple jobs
- Requires a StorageClass that supports ReadWriteMany

**Option 2: ConfigMaps (Small PCAPs)**

```bash
# Create ConfigMap from PCAP
kubectl create configmap -n elevadr pcap-data \
  --from-file=capture.pcap=/path/to/capture.pcap

# Update job.yaml to mount ConfigMap
```

**Option 3: Object Storage (S3, GCS)**
- Modify entrypoint script to download from cloud storage
- Add cloud provider credentials as Kubernetes Secrets

### Local Installation (Without Docker)

If you prefer to run eleVADR natively:

1. Place your PCAP file in `app/data/uploads/`

2. Update the PCAP path in `app/main.py:25`:

```python
file_path_info = FilePathInfo(
    path_to_pcap=str(Path(PROJECT_ROOT, "data/uploads/YOUR_PCAP_FILE.pcap")),
    path_to_zeek=str(Path(PROJECT_ROOT, "data/zeeks")),
    path_to_zeek_scripts=str(Path(PROJECT_ROOT, "data/zeek_scripts")),
    path_to_assessor_data=str(Path(PROJECT_ROOT, "data/assessor_data"))
)
```

3. Run the analysis:

```bash
cd app
python main.py
```

4. The analysis will:
   - Process the PCAP with Zeek (creates logs in `data/zeeks/<pcap_filename>/`)
   - Parse connection logs into dataframes
   - Enrich data with service, risk, and manufacturer information
   - Generate a comprehensive JSON report (printed to stdout)

### API Drilldowns

When the FastAPI application is running, analyzed reports are kept in an in-memory report registry and can be queried through report-scoped APIs.

#### Existing drilldown endpoints

- `GET /reports/{report_id}/drilldown/service/{service_name}`
- `GET /reports/{report_id}/drilldown/connection-state/{state}`
- `GET /reports/{report_id}/drilldown/suspicious-outbound`
- `GET /reports/{report_id}/drilldown/cross-segment`

#### Filter endpoints

- `GET /reports/{report_id}/connections`
- `GET /reports/{report_id}/devices`
- `GET /reports/{report_id}/services`

Example connection filters:

- `ip`
- `src_ip`
- `dst_ip`
- `subnet`
- `src_subnet`
- `dst_subnet`
- `manufacturer`
- `service_name`
- `connection_state`
- `direction`
- `success`
- `is_ot`
- `limit`

Example device filters:

- `manufacturer`
- `subnet`
- `service_name`
- `is_ot`
- `is_edge`

Example service filters:

- `subnet`
- `manufacturer`
- `device_ip`
- `risk_category`
- `service_name`

These APIs support frontend workflows such as clicking a service, risk category, Zeek state, suspicious outbound row, or subnet pair and retrieving the underlying matching records.

### Understanding the Output

The tool outputs a JSON report with the following structure:

```json
{
    "executive_summary": {},
    "modules": {
        "device_panel": {
            "hosts": <total_devices>,
            "ot_hosts": <ot_devices>,
            "ot_cross_segment": <cross_segment_count>
        },
        "service_panel": {
            "num_known_services": <count>,
            "num_ot_services": <count>,
            "num_risky_services": <count>,
            "num_unknown_services": <count>
        },
        "service_risk_breakdown_panel": {...},
        "service_count_panel": {...},
        "suspicious_outbound_connections_panel": [...],
        "ot_manufacturers": {...},
        "ot_services": [...]
    },
    "arch_insights": {}
}
```

### Zeek Processing

The tool runs two Zeek analysis passes:

1. **Default Zeek Processing**: Generates standard conn.log with connection metadata
2. **MAC Logging Script**: Adds link-layer (MAC) addresses to connection logs using `mac_logging.zeek`

Zeek logs are stored in `app/data/zeeks/<pcap_filename>/` and can be analyzed independently if needed.

## Key Security Insights

### What eleVADR Detects

1. **Insecure Protocols**: Identifies use of FTP, Telnet, unencrypted LDAP
2. **Industrial Protocols**: Detects Modbus, DNP3, BACnet, and other OT-specific protocols
3. **Cross-Segment Communication**: Flags OT devices communicating across network boundaries
4. **Suspicious External Connections**: Identifies OT devices with outbound internet connections
5. **Risky Services**: Categorizes services by security risk (cleartext credentials, known vulnerabilities, etc.)
6. **Unknown Services**: Highlights unrecognized services requiring investigation

### Risk Categories

Services are classified with risk categories including:

- Cleartext credentials
- Known vulnerabilities
- Weak authentication
- Legacy protocols
- Unnecessary services in OT environments

## Development

### Project Structure

- **app/main.py**: Entry point, orchestrates analysis workflow
- **app/utils/analysis.py**: Core classes (`PcapParser`, `Analyzer`)
- **app/utils/report.py**: Report generation logic and modules
- **app/utils/utils.py**: Helper functions for IP processing, service mapping, etc.

### Key Classes

- **`FilePathInfo`**: Configuration container for file paths
- **`PcapParser`**: Processes PCAP files using Zeek, creates traffic dataframe
- **`Analyzer`**: Enriches traffic data, generates endpoint and service dataframes
- **`Report`**: Aggregates analysis results into structured report modules

### Extending the Tool

To add new analysis modules:

1. Add analysis method to the `Analyzer` class in `app/utils/analysis.py`
2. Create corresponding report module in `Report` class in `app/utils/report.py`
3. Call the new module in `Report.build_report()` method

## Troubleshooting

### Common Issues

**Zeek not found**
- Ensure Zeek is installed and in your PATH
- Test with `zeek --version`

**Missing reference data files**
- Run `python app/utils/download_and_parse_oui.py` to generate OUI lookup
- Ensure ports.json and port_risk.json exist in `app/data/assessor_data/`

**Out of memory errors**
- Process smaller PCAP files
- Increase available system memory
- Consider chunking large PCAPs

**No devices classified as OT**
- Verify PCAP contains OT protocol traffic
- Check that industrial protocol port mappings are in ports.json
- Review CONST.yml for manufacturer keywords

## Security Considerations

This tool is designed for **defensive security purposes only**:

- Network assessment and security auditing
- Vulnerability identification and remediation
- Compliance validation
- Incident response and forensics

**Do not use for**:
- Unauthorized network scanning
- Offensive security operations without proper authorization
- Any malicious purposes

## License

[Specify license here]

## Contributing

[Specify contribution guidelines]

## Contact

For questions or support regarding this tool, please contact [appropriate CISA contact or team].

## Acknowledgments

This tool utilizes:
- **Zeek**: Network security monitoring platform
- **ZAT (Zeek Analysis Tools)**: Python library for Zeek log processing
- **pandas**: Data analysis and manipulation
- OUI database from IEEE for manufacturer identification

---

**Developed for the Cybersecurity and Infrastructure Security Agency (CISA)**
