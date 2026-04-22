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

---

**Developed for the Cybersecurity and Infrastructure Security Agency (CISA)**
