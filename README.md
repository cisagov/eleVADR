# eleVADR - OT Network Security Analysis Tool #

A network security analysis tool developed for the Cybersecurity and
Infrastructure Security Agency (CISA) to assess operational technology
(OT) systems through PCAP analysis. eleVADR processes network traffic
captures using Zeek and conducts backend analysis with pandas to
identify assets, services, security risks, and provide actionable
remediation guidance.

## Overview ##

eleVADR analyzes OT network traffic to provide comprehensive security
assessments including:

- **Asset Discovery**: Identification of network devices, IP addresses,
  MAC addresses, and manufacturers
- **Service Detection**: Recognition of network services including
  industrial protocols such as Modbus and DNP3
- **Risk Assessment**: Classification of services by security risk
  categories
- **Network Segmentation Analysis**: Detection of cross-segment
  communications
- **Security Findings**: Identification of insecure protocols,
  suspicious outbound connections, and risky services
- **Detailed Reporting**: JSON-formatted reports with executive
  summaries and detailed module data
- **Interactive Drilldown APIs**: Report-scoped endpoints for filtering
  connections, devices, and services after analysis

## Key Features ##

### Analysis Capabilities ###

- **Traffic Analysis**: Processes network flows to classify connection
  types such as unicast, multicast, and broadcast, along with direction
  and protocol metadata
- **Endpoint Profiling**: Identifies and profiles devices including
  manufacturer information, IP assignments, service usage, and OT
  classification
- **Service Classification**: Maps ports to services and categorizes
  them by information type and risk level
- **OT Device Detection**: Identifies devices using industrial
  protocols or communicating with OT hosts
- **Cross-Segment Detection**: Flags OT devices communicating across
  network segments

### Report Modules ###

The tool generates comprehensive reports with the following modules:

1. **Device Panel**: Total hosts, OT hosts, cross-segment OT
   communications
1. **Service Panel**: Known services, OT-specific protocols, risky
   services, and unknown services
1. **Service Risk Breakdown**: Categorization and counts of services by
   risk category
1. **Service Count Panel**: Connection frequency analysis per service
1. **Suspicious Outbound Connections**: External communications from OT
   devices
1. **OT Manufacturers**: Distribution of OT device manufacturers
1. **OT Services**: Detailed list of industrial protocols detected
1. **Connection Success Panel**: Successful vs unsuccessful Zeek
   connection-state summary and sample detail rows

---

## Attribution ##

Developed for the Cybersecurity and Infrastructure Security Agency
(CISA).
