# Introduction #

{term}`eleVADR` is a network security analysis engine
designed to assess {term}`Operational Technology`
(OT) systems by transforming raw {term}`PCAP` traffic into
actionable security intelligence.

The overall goal is to support the automated analysis of data to
allow anyone operating {term}`OT` to make informed decisions about
their network security posture.

It is currently designed with ease of use in mind by leveraging
{term}`containerization`.

## Core Architecture ##

EleVADR is split into a {term}`frontend` and a {term}`backend`
component.

### Backend ###

The backend is a {term}`Python` application that is used to run
{term}`Zeek` to collect network data and analyze
it with {term}`numpy`, {term}`pandas`, and generate a
{term}`JSON` report.

The backend collects a {term}`PCAP` file from the frontend
and spawns a {term}`Zeek` process to collect
the network logs. Those logs are then converted to {term}`pandas`
using {term}`zat` and then custom
analytics are written to create report modules.

#### Zeek Script Integration ####

eleVADR relies on Zeek to parse raw packet captures (PCAP) and
generate structured log files. To support advanced physical asset
discovery and network logical boundary mapping, the backend executes
custom Zeek scripts located in the `backend/src/app/data/zeek_scripts/`
directory during the analysis pass.

##### 1. MAC Logging Script (`mac_logging.zeek`) #####

By default, Zeek tracks connections at Layer 3 (IP addresses)
and Layer 4 (Ports). However, mapping physical hardware
manufacturers and establishing true hardware identities requires
Layer 2 MAC addresses.

The `mac_logging.zeek` script hooks into Zeek's connection state removal
pipeline and appends Layer 2 source and destination MAC addresses to the
connection metadata.

* **Log Hook:** `connection_state_remove(c: connection)`
* **Extended Fields:**
  * `orig_l2_addr` (String): The hardware MAC address of the initiator (Originator).
  * `resp_l2_addr` (String): The hardware MAC address of the responder.

These fields are mapped to `src_endpoint.mac` and `dst_endpoint.mac`
in the backend Pandas DataFrame, allowing the engine to aggregate
manufacturer profiles via OUI lookup.

---

##### 2. Known Services Script (`known_services.zeek`) DEPRECATED ######

The `known_services.zeek` script tracks active, validated services
communicating on the network. For the purposes of eleVADR, an active service
is defined under the following lifecycle rules:

* **TCP Connections:** Requires a completed TCP handshake (SYN+ACK)
or an established state where server payload transfer is recognized.
Passive, unacknowledged connection attempts
(e.g., ports scanned but not open) are ignored.
* **UDP Connections:** Requires at least one packet from the server side
confirming that the target port is actively responding, unless
the configuration option
`Known::service_udp_requires_response`
is explicitly disabled.
* **ICMP Traffic:** Excluded from service classification.

##### Configurable Options #####

* `service_tracking`: Defaults to `LOCAL_HOSTS`. Limits active service
profiling to local subnets to protect memory overhead.
* `service_store_expiry`: Defaults to `1day`. Forces periodic state
evaluation to prevent stale connection maps on continuous captures.

#### PcapParser ####

The parsing is done through `PcapParser`.

```{eval-rst}
.. autoclass:: src.app.utils.analysis.PcapParser
    :members: parse, zeekify
```

The data is then passed to `Analyzer`.

#### Analyzer ####

The `Analyzer` is responsible for processing the data and running
analytics on the data.

```{eval-rst}
.. autoclass:: src.app.utils.analysis.Analyzer
    :members: traffic_df_processing, endpoints_df_processing,
        services_df_processing, ot_cross_segment_communication_count,
        service_counts_in_traffic
```

It is also responsible for responding to the
frontend to filter the data for unique views.

```{eval-rst}
.. autoclass:: src.app.utils.analysis.Analyzer
    :no-index:
    :members: connection_lines_filtered, devices_filtered, services_filtered
```

#### Structure ####

All of the findings are summarized into a {term}`JSON` report.

```{eval-rst}
.. autoclass:: src.app.utils.report.Report
```

The report is split into different `Modules`. See [Report Modules](#report-modules)
for the list of modules that are available.

### Frontend ###

The frontend is a {term}`React` application that is used to interact
with the {term}`Python` {term}`backend` component.
The frontend takes the {term}`JSON` report that the {term}`backend`
generates and displays it in an interactive format,
allowing the user to filter and drill-down into the data.

The frontend is organized into sections that mirror what the {term}`backend` generates.

#### Upload Form ####

The upload form is where a user can upload a {term}`PCAP` to run the analysis
and download the associated JSON report.
There is also an option to upload a {term}`JSON` report to view it.

#### Report ####

The frontend is a {term}`React` application that is used to interact with the
{term}`Python` {term}`backend` component.
The frontend takes the {term}`JSON` report that the {term}`backend`
generates and displays it in an interactive format,
allowing the user to filter and drill-down into the data.

The frontend is organized into the following sections.

##### Executive Summary #####

The executive summary is a high-level set of key takeaways from the report.
It can include alerts defined by
any class that inherits from `DetectionModule` and implements
`executive_summary`

```{eval-rst}
.. autoclass:: src.app.utils.report.DetectionModule
    :members: executive_summary
```

That list is currently:

```{eval-rst}
.. autoclass:: src.app.utils.report.SuspiciousOutboundConnectionsDetection
.. autoclass:: src.app.utils.report.OTcrossSegmentDetection
```

(report-modules)=

##### Report Modules #####

The report modules are panels that aim to answer specific
analytic questions. Each module inherits from
`ReportModule` and implements `generate_data`

```{eval-rst}
.. autoclass src.app.utils.report.ReportModule
    :members: generate_data
```

That list is currently:

```{eval-rst}
.. autoclass:: src.app.utils.report.DevicePanelModule
.. autoclass:: src.app.utils.report.ServicePanelModule
.. autoclass:: src.app.utils.report.ServiceRiskBreakdownModule
.. autoclass:: src.app.utils.report.ServiceCountModule
.. autoclass:: src.app.utils.report.RiskBasisBreakdownModule
.. autoclass:: src.app.utils.report.ExposureBreakdownModule
.. autoclass:: src.app.utils.report.ConnectionSuccessModule
.. autoclass:: src.app.utils.report.ProtocolPostureModule
.. autoclass:: src.app.utils.report.SuspiciousOutboundConnectionsModule
.. autoclass:: src.app.utils.report.DevicesModule
.. autoclass:: src.app.utils.report.OTServicesModule
```
