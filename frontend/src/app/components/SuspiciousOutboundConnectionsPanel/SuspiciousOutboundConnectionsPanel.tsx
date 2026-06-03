import React from "react";
import "./SuspiciousOutboundConnectionsPanel.css";
import Panel from "../Panel/Panel";
import SortableTable, { Column } from "../SortableTable/SortableTable";
import {
  ElevadrReport,
  ServiceConnectionDetail,
  SuspiciousOutboundConnection,
} from "../../types/Report";
import InfoTooltip from "../InfoTooltip/InfoTooltip";
import DetailModal from "../DetailModal/DetailModal";
import { useDrilldown } from "../../hooks/useDrilldown";
import { fetchSuspiciousOutboundDrilldown } from "../../services/drilldownService";

interface SuspiciousOutboundConnectionsPanelProps {
  data: SuspiciousOutboundConnection[];
  reportId: ElevadrReport["report_id"];
}

interface SuspiciousOutboundRow {
  srcIp: string;
  dstIp: string;
  port: number;
  service: string;
  count: number;
}

const SuspiciousOutboundConnectionsPanel: React.FC<
  SuspiciousOutboundConnectionsPanelProps
> = ({ data, reportId }) => {
  const drilldown = useDrilldown((row: SuspiciousOutboundRow) =>
    fetchSuspiciousOutboundDrilldown(
      reportId,
      row.srcIp,
      row.dstIp,
      row.port,
      row.service,
    ),
  );
  const tableData = data.map((conn) => ({
    srcIp: conn["src_endpoint.ip"],
    dstIp: conn["dst_endpoint.ip"],
    port: conn["dst_endpoint.port"],
    service: conn["service.name"],
    count: conn.count,
  }));

  const handleRowClick = async (row: SuspiciousOutboundRow) => {
    await drilldown.open(row);
  };

  const closeModal = () => {
    drilldown.close();
  };

  const columns: Column<unknown, SuspiciousOutboundRow>[] = [
    {
      key: "srcIp",
      label: (
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span>Source IP</span>
          <InfoTooltip text="The IP address of the device initiating the outbound connection." />
        </div>
      ),
      sortable: true,
      clickable: true,
      onClick: (_value, row) => handleRowClick(row as SuspiciousOutboundRow),
      render: (value) => <span className="ip-cell">{String(value ?? "")}</span>,
    },
    {
      key: "dstIp",
      label: (
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span>Destination IP</span>
          <InfoTooltip text="The IP address of the external server or device receiving the outbound connection." />
        </div>
      ),
      sortable: true,
      clickable: true,
      onClick: (_value, row) => handleRowClick(row as SuspiciousOutboundRow),
      render: (value) => <span className="ip-cell">{String(value ?? "")}</span>,
    },
    {
      key: "port",
      label: (
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span>Port</span>
          <InfoTooltip text="The destination port number used for the outbound connection." />
        </div>
      ),
      sortable: true,
      align: "center",
      clickable: true,
      onClick: (_value, row) => handleRowClick(row as SuspiciousOutboundRow),
      render: (value) => (
        <span className="port-cell">{String(value ?? "")}</span>
      ),
    },
    {
      key: "service",
      label: (
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span>Service</span>
          <InfoTooltip text="The service or protocol associated with the outbound connection." />
        </div>
      ),
      sortable: true,
      clickable: true,
      onClick: (_value, row) => handleRowClick(row as SuspiciousOutboundRow),
    },
    {
      key: "count",
      label: (
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span>Count</span>
          <InfoTooltip text="The number of times this specific suspicious outbound connection was observed." />
        </div>
      ),
      sortable: true,
      align: "center",
      clickable: true,
      onClick: (_value, row) => handleRowClick(row as SuspiciousOutboundRow),
      render: (value) => (
        <span className="count-cell">{String(value ?? "")}</span>
      ),
    },
  ];

  const isEmpty = data.length === 0;

  return (
    <Panel
      id="suspicious-outbound-connections-panel"
      title={
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span>Suspicious Outbound Connections</span>
          <InfoTooltip text="OT devices making outbound connections to external IP addresses - potentially indicating unauthorized access or data exfiltration." />
        </div>
      }
      isEmpty={isEmpty}
    >
      <SortableTable
        columns={columns}
        data={tableData}
        filterable={true}
        filterPlaceholder="Search by IP, port, or service..."
        emptyMessage="No Results"
      />
      <DetailModal
        isOpen={Boolean(drilldown.selectedKey)}
        title={
          drilldown.selectedKey
            ? `Suspicious Outbound Details: ${drilldown.selectedKey.srcIp} → ${drilldown.selectedKey.dstIp}:${drilldown.selectedKey.port}`
            : "Suspicious Outbound Details"
        }
        onClose={closeModal}
      >
        {drilldown.isLoading && (
          <p>Loading suspicious outbound connection details...</p>
        )}
        {drilldown.error && <p>{drilldown.error}</p>}
        {!drilldown.isLoading && !drilldown.error && (
          <SortableTable
            columns={[
              { key: "src_endpoint.ip", label: "Source IP", sortable: true },
              {
                key: "src_endpoint.port",
                label: "Src Port",
                sortable: true,
                align: "right",
              },
              {
                key: "dst_endpoint.ip",
                label: "Destination IP",
                sortable: true,
              },
              {
                key: "dst_endpoint.port",
                label: "Dst Port",
                sortable: true,
                align: "right",
              },
              { key: "service.name", label: "Service", sortable: true },
              {
                key: "connection_info.protocol_name",
                label: "Protocol",
                sortable: true,
              },
              {
                key: "connection_info.direction_name",
                label: "Direction",
                sortable: true,
              },
              { key: "state", label: "State", sortable: true },
              { key: "history", label: "History", sortable: true },
              {
                key: "success",
                label: "Success",
                sortable: true,
                render: (value) => (value ? "Yes" : "No"),
              },
            ]}
            data={
              drilldown.data?.connections || ([] as ServiceConnectionDetail[])
            }
            filterable={true}
            filterPlaceholder="Search suspicious outbound connection details..."
            emptyMessage="No matching connections found"
          />
        )}
      </DetailModal>
    </Panel>
  );
};

export default SuspiciousOutboundConnectionsPanel;
