import React from "react";
import "./ConnectionSuccessPanel.css";
import Panel from "../Panel/Panel";
import SortableTable, { Column } from "../SortableTable/SortableTable";
import {
  ConnectionSuccessLine,
  ConnectionSuccessPanel as ConnectionSuccessPanelType,
  ElevadrReport,
  ServiceConnectionDetail,
} from "../../types/Report";
import InfoTooltip from "../InfoTooltip/InfoTooltip";
import DetailModal from "../DetailModal/DetailModal";
import PivotValue from "../PivotValue/PivotValue";
import { InvestigationFilter, SelectedEntity } from "../../types/Investigation";
import { useDrilldown } from "../../hooks/useDrilldown";
import { fetchConnectionStateDrilldown } from "../../services/drilldownService";

interface ConnectionSuccessPanelProps {
  data: ConnectionSuccessPanelType;
  reportId: ElevadrReport["report_id"];
  filters?: InvestigationFilter[];
  onFilter?: (filter: InvestigationFilter) => void;
  onSelect?: (entity: SelectedEntity) => void;
}

interface ConnectionStateRow {
  state: string;
  count: number;
}

interface ConnectionTableRow {
  srcIp: string | null;
  dstIp: string | null;
  port: number | null;
  service: string;
  state: string | null;
  history: string | null;
  outcome: string;
}

const toStateRows = (byState: Record<string, number>): ConnectionStateRow[] =>
  Object.entries(byState).map(([state, count]) => ({
    state,
    count,
  }));

const toConnectionTableRows = (
  connections: ConnectionSuccessLine[],
): ConnectionTableRow[] =>
  connections.map((connection) => ({
    srcIp: connection["src_endpoint.ip"],
    dstIp: connection["dst_endpoint.ip"],
    port: connection["dst_endpoint.port"],
    service:
      connection["service.name"] ||
      connection["connection_info.protocol_name"] ||
      `Port ${connection["dst_endpoint.port"] ?? "—"}`,
    state: connection.state,
    history: connection.history ?? null,
    outcome: connection.success ? "Successful" : "Unsuccessful",
  }));

const ConnectionSuccessPanel: React.FC<ConnectionSuccessPanelProps> = ({
  data,
  reportId,
  filters = [],
  onFilter,
  onSelect,
}) => {
  const drilldown = useDrilldown((state: string) =>
    fetchConnectionStateDrilldown(reportId, state),
  );
  const stateRows = toStateRows(data.summary.by_state);
  const connectionRows = toConnectionTableRows(data.connections);

  const handleStateClick = async (state: string) => {
    await drilldown.open(state);
  };

  const closeModal = () => {
    drilldown.close();
  };

  const stateColumns: Column<unknown, ConnectionStateRow>[] = [
    {
      key: "state",
      label: "Zeek State",
      sortable: true,
      clickable: true,
      onClick: (value) => handleStateClick(value as string),
      render: (value) =>
        value && onFilter ? (
          <PivotValue
            filter={{
              key: "zeekState",
              value: String(value),
              label: "Zeek State",
            }}
            filters={filters}
            onFilter={onFilter}
          >
            {String(value)}
          </PivotValue>
        ) : (
          <button type="button" className="clickable-service-link">
            {String(value ?? "—")}
          </button>
        ),
    },
    { key: "count", label: "Count", sortable: true, align: "right" },
  ];

  const connectionColumns: Column<unknown, ConnectionTableRow>[] = [
    {
      key: "srcIp",
      label: "Source IP",
      sortable: true,
      render: (value) =>
        value && onFilter ? (
          <PivotValue
            filter={{ key: "ip", value: String(value), label: "Device" }}
            filters={filters}
            onFilter={onFilter}
          >
            {String(value)}
          </PivotValue>
        ) : (
          ((value as string | null) ?? "—")
        ),
    },
    {
      key: "dstIp",
      label: "Destination IP",
      sortable: true,
      render: (value) =>
        value && onFilter ? (
          <PivotValue
            filter={{ key: "ip", value: String(value), label: "Device" }}
            filters={filters}
            onFilter={onFilter}
          >
            {String(value)}
          </PivotValue>
        ) : (
          ((value as string | null) ?? "—")
        ),
    },
    {
      key: "port",
      label: "Port",
      sortable: true,
      align: "right",
      render: (value) =>
        value != null && onFilter ? (
          <PivotValue
            filter={{ key: "port", value: String(value), label: "Port" }}
            filters={filters}
            onFilter={onFilter}
          >
            {String(value)}
          </PivotValue>
        ) : (
          ((value as number | null) ?? "—")
        ),
    },
    {
      key: "service",
      label: "Service",
      sortable: true,
      render: (value) =>
        value && onFilter ? (
          <PivotValue
            filter={{ key: "service", value: String(value), label: "Service" }}
            filters={filters}
            onFilter={onFilter}
          >
            {String(value)}
          </PivotValue>
        ) : (
          String(value ?? "—")
        ),
    },
    {
      key: "state",
      label: "Zeek State",
      sortable: true,
      render: (value) =>
        value && onFilter ? (
          <PivotValue
            filter={{
              key: "zeekState",
              value: String(value),
              label: "Zeek State",
            }}
            filters={filters}
            onFilter={onFilter}
          >
            {String(value)}
          </PivotValue>
        ) : (
          String(value ?? "—")
        ),
    },
    { key: "history", label: "Zeek History", sortable: true },
    { key: "outcome", label: "Outcome", sortable: true },
  ];

  const detailColumns: Column<unknown, ServiceConnectionDetail>[] = [
    {
      key: "src_endpoint.ip",
      label: "Source IP",
      sortable: true,
      render: (value) =>
        value && onFilter ? (
          <PivotValue
            filter={{ key: "ip", value: String(value), label: "Device" }}
            filters={filters}
            onFilter={onFilter}
          >
            {String(value)}
          </PivotValue>
        ) : (
          ((value as string | null) ?? "—")
        ),
    },
    {
      key: "src_endpoint.port",
      label: "Src Port",
      sortable: true,
      align: "right",
      render: (value) =>
        value != null && onFilter ? (
          <PivotValue
            filter={{ key: "port", value: String(value), label: "Port" }}
            filters={filters}
            onFilter={onFilter}
          >
            {String(value)}
          </PivotValue>
        ) : (
          ((value as number | null) ?? "—")
        ),
    },
    {
      key: "dst_endpoint.ip",
      label: "Destination IP",
      sortable: true,
      render: (value) =>
        value && onFilter ? (
          <PivotValue
            filter={{ key: "ip", value: String(value), label: "Device" }}
            filters={filters}
            onFilter={onFilter}
          >
            {String(value)}
          </PivotValue>
        ) : (
          ((value as string | null) ?? "—")
        ),
    },
    {
      key: "dst_endpoint.port",
      label: "Dst Port",
      sortable: true,
      align: "right",
      render: (value) =>
        value != null && onFilter ? (
          <PivotValue
            filter={{ key: "port", value: String(value), label: "Port" }}
            filters={filters}
            onFilter={onFilter}
          >
            {String(value)}
          </PivotValue>
        ) : (
          ((value as number | null) ?? "—")
        ),
    },
    {
      key: "service.name",
      label: "Service",
      sortable: true,
      render: (value) =>
        value && onFilter ? (
          <PivotValue
            filter={{ key: "service", value: String(value), label: "Service" }}
            filters={filters}
            onFilter={onFilter}
          >
            {String(value)}
          </PivotValue>
        ) : (
          ((value as string | null) ?? "—")
        ),
    },
    { key: "connection_info.protocol_name", label: "Protocol", sortable: true },
    {
      key: "connection_info.direction_name",
      label: "Direction",
      sortable: true,
    },
    {
      key: "state",
      label: "State",
      sortable: true,
      render: (value) =>
        value && onFilter ? (
          <PivotValue
            filter={{
              key: "zeekState",
              value: String(value),
              label: "Zeek State",
            }}
            filters={filters}
            onFilter={onFilter}
          >
            {String(value)}
          </PivotValue>
        ) : (
          String(value ?? "—")
        ),
    },
    { key: "history", label: "History", sortable: true },
    {
      key: "success",
      label: "Success",
      sortable: true,
      render: (value) => (value ? "Yes" : "No"),
    },
  ];

  const isEmpty =
    data.summary.successful_count === 0 &&
    data.summary.unsuccessful_count === 0 &&
    stateRows.length === 0 &&
    connectionRows.length === 0;

  return (
    <Panel
      id="connection-success-panel"
      title={
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span>Connection Success</span>
          <InfoTooltip text="Connection outcomes are derived from Zeek conn_state. Successful connections are currently classified as SF; all other states are treated as unsuccessful. Zeek history is also shown for analyst drill-down, but it is not used as the primary success/failure signal." />
        </div>
      }
      isEmpty={isEmpty}
    >
      <div className="connection-success-summary">
        <div className="summary-card">
          <span className="summary-label">Successful</span>
          <span className="summary-value summary-value-success">
            {data.summary.successful_count}
          </span>
        </div>

        <div className="summary-card">
          <span className="summary-label">Unsuccessful</span>
          <span className="summary-value summary-value-failure">
            {data.summary.unsuccessful_count}
          </span>
        </div>
      </div>

      <div className="connection-success-tables">
        <div className="connection-success-section">
          <SortableTable
            columns={stateColumns}
            data={stateRows}
            filterable={true}
            filterHeader={
              <h3 className="section-subtitle">
                <div
                  style={{ display: "flex", alignItems: "center", gap: "8px" }}
                >
                  <span>Breakdown by Zeek State</span>
                  <InfoTooltip text="Counts by Zeek conn_state value, such as SF, S0, or REJ." />
                </div>
              </h3>
            }
            filterPlaceholder="Search states..."
            emptyMessage="No Results"
          />
        </div>

        <div className="connection-success-section">
          <SortableTable
            columns={connectionColumns}
            data={connectionRows}
            onRowClick={(row) => {
              if (row.srcIp && row.dstIp)
                onSelect?.({
                  type: "connection",
                  id: `${row.srcIp}|${row.dstIp}|${row.service}`,
                });
            }}
            filterable={true}
            filterHeader={
              <h3 className="section-subtitle">
                <div
                  style={{ display: "flex", alignItems: "center", gap: "8px" }}
                >
                  <span>Sample Connections</span>
                  <InfoTooltip text="Sample per-connection rows annotated with success or failure, plus the raw Zeek history field for deeper inspection." />
                </div>
              </h3>
            }
            filterPlaceholder="Search connections..."
            emptyMessage="No Results"
          />
        </div>
      </div>
      <DetailModal
        isOpen={Boolean(drilldown.selectedKey)}
        title={
          drilldown.selectedKey
            ? `Connection State Details: ${drilldown.selectedKey}`
            : "Connection State Details"
        }
        onClose={closeModal}
      >
        {drilldown.isLoading && <p>Loading connection details...</p>}
        {drilldown.error && <p>{drilldown.error}</p>}
        {!drilldown.isLoading && !drilldown.error && (
          <SortableTable<unknown, ServiceConnectionDetail>
            columns={detailColumns}
            data={drilldown.data?.connections || []}
            filterable={true}
            filterPlaceholder="Search connection state details..."
            emptyMessage="No connections found for this state"
          />
        )}
      </DetailModal>
    </Panel>
  );
};

export default ConnectionSuccessPanel;
