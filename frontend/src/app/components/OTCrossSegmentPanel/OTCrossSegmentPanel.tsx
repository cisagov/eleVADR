import React from "react";
import Panel from "../Panel/Panel";
import {
  ElevadrReport,
  OTActivityCrossSegmentLine,
  OTcrossSegmentLinesPanel,
  OTSubnetPairCount,
  ServiceConnectionDetail,
} from "../../types/Report";
import InfoTooltip from "../InfoTooltip/InfoTooltip";
import SortableTable, { Column } from "../SortableTable/SortableTable";
import DetailModal from "../DetailModal/DetailModal";
import { useDrilldown } from "../../hooks/useDrilldown";
import { fetchCrossSegmentDrilldown } from "../../services/drilldownService";
import PivotValue from "../PivotValue/PivotValue";
import { InvestigationFilter, SelectedEntity } from "../../types/Investigation";

interface OTCrossSegmentPanelProps {
  data?: OTcrossSegmentLinesPanel | null;
  reportId: ElevadrReport["report_id"];
  filters?: InvestigationFilter[];
  onFilter?: (filter: InvestigationFilter) => void;
  onSelect?: (entity: SelectedEntity) => void;
}

const formatIpForDisplay = (ip?: string | null): string => {
  if (!ip || ip === "0.0.0.0" || ip === "::") {
    return "Unknown";
  }

  return ip;
};

const OTCrossSegmentPanel: React.FC<OTCrossSegmentPanelProps> = ({
  data,
  reportId,
  filters = [],
  onFilter,
  onSelect,
}) => {
  const drilldown = useDrilldown(
    ({ src_subnet, dst_subnet }: { src_subnet: string; dst_subnet: string }) =>
      fetchCrossSegmentDrilldown(reportId, src_subnet, dst_subnet),
  );
  const payload: OTcrossSegmentLinesPanel = data ?? {
    lines: [],
    subnet_pair_counts: [],
    dst_subnet_counts: [],
    ot_device_counts: [],
  };

  const handleSubnetPairClick = async (row: {
    src_subnet: string;
    dst_subnet: string;
  }) => {
    await drilldown.open(row);
  };

  const closeModal = () => {
    drilldown.close();
  };

  const isEmpty =
    payload.lines.length === 0 &&
    payload.subnet_pair_counts.length === 0 &&
    payload.dst_subnet_counts.length === 0 &&
    payload.ot_device_counts.length === 0;

  return (
    <Panel
      id="ot-cross-segment-panel"
      title={
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span>OT Cross-Segment Communications</span>
          <InfoTooltip text="OT communications observed across different Subnet/VLAN boundaries. Review segmentation enforcement and investigate unexpected lateral movement." />
        </div>
      }
      isEmpty={isEmpty}
    >
      <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
        <div
          style={{
            display: "flex",
            gap: "16px",
            alignItems: "baseline",
            flexWrap: "wrap",
          }}
        >
          {/* <div style={{ fontWeight: 700, fontSize: '1.1rem' }}>{payload.lines.length}</div> */}
          <div style={{ color: "#6b6b6b" }}>
            cross-segment communication example(s)
          </div>
        </div>

        <section
          style={{ display: "flex", flexDirection: "column", gap: "8px" }}
        >
          <SortableTable<unknown, OTSubnetPairCount>
            columns={
              [
                {
                  key: "src_subnet",
                  label: "Source Subnet",
                  sortable: true,
                  clickable: true,
                  onClick: (_value, row) =>
                    handleSubnetPairClick(
                      row as { src_subnet: string; dst_subnet: string },
                    ),
                },
                {
                  key: "dst_subnet",
                  label: "Destination Subnet",
                  sortable: true,
                  clickable: true,
                  onClick: (_value, row) =>
                    handleSubnetPairClick(
                      row as { src_subnet: string; dst_subnet: string },
                    ),
                },
                {
                  key: "count",
                  label: "Count",
                  sortable: true,
                  align: "right",
                  clickable: true,
                  onClick: (_value, row) =>
                    handleSubnetPairClick(
                      row as { src_subnet: string; dst_subnet: string },
                    ),
                },
              ] satisfies Column<unknown, OTSubnetPairCount>[]
            }
            data={payload.subnet_pair_counts}
            filterable={true}
            filterHeader={
              <div style={{ fontWeight: 600 }}>Subnet Pair Breakdown</div>
            }
            filterPlaceholder="Filter by subnet..."
            emptyMessage="No Results"
          />
        </section>

        <section
          style={{ display: "flex", flexDirection: "column", gap: "8px" }}
        >
          <SortableTable
            columns={
              [
                {
                  key: "dst_subnet",
                  label: "Destination Subnet",
                  sortable: true,
                },
                {
                  key: "count",
                  label: "Count",
                  sortable: true,
                  align: "right",
                },
              ] satisfies Column[]
            }
            data={payload.dst_subnet_counts}
            filterable={true}
            filterHeader={
              <div style={{ fontWeight: 600 }}>
                Destination Subnet Breakdown
              </div>
            }
            filterPlaceholder="Filter by destination subnet..."
            emptyMessage="No Results"
          />
        </section>

        <section
          style={{ display: "flex", flexDirection: "column", gap: "8px" }}
        >
          <SortableTable
            columns={
              [
                {
                  key: "src_device_ip",
                  label: "OT Device IP",
                  sortable: true,
                  render: (value) =>
                    value && onFilter ? (
                      <PivotValue
                        filter={{
                          key: "ip",
                          value: String(value),
                          label: "Device",
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
                {
                  key: "count",
                  label: "Cross-Segment Flow Count",
                  sortable: true,
                  align: "right",
                },
              ] satisfies Column[]
            }
            data={payload.ot_device_counts}
            onRowClick={(row) => {
              if (row.src_device_ip)
                onSelect?.({ type: "device", id: row.src_device_ip });
            }}
            filterable={true}
            filterHeader={
              <div style={{ fontWeight: 600 }}>Per-OT Device Flow Count</div>
            }
            filterPlaceholder="Filter by OT device..."
            emptyMessage="No Results"
          />
        </section>

        <section
          style={{ display: "flex", flexDirection: "column", gap: "8px" }}
        >
          <SortableTable<unknown, OTActivityCrossSegmentLine>
            columns={
              [
                {
                  key: "src_endpoint.ip",
                  label: "Source IP",
                  sortable: true,
                  render: (value: unknown) => {
                    const ip = formatIpForDisplay(
                      typeof value === "string" ? value : null,
                    );
                    return ip !== "Unknown" && onFilter ? (
                      <PivotValue
                        filter={{ key: "ip", value: ip, label: "Device" }}
                        filters={filters}
                        onFilter={onFilter}
                      >
                        {ip}
                      </PivotValue>
                    ) : (
                      ip
                    );
                  },
                },
                {
                  key: "dst_endpoint.ip",
                  label: "Destination",
                  sortable: true,
                  render: (
                    _value: unknown,
                    row: OTActivityCrossSegmentLine,
                  ) => {
                    const destinationIp = formatIpForDisplay(
                      typeof row["dst_endpoint.ip"] === "string"
                        ? row["dst_endpoint.ip"]
                        : null,
                    );
                    const destinationPort =
                      row["dst_endpoint.port"] ?? "Unknown";

                    return (
                      <span>
                        {destinationIp !== "Unknown" && onFilter ? (
                          <PivotValue
                            filter={{
                              key: "ip",
                              value: destinationIp,
                              label: "Device",
                            }}
                            filters={filters}
                            onFilter={onFilter}
                          >
                            {destinationIp}
                          </PivotValue>
                        ) : (
                          destinationIp
                        )}
                        :
                        {destinationPort != null && onFilter ? (
                          <PivotValue
                            filter={{
                              key: "port",
                              value: String(destinationPort),
                              label: "Port",
                            }}
                            filters={filters}
                            onFilter={onFilter}
                          >
                            {String(destinationPort)}
                          </PivotValue>
                        ) : (
                          String(destinationPort)
                        )}
                      </span>
                    );
                  },
                },
                {
                  key: "service.name",
                  label: "Service",
                  sortable: true,
                  render: (value) =>
                    value && onFilter ? (
                      <PivotValue
                        filter={{
                          key: "service",
                          value: String(value),
                          label: "Service",
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
                {
                  key: "count",
                  label: "Count",
                  sortable: true,
                  align: "right",
                },
              ] satisfies Column<unknown, OTActivityCrossSegmentLine>[]
            }
            data={payload.lines}
            onRowClick={(row) => {
              const src = row["src_endpoint.ip"];
              const dst = row["dst_endpoint.ip"];
              const service =
                row["service.name"] ||
                `Port ${row["dst_endpoint.port"] ?? "—"}`;
              if (src && dst)
                onSelect?.({
                  type: "connection",
                  id: `${src}|${dst}|${service}`,
                });
            }}
            filterable={true}
            filterHeader={
              <div style={{ fontWeight: 600 }}>Communications (All)</div>
            }
            filterPlaceholder="Filter by IP/service..."
            emptyMessage="No Results"
          />
        </section>
      </div>
      <DetailModal
        isOpen={Boolean(drilldown.selectedKey)}
        title={
          drilldown.selectedKey
            ? `Cross-Segment Details: ${drilldown.selectedKey.src_subnet} → ${drilldown.selectedKey.dst_subnet}`
            : "Cross-Segment Details"
        }
        onClose={closeModal}
      >
        {drilldown.isLoading && (
          <p>Loading cross-segment connection details...</p>
        )}
        {drilldown.error && <p>{drilldown.error}</p>}
        {!drilldown.isLoading && !drilldown.error && (
          <SortableTable
            columns={[
              {
                key: "src_endpoint.ip",
                label: "Source IP",
                sortable: true,
                render: (value) =>
                  value && onFilter ? (
                    <PivotValue
                      filter={{
                        key: "ip",
                        value: String(value),
                        label: "Device",
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
              {
                key: "src_endpoint.subnet",
                label: "Source Subnet",
                sortable: true,
                render: (value) =>
                  value && onFilter ? (
                    <PivotValue
                      filter={{
                        key: "subnet",
                        value: String(value),
                        label: "Subnet",
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
              {
                key: "src_endpoint.port",
                label: "Src Port",
                sortable: true,
                align: "right",
                render: (value) =>
                  value != null && onFilter ? (
                    <PivotValue
                      filter={{
                        key: "port",
                        value: String(value),
                        label: "Port",
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
              {
                key: "dst_endpoint.ip",
                label: "Destination IP",
                sortable: true,
                render: (value) =>
                  value && onFilter ? (
                    <PivotValue
                      filter={{
                        key: "ip",
                        value: String(value),
                        label: "Device",
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
              {
                key: "dst_endpoint.subnet",
                label: "Destination Subnet",
                sortable: true,
                render: (value) =>
                  value && onFilter ? (
                    <PivotValue
                      filter={{
                        key: "subnet",
                        value: String(value),
                        label: "Subnet",
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
              {
                key: "dst_endpoint.port",
                label: "Dst Port",
                sortable: true,
                align: "right",
                render: (value) =>
                  value != null && onFilter ? (
                    <PivotValue
                      filter={{
                        key: "port",
                        value: String(value),
                        label: "Port",
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
              {
                key: "service.name",
                label: "Service",
                sortable: true,
                render: (value) =>
                  value && onFilter ? (
                    <PivotValue
                      filter={{
                        key: "service",
                        value: String(value),
                        label: "Service",
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
            filterPlaceholder="Search cross-segment connection details..."
            emptyMessage="No matching cross-segment connections found"
          />
        )}
      </DetailModal>
    </Panel>
  );
};

export default OTCrossSegmentPanel;
