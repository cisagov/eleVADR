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

interface OTCrossSegmentPanelProps {
  data?: OTcrossSegmentLinesPanel | null;
  reportId: ElevadrReport["report_id"];
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
          <div style={{ fontWeight: 600 }}>Subnet Pair Breakdown</div>
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
            filterPlaceholder="Filter by subnet..."
            emptyMessage="No Results"
          />
        </section>

        <section
          style={{ display: "flex", flexDirection: "column", gap: "8px" }}
        >
          <div style={{ fontWeight: 600 }}>Destination Subnet Breakdown</div>
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
            filterPlaceholder="Filter by destination subnet..."
            emptyMessage="No Results"
          />
        </section>

        <section
          style={{ display: "flex", flexDirection: "column", gap: "8px" }}
        >
          <div style={{ fontWeight: 600 }}>Per-OT Device Flow Count</div>
          <SortableTable
            columns={
              [
                { key: "src_device_ip", label: "OT Device IP", sortable: true },
                {
                  key: "count",
                  label: "Cross-Segment Flow Count",
                  sortable: true,
                  align: "right",
                },
              ] satisfies Column[]
            }
            data={payload.ot_device_counts}
            filterable={true}
            filterPlaceholder="Filter by OT device..."
            emptyMessage="No Results"
          />
        </section>

        <section
          style={{ display: "flex", flexDirection: "column", gap: "8px" }}
        >
          <div style={{ fontWeight: 600 }}>Communications (All)</div>
          <SortableTable<unknown, OTActivityCrossSegmentLine>
            columns={
              [
                {
                  key: "src_endpoint.ip",
                  label: "Source IP",
                  sortable: true,
                  render: (value: unknown) =>
                    formatIpForDisplay(
                      typeof value === "string" ? value : null,
                    ),
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

                    return <span>{`${destinationIp}:${destinationPort}`}</span>;
                  },
                },
                { key: "service.name", label: "Service", sortable: true },
                {
                  key: "count",
                  label: "Count",
                  sortable: true,
                  align: "right",
                },
              ] satisfies Column<unknown, OTActivityCrossSegmentLine>[]
            }
            data={payload.lines}
            filterable={true}
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
              { key: "src_endpoint.ip", label: "Source IP", sortable: true },
              {
                key: "src_endpoint.subnet",
                label: "Source Subnet",
                sortable: true,
              },
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
                key: "dst_endpoint.subnet",
                label: "Destination Subnet",
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
