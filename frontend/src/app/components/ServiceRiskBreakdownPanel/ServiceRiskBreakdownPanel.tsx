import React from "react";
import "./ServiceRiskBreakdownPanel.css";
import Panel from "../Panel/Panel";
import SortableTable, { Column } from "../SortableTable/SortableTable";
import {
  ElevadrReport,
  ServiceConnectionDetail,
  ServiceRiskBreakdownPanel as ServiceRiskBreakdownPanelType,
} from "../../types/Report";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import InfoTooltip from "../InfoTooltip/InfoTooltip";
import DetailModal from "../DetailModal/DetailModal";
import { useDrilldown } from "../../hooks/useDrilldown";
import { fetchServiceDrilldown } from "../../services/drilldownService";
import PivotValue from "../PivotValue/PivotValue";
import { InvestigationFilter } from "../../types/Investigation";

interface ServiceRiskBreakdownPanelProps {
  data: ServiceRiskBreakdownPanelType;
  reportId: ElevadrReport["report_id"];
  filters?: InvestigationFilter[];
  onFilter?: (filter: InvestigationFilter) => void;
}

/**
 * FIX: Moved CustomTooltip outside of the main component.
 * This prevents the component from being recreated on every render,
 * resolving the 'react-hooks/static-components' ESLint error.
 */
const CustomTooltip = ({
  active,
  payload,
  data,
  filters,
  onFilter,
}: {
  active?: boolean;
  payload?: {
    value?: string | number;
    payload: {
      category: string;
    };
  }[];
  data: ServiceRiskBreakdownPanelType;
  filters: InvestigationFilter[];
  onFilter?: (filter: InvestigationFilter) => void;
}) => {
  if (active && payload && payload.length) {
    const category = payload[0].payload.category;
    const services = data.risk_category_services[category] || [];

    return (
      <div className="risk-chart-tooltip">
        <p className="tooltip-title">{category}</p>
        <p className="tooltip-count">Count: {payload[0].value}</p>
        <div className="tooltip-services">
          <strong>Services:</strong>
          <ul>
            {services.map((service, idx) => (
              <li key={idx}>
                {onFilter ? (
                  <PivotValue
                    filter={{ key: "service", value: service, label: "Service" }}
                    filters={filters}
                    onFilter={onFilter}
                  >
                    {service}
                  </PivotValue>
                ) : service}
              </li>
            ))}
          </ul>
        </div>
      </div>
    );
  }
  return null;
};

const ServiceRiskBreakdownPanel: React.FC<ServiceRiskBreakdownPanelProps> = ({
  data,
  reportId,
  filters = [],
  onFilter,
}) => {
  const drilldown = useDrilldown((serviceName: string) =>
    fetchServiceDrilldown(reportId, serviceName),
  );

  const chartData = Object.entries(data.risk_category_counts).map(
    ([category, count]) => ({
      category,
      count,
    }),
  );

  const tableData = Object.entries(data.risk_category_services).flatMap(
    ([category, services]) =>
      services.map((service) => ({
        category,
        service,
      })),
  );

  const handleServiceClick = async (service: string) => {
    await drilldown.open(service);
  };

  const closeModal = () => {
    drilldown.close();
  };

  const tableColumns: Column<string>[] = [
    { key: "category", label: "Category", sortable: true },
    {
      key: "service",
      label: "Service",
      sortable: true,
      render: (value) => value && onFilter ? <PivotValue filter={{ key: "service", value: String(value), label: "Service" }} filters={filters} onFilter={onFilter}>{String(value)}</PivotValue> : String(value ?? ""),
    },
  ];

  const detailColumns: Column<
    string | number | boolean | string[] | null,
    ServiceConnectionDetail
  >[] = [
    { key: "src_endpoint.ip", label: "Source IP", sortable: true, render: (value) => value && onFilter ? <PivotValue filter={{ key: "ip", value: String(value), label: "Device" }} filters={filters} onFilter={onFilter}>{String(value)}</PivotValue> : String(value ?? "—") },
    { key: "src_endpoint.port", label: "Src Port", sortable: true, align: "right", render: (value) => value != null && onFilter ? <PivotValue filter={{ key: "port", value: String(value), label: "Port" }} filters={filters} onFilter={onFilter}>{String(value)}</PivotValue> : String(value ?? "—") },
    { key: "dst_endpoint.ip", label: "Destination IP", sortable: true, render: (value) => value && onFilter ? <PivotValue filter={{ key: "ip", value: String(value), label: "Device" }} filters={filters} onFilter={onFilter}>{String(value)}</PivotValue> : String(value ?? "—") },
    { key: "dst_endpoint.port", label: "Dst Port", sortable: true, align: "right", render: (value) => value != null && onFilter ? <PivotValue filter={{ key: "port", value: String(value), label: "Port" }} filters={filters} onFilter={onFilter}>{String(value)}</PivotValue> : String(value ?? "—") },
    { key: "connection_info.protocol_name", label: "Protocol", sortable: true },
    {
      key: "connection_info.direction_name",
      label: "Direction",
      sortable: true,
    },
    { key: "state", label: "State", sortable: true, render: (value) => value && onFilter ? <PivotValue filter={{ key: "zeekState", value: String(value), label: "Zeek State" }} filters={filters} onFilter={onFilter}>{String(value)}</PivotValue> : String(value ?? "—") },
    { key: "history", label: "History", sortable: true },
    {
      key: "success",
      label: "Success",
      sortable: true,
      render: (value) => (value ? "Yes" : "No"),
    },
  ];

  const isEmpty =
    Object.keys(data.risk_category_counts).length === 0 &&
    tableData.length === 0;

  return (
    <Panel
      id="service-risk-breakdown-panel"
      title={
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span>Service Risk Breakdown</span>
          <InfoTooltip text="Services categorized by risk type with detailed breakdowns of which services fall under each category." />
        </div>
      }
      isEmpty={isEmpty}
    >
      <div className="risk-breakdown-content">
        <div className="risk-chart-section">
          <h3 className="section-subtitle">
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span>Risk Category Counts</span>
              <InfoTooltip text="A visual representation of the number of services falling into each risk category." />
            </div>
          </h3>

          <ResponsiveContainer width="100%" height={300}>
            <BarChart
              data={chartData}
              layout="vertical"
              margin={{ top: 5, right: 30, left: 120, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis type="number" allowDecimals={false} />
              <YAxis
                type="category"
                dataKey="category"
                width={110}
                tick={{ fontSize: 12 }}
              />
              {/* FIX: Pass the data prop to the external CustomTooltip component */}
              <Tooltip content={<CustomTooltip data={data} filters={filters} onFilter={onFilter} />} />
              <Bar dataKey="count">
                {chartData.map((_, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={
                      ["#005ea2", "#0076d6", "#2491ff", "#73b3ff", "#a9d4ff"][
                        index % 5
                      ]
                    }
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="risk-table-section">
          <SortableTable<string, { category: string; service: string }>
            columns={tableColumns}
            data={tableData}
            filterable={true}
            filterHeader={
              <h3 className="section-subtitle">
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <span>Risk Category Services</span>
                  <InfoTooltip text="A detailed list of services grouped by their assigned risk category." />
                </div>
              </h3>
            }
            filterPlaceholder="Search by category or service..."
            emptyMessage="No Results"
          />
        </div>
      </div>

      <DetailModal
        isOpen={Boolean(drilldown.selectedKey)}
        title={
          drilldown.selectedKey
            ? `Service Details: ${drilldown.selectedKey}`
            : "Service Details"
        }
        onClose={closeModal}
      >
        {drilldown.isLoading && <p>Loading service connections...</p>}
        {drilldown.error && <p>{drilldown.error}</p>}
        {!drilldown.isLoading && !drilldown.error && (
          <SortableTable<
            string | number | boolean | string[] | null,
            ServiceConnectionDetail
          >
            columns={detailColumns}
            data={drilldown.data?.connections || []}
            filterable={true}
            filterPlaceholder="Search service connection details..."
            emptyMessage="No connections found for this service"
          />
        )}
      </DetailModal>
    </Panel>
  );
};

export default ServiceRiskBreakdownPanel;
