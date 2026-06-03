import React from "react";
import "./OTServices.css";
import Panel from "../Panel/Panel";
import SortableTable, { Column } from "../SortableTable/SortableTable";
import { OTService, ServiceConnectionDetail } from "../../types/Report";
import InfoTooltip from "../InfoTooltip/InfoTooltip";
import DetailModal from "../DetailModal/DetailModal";
import { usePivotDrilldown } from "../../hooks/usePivotDrilldown";
import {
  fetchFilteredConnections,
  fetchFilteredServices,
} from "../../services/drilldownService";
import DrilldownTable, {
  buildOtServiceRows,
  connectionDetailColumns,
  OtServiceRow,
} from "../DrilldownTable/DrilldownTable";
import PivotFilterBar from "../PivotFilterBar/PivotFilterBar";

interface OTServicesProps {
  data: OTService[];
  reportId: string;
}

const buildConnectionPivotColumns = (
  onPivot: (
    filters: Record<string, string | number | boolean | null | undefined>,
  ) => void,
): Column<unknown, ServiceConnectionDetail>[] => [
  {
    ...connectionDetailColumns[0],
    clickable: true,
    onClick: (value) => {
      if (value) onPivot({ src_ip: String(value) });
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "")}
      </button>
    ),
  },
  {
    ...connectionDetailColumns[1],
    clickable: true,
    onClick: (value) => {
      if (value) onPivot({ src_subnet: String(value) });
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "")}
      </button>
    ),
  },
  {
    ...connectionDetailColumns[2],
    clickable: true,
    onClick: (_value, row: ServiceConnectionDetail) => {
      const manufacturer = row["src_device.manufacturer"];
      if (manufacturer) onPivot({ manufacturer: String(manufacturer) });
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "Unknown")}
      </button>
    ),
  },
  connectionDetailColumns[3],
  {
    ...connectionDetailColumns[4],
    clickable: true,
    onClick: (value) => {
      if (value) onPivot({ dst_ip: String(value) });
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "")}
      </button>
    ),
  },
  {
    ...connectionDetailColumns[5],
    clickable: true,
    onClick: (value) => {
      if (value) onPivot({ dst_subnet: String(value) });
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "")}
      </button>
    ),
  },
  {
    ...connectionDetailColumns[6],
    clickable: true,
    onClick: (_value, row: ServiceConnectionDetail) => {
      const manufacturer = row["dst_device.manufacturer"];
      if (manufacturer) onPivot({ manufacturer: String(manufacturer) });
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "Unknown")}
      </button>
    ),
  },
  connectionDetailColumns[7],
  {
    ...connectionDetailColumns[8],
    clickable: true,
    onClick: (value) => {
      if (value) onPivot({ service_name: String(value) });
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "")}
      </button>
    ),
  },
  connectionDetailColumns[9],
  {
    ...connectionDetailColumns[10],
    clickable: true,
    onClick: (value) => {
      if (value) onPivot({ direction: String(value) });
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "")}
      </button>
    ),
  },
  {
    ...connectionDetailColumns[11],
    clickable: true,
    onClick: (value) => {
      if (value) onPivot({ connection_state: String(value) });
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "")}
      </button>
    ),
  },
  connectionDetailColumns[12],
];

const OTServices: React.FC<OTServicesProps> = ({ data, reportId }) => {
  const servicesDrilldown = usePivotDrilldown(
    (filters: Record<string, string | number | boolean | null | undefined>) =>
      fetchFilteredServices(reportId, filters),
  );
  const connectionsDrilldown = usePivotDrilldown(
    (filters: Record<string, string | number | boolean | null | undefined>) =>
      fetchFilteredConnections(reportId, filters),
  );
  const tableData = buildOtServiceRows(data);

  const openServiceConnections = async (serviceName: string) => {
    await connectionsDrilldown.open({ service_name: serviceName, limit: 500 });
  };

  const openRiskCategoryServices = async (riskCategory: string) => {
    await servicesDrilldown.open({ risk_category: riskCategory });
  };

  const columns: Column<unknown, OtServiceRow>[] = [
    {
      key: "name",
      label: (
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span>Service Name</span>
          <InfoTooltip text="The name of the detected OT service." />
        </div>
      ),
      sortable: true,
      clickable: true,
      onClick: (value) => openServiceConnections(String(value)),
      render: (value) => (
        <button
          type="button"
          className="clickable-service-link service-name-cell clickable-cell-text"
        >
          {String(value ?? "")}
        </button>
      ),
    },
    {
      key: "description",
      label: (
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span>Description</span>
          <InfoTooltip text="A brief description of the OT service and its function." />
        </div>
      ),
      sortable: true,
      render: (value) => (
        <span className="description-cell">{String(value ?? "")}</span>
      ),
    },
    {
      key: "informationCategories",
      label: (
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span>Information Categories</span>
          <InfoTooltip text="Categories of information associated with the service, such as configuration or operational data." />
        </div>
      ),
      sortable: true,
      render: (value) => (
        <span className="category-cell">{String(value ?? "")}</span>
      ),
    },
    {
      key: "riskCategories",
      label: (
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span>Risk Categories</span>
          <InfoTooltip text="Potential risk categories associated with the service, if any." />
        </div>
      ),
      sortable: true,
      clickable: true,
      render: (_value, row) => {
        const riskCategories = Array.isArray(row.riskCategoryList)
          ? row.riskCategoryList
          : [];
        if (riskCategories.length === 0) {
          return <span className="no-risk">None</span>;
        }
        return (
          <span
            className="category-cell"
            style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}
          >
            {riskCategories.map((category: string) => (
              <button
                key={category}
                type="button"
                className="clickable-service-link clickable-cell-text"
                onClick={(event) => {
                  event.stopPropagation();
                  void openRiskCategoryServices(category);
                }}
              >
                {category}
              </button>
            ))}
          </span>
        );
      },
    },
  ];

  const connectionColumns = buildConnectionPivotColumns((filters) => {
    void connectionsDrilldown.pivot(filters);
  });

  const isEmpty = tableData.length === 0;

  return (
    <Panel
      id="ot-services-panel"
      title={
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span>OT Services</span>
          <InfoTooltip text="Industrial protocols and OT-specific services detected with security descriptions and risk assessments. Click services, risk categories, or drilldown rows to continue pivoting." />
        </div>
      }
      isEmpty={isEmpty}
    >
      <SortableTable
        columns={columns}
        data={tableData}
        filterable={true}
        filterPlaceholder="Search by name, description, or category..."
        emptyMessage="No Results"
      />

      <DetailModal
        isOpen={Boolean(connectionsDrilldown.selectedFilters)}
        title="Service Connection Details"
        onClose={connectionsDrilldown.close}
      >
        {connectionsDrilldown.isLoading && (
          <p>Loading service connections...</p>
        )}
        {connectionsDrilldown.error && <p>{connectionsDrilldown.error}</p>}
        {!connectionsDrilldown.isLoading && !connectionsDrilldown.error && (
          <>
            <PivotFilterBar
              filters={connectionsDrilldown.selectedFilters}
              onRemoveFilter={(key) => {
                void connectionsDrilldown.removeFilter(key);
              }}
            />
            <DrilldownTable
              columns={connectionColumns}
              data={connectionsDrilldown.data?.connections || []}
              filterPlaceholder="Search connection details..."
              emptyMessage="No matching connections found"
            />
          </>
        )}
      </DetailModal>

      <DetailModal
        isOpen={Boolean(servicesDrilldown.selectedFilters)}
        title="Filtered OT Services"
        onClose={servicesDrilldown.close}
      >
        {servicesDrilldown.isLoading && <p>Loading services...</p>}
        {servicesDrilldown.error && <p>{servicesDrilldown.error}</p>}
        {!servicesDrilldown.isLoading && !servicesDrilldown.error && (
          <>
            <PivotFilterBar
              filters={servicesDrilldown.selectedFilters}
              onRemoveFilter={(key) => {
                void servicesDrilldown.removeFilter(key);
              }}
            />
            <DrilldownTable
              columns={columns}
              data={buildOtServiceRows(servicesDrilldown.data?.services || [])}
              filterPlaceholder="Search filtered services..."
              emptyMessage="No matching services found"
            />
          </>
        )}
      </DetailModal>
    </Panel>
  );
};

export default OTServices;
