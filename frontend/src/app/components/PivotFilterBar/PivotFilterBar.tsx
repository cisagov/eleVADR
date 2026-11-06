import React from "react";
import "./PivotFilterBar.css";
import { DrilldownFilters } from "../../hooks/usePivotDrilldown";

interface PivotFilterBarProps {
  filters: DrilldownFilters | null;
  onRemoveFilter?: (key: string) => void;
}

const formatValue = (value: string | number | boolean | null | undefined) => {
  if (value === null || value === undefined || value === "") {
    return "Any";
  }
  return String(value);
};

const PivotFilterBar: React.FC<PivotFilterBarProps> = ({
  filters,
  onRemoveFilter,
}) => {
  if (!filters || Object.keys(filters).length === 0) {
    return null;
  }

  return (
    <div className="pivot-filter-bar">
      <div className="pivot-filter-label">Active Filters</div>
      <div className="pivot-filter-chips">
        {Object.entries(filters).map(([key, value]) => (
          <span key={key} className="pivot-filter-chip">
            <strong>{key}:</strong> {formatValue(value)}
            {onRemoveFilter && (
              <button
                type="button"
                className="pivot-filter-chip-remove"
                onClick={() => onRemoveFilter(key)}
                aria-label={`Remove filter ${key}`}
              >
                ×
              </button>
            )}
          </span>
        ))}
      </div>
    </div>
  );
};

export default PivotFilterBar;
