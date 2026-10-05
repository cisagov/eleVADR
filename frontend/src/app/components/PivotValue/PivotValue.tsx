import React from "react";
import { InvestigationFilter } from "../../types/Investigation";
import "./PivotValue.css";

interface Props {
  filter: InvestigationFilter;
  filters?: InvestigationFilter[];
  onFilter: (filter: InvestigationFilter) => void;
  children?: React.ReactNode;
  className?: string;
  stopPropagation?: boolean;
}

const PivotValue: React.FC<Props> = ({
  filter,
  filters = [],
  onFilter,
  children,
  className = "",
  stopPropagation = true,
}) => {
  const active = filters.some((item) => item.key === filter.key && item.value === filter.value);
  const action = active ? "Remove report filter" : `Filter report by this ${filter.label.toLowerCase()}`;

  return (
    <span
      className={`pivot-value${active ? " pivot-value-active" : ""}${className ? ` ${className}` : ""}`}
      data-pivot-key={filter.key}
    >
      <span className="pivot-value-label">{children ?? filter.value}</span>
      <button
        type="button"
        className="pivot-value-icon"
        onClick={(event) => {
          if (stopPropagation) event.stopPropagation();
          onFilter(filter);
        }}
        aria-pressed={active}
        aria-label={`${action}: ${filter.value}`}
        title={`${action}: ${filter.value}`}
      >
        <svg viewBox="0 0 16 16" focusable="false" aria-hidden="true">
          <path d="M2.2 3h11.6L9.4 8.1v3.6l-2.8 1.4v-5L2.2 3Z" />
        </svg>
      </button>
    </span>
  );
};

export default PivotValue;
