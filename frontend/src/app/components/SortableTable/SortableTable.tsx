import React, { useState, useMemo } from "react";
import "./SortableTable.css";
import { getNestedValue, toFilterableString } from "../../utils/tableUtils";

export interface Column<T = unknown, R extends object = object> {
  key: string;
  label: string | React.ReactNode;
  sortable?: boolean;
  align?: "left" | "center" | "right";
  render?: (value: T, row: R) => React.ReactNode;
  onClick?: (value: T, row: R) => void;
  clickable?: boolean;
}

interface SortableTableProps<T = unknown, R extends object = object> {
  columns: Column<T, R>[];
  data: R[];
  filterable?: boolean;
  filterPlaceholder?: string;
  emptyMessage?: string;
  onRowClick?: (row: R) => void;
}

type SortDirection = "asc" | "desc" | null;

const SortableTable = <T = unknown, R extends object = object>({
  columns,
  data,
  filterable = false,
  filterPlaceholder = "Filter table...",
  emptyMessage = "No data available",
  onRowClick,
}: SortableTableProps<T, R>) => {
  const [sortColumn, setSortColumn] = useState<string | null>(null);
  const [sortDirection, setSortDirection] = useState<SortDirection>(null);
  const [filter, setFilter] = useState("");

  const handleSort = (columnKey: string) => {
    if (sortColumn === columnKey) {
      if (sortDirection === "asc") {
        setSortDirection("desc");
      } else if (sortDirection === "desc") {
        setSortColumn(null);
        setSortDirection(null);
      } else {
        setSortDirection("asc");
      }
    } else {
      setSortColumn(columnKey);
      setSortDirection("asc");
    }
  };

  const filteredAndSortedData = useMemo(() => {
    let result = [...data];

    // Apply filter
    if (filter && filterable) {
      const searchText = filter.toLowerCase();
      result = result.filter((row) =>
        columns.some((col) => {
          const value = getNestedValue(row, col.key) as T;
          return toFilterableString(value).toLowerCase().includes(searchText);
        }),
      );
    }

    // Apply sort
    if (sortColumn && sortDirection) {
      result.sort((a, b) => {
        const aVal = getNestedValue(a, sortColumn) as T;
        const bVal = getNestedValue(b, sortColumn) as T;

        // Handle numeric sorting
        if (typeof aVal === "number" && typeof bVal === "number") {
          return sortDirection === "asc" ? aVal - bVal : bVal - aVal;
        }

        // Handle string sorting
        const aStr = String(aVal || "").toLowerCase();
        const bStr = String(bVal || "").toLowerCase();

        if (sortDirection === "asc") {
          return aStr.localeCompare(bStr);
        } else {
          return bStr.localeCompare(aStr);
        }
      });
    }

    return result;
  }, [data, filter, sortColumn, sortDirection, columns, filterable]);

  const getSortIcon = (columnKey: string) => {
    if (sortColumn !== columnKey) {
      return <span className="sort-icon">↕</span>;
    }
    if (sortDirection === "asc") {
      return <span className="sort-icon active">↑</span>;
    }
    return <span className="sort-icon active">↓</span>;
  };

  return (
    <div className="sortable-table-wrapper">
      {filterable && (
        <div className="table-filter-section">
          <label htmlFor="table-filter" className="usa-label">
            Filter:
          </label>
          <input
            id="table-filter"
            className="usa-input"
            type="text"
            placeholder={filterPlaceholder}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
      )}

      <div className="scrollable-table-container">
        <table className="usa-table usa-table--striped usa-table--sortable">
          <thead>
            <tr>
              {columns.map((col) => (
                <th
                  key={col.key}
                  scope="col"
                  className={col.sortable !== false ? "sortable" : ""}
                  style={{ textAlign: col.align || "left" }}
                  onClick={() => col.sortable !== false && handleSort(col.key)}
                  role={col.sortable !== false ? "button" : undefined}
                  aria-sort={
                    sortColumn === col.key
                      ? sortDirection === "asc"
                        ? "ascending"
                        : "descending"
                      : undefined
                  }
                >
                  <span className="th-content">
                    {col.label}
                    {col.sortable !== false && getSortIcon(col.key)}
                  </span>
                </th>
              ))}
            </tr>
          </thead>

          <tbody>
            {filteredAndSortedData.length > 0 ? (
              filteredAndSortedData.map((row, idx) => (
                <tr
                  key={idx}
                  className={onRowClick ? "clickable-row" : ""}
                  onClick={() => onRowClick?.(row)}
                >
                  {columns.map((col) => {
                    const cellValue = getNestedValue(row, col.key) as T;
                    const isClickableCell = Boolean(
                      col.onClick || col.clickable,
                    );

                    return (
                      <td
                        key={col.key}
                        style={{ textAlign: col.align || "left" }}
                        className={isClickableCell ? "clickable-cell" : ""}
                        onClick={(event) => {
                          if (col.onClick) {
                            event.stopPropagation();
                            col.onClick(cellValue, row);
                          }
                        }}
                      >
                        {col.render
                          ? col.render(cellValue, row)
                          : String(cellValue ?? "")}
                      </td>
                    );
                  })}
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={columns.length} className="empty-cell">
                  {filter ? `No results match "${filter}"` : emptyMessage}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {filterable && filteredAndSortedData.length > 0 && (
        <div className="table-summary">
          Showing {filteredAndSortedData.length} of {data.length} rows
        </div>
      )}
    </div>
  );
};

export default SortableTable;
