import React, { useMemo, useState } from "react";
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
  filterHeader?: React.ReactNode;
  emptyMessage?: string;
  onRowClick?: (row: R) => void;
}

type SortDirection = "asc" | "desc" | null;

const SortableTable = <T = unknown, R extends object = object>({
  columns,
  data,
  filterable = false,
  filterPlaceholder = "Filter table...",
  filterHeader,
  emptyMessage = "No data available",
  onRowClick,
}: SortableTableProps<T, R>) => {
  const [sortColumn, setSortColumn] = useState<string | null>(null);
  const [sortDirection, setSortDirection] = useState<SortDirection>(null);
  const [filter, setFilter] = useState("");
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(50);
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

  const pageCount = Math.max(1, Math.ceil(filteredAndSortedData.length / pageSize));
  const safePage = Math.min(page, pageCount - 1);
  const visibleData = filteredAndSortedData.slice(safePage * pageSize, safePage * pageSize + pageSize);

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
        filterHeader ? (
          <div className="table-filter-header">
            <div className="table-filter-header-title">{filterHeader}</div>
            <label className="table-filter-inline">
              <span>Filter:</span>
              <input
                className="usa-input"
                type="text"
                placeholder={filterPlaceholder}
                value={filter}
                onChange={(e) => { setFilter(e.target.value); setPage(0); }}
              />
            </label>
          </div>
        ) : (
          <div className="table-filter-section">
            <label className="usa-label">
              Filter:
            </label>
            <input
              className="usa-input"
              type="text"
              placeholder={filterPlaceholder}
              value={filter}
              onChange={(e) => { setFilter(e.target.value); setPage(0); }}
            />
          </div>
        )
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
              visibleData.map((row, idx) => (
                <tr
                  key={idx}
                  className={onRowClick ? "clickable-row" : ""}
                  onClick={() => onRowClick?.(row)}
                  tabIndex={onRowClick ? 0 : undefined}
                  role={onRowClick ? "button" : undefined}
                  onKeyDown={(event) => {
                    if (!onRowClick) return;
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      onRowClick(row);
                    }
                  }}
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

      {filteredAndSortedData.length > 0 && (
        <div className="table-summary table-pagination">
          <span>Showing {safePage * pageSize + 1}–{Math.min((safePage + 1) * pageSize, filteredAndSortedData.length)} of {filteredAndSortedData.length}{filterable && filteredAndSortedData.length !== data.length ? ` matching (${data.length} total)` : ""}</span>
          <div className="table-pagination-controls">
            <label>Rows <select value={pageSize} onChange={(e) => { setPageSize(Number(e.target.value)); setPage(0); }}><option value={25}>25</option><option value={50}>50</option><option value={100}>100</option></select></label>
            <button type="button" disabled={safePage === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>Previous</button>
            <span>Page {safePage + 1} of {pageCount}</span>
            <button type="button" disabled={safePage >= pageCount - 1} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>Next</button>
          </div>
        </div>
      )}
    </div>
  );
};

export default SortableTable;
