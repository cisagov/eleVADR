import { useState } from "react";

export type FilterValue = string | number | boolean | null | undefined;
export type DrilldownFilters = Record<string, FilterValue>;

const mergeFilters = (
  baseFilters: DrilldownFilters | null,
  nextFilters: DrilldownFilters,
): DrilldownFilters =>
  Object.entries({
    ...(baseFilters || {}),
    ...nextFilters,
  }).reduce<DrilldownFilters>((acc, [key, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      acc[key] = value;
    }
    return acc;
  }, {});

interface UsePivotDrilldownResult<T> {
  selectedFilters: DrilldownFilters | null;
  data: T | null;
  isLoading: boolean;
  error: string | null;
  open: (filters: DrilldownFilters) => Promise<void>;
  pivot: (filters: DrilldownFilters) => Promise<void>;
  replace: (filters: DrilldownFilters) => Promise<void>;
  removeFilter: (key: string) => Promise<void>;
  clear: () => void;
  close: () => void;
}

export function usePivotDrilldown<T>(
  fetcher: (filters: DrilldownFilters) => Promise<T>,
): UsePivotDrilldownResult<T> {
  const [selectedFilters, setSelectedFilters] =
    useState<DrilldownFilters | null>(null);
  const [data, setData] = useState<T | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async (filters: DrilldownFilters) => {
    setSelectedFilters(filters);
    setIsLoading(true);
    setError(null);

    try {
      const result = await fetcher(filters);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load details");
      setData(null);
    } finally {
      setIsLoading(false);
    }
  };

  const open = async (filters: DrilldownFilters) => {
    await run(mergeFilters(null, filters));
  };

  const pivot = async (filters: DrilldownFilters) => {
    await run(mergeFilters(selectedFilters, filters));
  };

  const replace = async (filters: DrilldownFilters) => {
    await run(mergeFilters(null, filters));
  };

  const removeFilter = async (key: string) => {
    const nextFilters = Object.entries(
      selectedFilters || {},
    ).reduce<DrilldownFilters>((acc, [entryKey, value]) => {
      if (
        entryKey !== key &&
        value !== undefined &&
        value !== null &&
        value !== ""
      ) {
        acc[entryKey] = value;
      }
      return acc;
    }, {});

    if (Object.keys(nextFilters).length === 0) {
      setSelectedFilters(null);
      setData(null);
      setError(null);
      setIsLoading(false);
      return;
    }

    await run(nextFilters);
  };

  const clear = () => {
    setSelectedFilters(null);
    setData(null);
    setError(null);
    setIsLoading(false);
  };

  return {
    selectedFilters,
    data,
    isLoading,
    error,
    open,
    pivot,
    replace,
    removeFilter,
    clear,
    close: clear,
  };
}
