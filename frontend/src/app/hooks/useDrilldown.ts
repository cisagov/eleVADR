import { useState } from "react";

export interface UseDrilldownResult<TData, TKey> {
  selectedKey: TKey | null;
  data: TData | null;
  isLoading: boolean;
  error: string | null;
  open: (key: TKey) => Promise<void>;
  close: () => void;
}

export function useDrilldown<TData, TKey = string>(
  fetcher: (key: TKey) => Promise<TData>,
): UseDrilldownResult<TData, TKey> {
  const [selectedKey, setSelectedKey] = useState<TKey | null>(null);
  const [data, setData] = useState<TData | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const open = async (key: TKey) => {
    setSelectedKey(key);
    setData(null);
    setError(null);
    setIsLoading(true);

    try {
      const result = await fetcher(key);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load drilldown");
    } finally {
      setIsLoading(false);
    }
  };

  const close = () => {
    setSelectedKey(null);
    setData(null);
    setError(null);
    setIsLoading(false);
  };

  return {
    selectedKey,
    data,
    isLoading,
    error,
    open,
    close,
  };
}
