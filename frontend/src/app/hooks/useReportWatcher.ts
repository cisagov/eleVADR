import { useState, useEffect } from "react";
import { ElevadrReport } from "../types/Report";

interface ReportState {
  report: ElevadrReport | null;
  loading: boolean;
  error: string | null;
}

export const useReportWatcher = (): ReportState => {
  const [state, setState] = useState<ReportState>({
    report: null,
    loading: true,
    error: null,
  });

  useEffect(() => {
    const loadReport = async () => {
      try {
        // In development, we'll load from the public folder
        // In production with container, this would watch the /input directory
        const response = await fetch("/input/report.json");

        if (!response.ok) {
          throw new Error("No report file found");
        }

        const data = await response.json();

        // Validate report structure
        if (!data.executive_summary || !data.modules) {
          throw new Error(
            "Invalid report format - please provide an eleVADR report file",
          );
        }

        setState({
          report: data as ElevadrReport,
          loading: false,
          error: null,
        });
      } catch (err) {
        setState({
          report: null,
          loading: false,
          error: err instanceof Error ? err.message : "Failed to load report",
        });
      }
    };

    loadReport();

    // Poll for changes every 5 seconds
    const interval = setInterval(loadReport, 5000);

    return () => clearInterval(interval);
  }, []);

  return state;
};
