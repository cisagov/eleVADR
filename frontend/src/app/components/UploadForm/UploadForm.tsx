import React, {
  useState,
  FormEvent,
  useRef,
  SetStateAction,
  Dispatch,
} from "react";
import { ElevadrReport } from "../../types/Report";
import "./UploadForm.css";

const BACKEND_HTTP = "http://localhost:8000";
const BACKEND_WS = "ws://localhost:8000";

interface ProgressEvent {
  stage: string;
  progress: number;
  message: string;
}

interface UploadFormProps {
  onReportLoaded: (report: ElevadrReport) => void;
  report: ElevadrReport | null; // New prop to check if a report is loaded
  onDownloadJson: () => void; // New prop for the download action
  isAnalyzing: boolean;
  setIsAnalyzing?: Dispatch<SetStateAction<boolean>>;
}

const UploadForm: React.FC<UploadFormProps> = ({
  onReportLoaded,
  report,
  onDownloadJson,
  isAnalyzing,
  setIsAnalyzing,
}) => {
  const [file, setFile] = useState<File | null>(null);
  const [jsonFile, setJsonFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<ProgressEvent | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // -----------------------------------------------------------------
  // PCAP upload handling (existing functionality)
  // -----------------------------------------------------------------
  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    setProgress(null);

    if (!file) {
      setError("Please select a PCAP file to upload.");
      return;
    }

    setIsAnalyzing?.(true);

    // Generate a session ID for the WebSocket/analysis correlation
    const sessionId = crypto.randomUUID();

    // Open WebSocket before POST to avoid missing any progress events
    const ws = new WebSocket(`${BACKEND_WS}/ws/progress/${sessionId}`);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data) as ProgressEvent;
      setProgress(data);
    };

    ws.onerror = () => {
      console.warn(
        "Progress WebSocket error - continuing without progress updates",
      );
    };

    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch(
        `${BACKEND_HTTP}/analyze?session_id=${sessionId}`,
        {
          method: "POST",
          body: formData,
        },
      );

      if (!response.ok) {
        const text = await response.text();
        throw new Error(
          text || `Analysis failed with status ${response.status}`,
        );
      }

      const data = (await response.json()) as ElevadrReport;

      if (!data.executive_summary || !data.modules) {
        throw new Error("Invalid report format returned from backend.");
      }

      onReportLoaded(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run analysis");
    } finally {
      setIsAnalyzing?.(false);
      wsRef.current?.close();
      wsRef.current = null;
    }
  };

  const isElevadrReport = (value: unknown): value is ElevadrReport => {
    if (typeof value !== "object" || value === null) {
      return false;
    }

    const candidate = value as Partial<ElevadrReport>;
    return Boolean(candidate.executive_summary && candidate.modules);
  };

  const handleJsonUpload = async (
    e: FormEvent<HTMLFormElement>,
  ): Promise<void> => {
    e.preventDefault();
    setError(null);

    if (!jsonFile) {
      setError("Please select a JSON report to upload.");
      return;
    }

    try {
      const contents = await jsonFile.text();
      const parsed: unknown = JSON.parse(contents);

      if (!isElevadrReport(parsed)) {
        throw new Error("Invalid JSON report format.");
      }

      onReportLoaded(parsed);
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "Failed to load JSON report",
      );
    }
  };

  return (
    <div className="upload-container">
      {/* PCAP upload form */}
      <form onSubmit={handleSubmit} className="upload-form">
        <label htmlFor="pcap-upload" className="upload-label">
          Upload PCAP for Analysis
        </label>
        <input
          id="pcap-upload"
          type="file"
          accept=".pcap,.pcapng"
          onChange={(e) => setFile(e.target.files?.[0] || null)}
        />
        <div className="form-actions">
          <button type="submit" disabled={!file || isAnalyzing}>
            {isAnalyzing ? "Analyzing..." : "Run Analysis"}
          </button>
          <button
            type="button"
            onClick={onDownloadJson}
            disabled={!report || isAnalyzing}
            className="download-button"
          >
            Download JSON Report
          </button>
        </div>
      </form>

      {/* JSON report upload */}
      <form
        onSubmit={handleJsonUpload}
        className="upload-form json-upload-form"
      >
        <label htmlFor="json-upload" className="upload-label">
          Upload JSON Report
        </label>
        <input
          id="json-upload"
          type="file"
          accept=".json,application/json"
          onChange={(e) => setJsonFile(e.target.files?.[0] || null)}
        />
        <div className="form-actions">
          <button type="submit" disabled={!jsonFile || isAnalyzing}>
            Load JSON Report
          </button>
        </div>
      </form>

      {/* Progress bar (shown only during PCAP analysis) */}
      {isAnalyzing && (
        <div className="upload-status">
          <p className="loading-text">
            {progress?.message ?? "Starting analysis..."}
          </p>
          <div className="progress-bar-track">
            <div
              className="progress-bar-fill"
              style={{ width: `${progress?.progress ?? 0}%` }}
            />
          </div>
          <p className="progress-percent">{progress?.progress ?? 0}%</p>
        </div>
      )}

      {/* Error handling */}
      {error && (
        <div className="error-container">
          <p className="error-text">Error during analysis</p>
          <p className="error-details">{error}</p>
        </div>
      )}
    </div>
  );
};

export default UploadForm;
