import React from "react";
import "./ErrorBoundary.css";

type State = { hasError: boolean; message: string };

class ErrorBoundary extends React.Component<React.PropsWithChildren, State> {
  state: State = { hasError: false, message: "" };

  static getDerivedStateFromError(error: Error): State {
    return {
      hasError: true,
      message: error.message || "Unexpected frontend error",
    };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("eleVADR frontend error", error, info);
  }

  render() {
    if (!this.state.hasError) return this.props.children;
    return (
      <main className="fatal-error" role="alert">
        <div>
          <span>eleVADR</span>
          <h1>The report viewer encountered an error.</h1>
          <p>{this.state.message}</p>
          <button type="button" onClick={() => window.location.reload()}>
            Reload viewer
          </button>
        </div>
      </main>
    );
  }
}
export default ErrorBoundary;
