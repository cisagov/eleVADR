import React, { useEffect, useState } from "react";
import "./Panel.css";

interface PanelProps {
  title: React.ReactNode;
  children: React.ReactNode;
  highlight?: boolean;
  isEmpty?: boolean;
  id?: string;
  emptyMessage?: React.ReactNode;
  headerAction?: React.ReactNode;
}

const Panel: React.FC<PanelProps> = ({
  title,
  children,
  highlight = false,
  isEmpty = false,
  id,
  emptyMessage = "No Results",
  headerAction,
}) => {
  const [isExpanded, setIsExpanded] = useState(true); // All report sections start expanded

  useEffect(() => {
    const handleExpandCollapseAll = (event: Event) => {
      const customEvent = event as CustomEvent<{ expanded: boolean }>;
      setIsExpanded(customEvent.detail.expanded);
    };
    window.addEventListener("elevadr:set-all-panels-expanded", handleExpandCollapseAll);
    return () => window.removeEventListener("elevadr:set-all-panels-expanded", handleExpandCollapseAll);
  }, []);

  // Effect to update expanded state if isEmpty prop changes
  // useEffect(() => {
  //   setIsExpanded(!isEmpty);
  // }, [isEmpty]);

  const toggleExpand = () => {
    setIsExpanded((expanded) => {
      const next = !expanded;
      window.setTimeout(() => window.dispatchEvent(new CustomEvent("elevadr:panel-state-changed")), 0);
      return next;
    });
  };

  return (
    <div
      id={id}
      className={`panel ${highlight ? "panel-highlight" : ""} ${!isExpanded ? "panel-collapsed" : ""}`}
    >
      {" "}
      {/* Apply id here */}
      <div className="panel-header">
        <h2 className="panel-title">{title}</h2>
        {headerAction && <div className="panel-header-action">{headerAction}</div>}
        <button
          onClick={toggleExpand}
          className="panel-toggle-button"
          aria-expanded={isExpanded}
        >
          {isExpanded ? "−" : "+"}
        </button>
      </div>
      {isExpanded && (
        <div className="panel-content">{isEmpty ? emptyMessage : children}</div>
      )}
    </div>
  );
};

export default Panel;
