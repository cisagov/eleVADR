import React, { useState } from "react";
import "./Panel.css";

interface PanelProps {
  title: React.ReactNode;
  children: React.ReactNode;
  highlight?: boolean;
  isEmpty?: boolean;
  id?: string;
  emptyMessage?: React.ReactNode;
}

const Panel: React.FC<PanelProps> = ({
  title,
  children,
  highlight = false,
  isEmpty = false,
  id,
  emptyMessage = "No Results",
}) => {
  const [isExpanded, setIsExpanded] = useState(!isEmpty); // Default to expanded if not empty

  // Effect to update expanded state if isEmpty prop changes
  // useEffect(() => {
  //   setIsExpanded(!isEmpty);
  // }, [isEmpty]);

  const toggleExpand = () => {
    setIsExpanded(!isExpanded);
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
