import React, { useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import "./InfoTooltip.css";

interface InfoTooltipProps {
  text: string;
}

const InfoTooltip: React.FC<InfoTooltipProps> = ({ text }) => {
  const [isOpen, setIsOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const tooltipId = useId();

  useEffect(() => {
    if (!isOpen) return;

    const handlePointerDown = (event: MouseEvent | TouchEvent) => {
      if (!containerRef.current?.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setIsOpen(false);
        buttonRef.current?.focus();
      }
    };

    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("touchstart", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("touchstart", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [isOpen]);

  const tooltip = isOpen && typeof document !== "undefined"
    ? createPortal(
        <div
          id={tooltipId}
          className="info-tooltip-content"
          role="tooltip"
        >
          {text}
        </div>,
        document.body,
      )
    : null;

  return (
    <>
      <div ref={containerRef} className="info-tooltip-container">
        <button
          ref={buttonRef}
          className="info-tooltip-button"
          onClick={(event) => {
            event.preventDefault();
            event.stopPropagation();
            setIsOpen((current) => !current);
          }}
          aria-label="Information"
          aria-expanded={isOpen}
          aria-controls={isOpen ? tooltipId : undefined}
          type="button"
        >
          <span className="info-tooltip-glyph" aria-hidden="true">i</span>
        </button>
      </div>
      {tooltip}
    </>
  );
};

export default InfoTooltip;
