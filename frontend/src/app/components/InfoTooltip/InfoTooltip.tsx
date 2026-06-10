import React, { useState, useRef, useEffect } from "react";
import "./InfoTooltip.css";

interface InfoTooltipProps {
  text: string;
}

const InfoTooltip: React.FC<InfoTooltipProps> = ({ text }) => {
  const [isVisible, setIsVisible] = useState(false);
  const [tooltipStyle, setTooltipStyle] = useState<React.CSSProperties>({});
  const buttonRef = useRef<HTMLButtonElement>(null);
  const tooltipRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isVisible && buttonRef.current && tooltipRef.current) {
      const buttonRect = buttonRef.current.getBoundingClientRect();
      const tooltipRect = tooltipRef.current.getBoundingClientRect();
      const tooltipWidth = tooltipRect.width;
      const gap = 8;
      const padding = 10;

      // Position to the left of the button
      let left = buttonRect.left - gap;
      const top = buttonRect.top + buttonRect.height / 2;

      // Check if there's enough space on the left
      if (left - tooltipWidth < padding) {
        // Not enough space on left, position to the right instead
        left = buttonRect.right + gap;
        setTooltipStyle({
          left: `${left}px`,
          top: `${top}px`,
          transform: "translateY(-50%)",
        });
      } else {
        // Position to the left
        setTooltipStyle({
          left: `${left}px`,
          top: `${top}px`,
          transform: "translate(-100%, -50%)",
        });
      }
    }
  }, [isVisible]);

  return (
    <div className="info-tooltip-container">
      <button
        ref={buttonRef}
        className="info-tooltip-button"
        onMouseEnter={() => setIsVisible(true)}
        onMouseLeave={() => setIsVisible(false)}
        onFocus={() => setIsVisible(true)}
        onBlur={() => setIsVisible(false)}
        aria-label="Information"
        type="button"
      >
        ⓘ
      </button>
      {isVisible && (
        <div
          ref={tooltipRef}
          className="info-tooltip-content"
          style={tooltipStyle}
          role="tooltip"
        >
          {text}
        </div>
      )}
    </div>
  );
};

export default InfoTooltip;
