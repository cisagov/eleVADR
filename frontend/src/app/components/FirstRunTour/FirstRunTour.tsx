import React, { useEffect, useRef, useState } from "react";
import "./FirstRunTour.css";

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onGoTo: (section: string) => void;
}

interface TourStep {
  title: string;
  body: string;
  section?: string;
  scrollTarget: string;
  highlightTargets: string[];
}

const steps: TourStep[] = [
  {
    title: "Start with the summary",
    body: "Use the executive summary to understand the capture and the highest-priority takeaways before opening individual evidence.",
    section: "overview",
    scrollTarget: "overview",
    highlightTargets: ["overview"],
  },
  {
    title: "Ask why a finding fired",
    body: "Open Findings and use Why flagged? to follow observation → detector rule → Analysis Context → conclusion before you validate the detailed evidence.",
    section: "findings",
    scrollTarget: "findings",
    highlightTargets: ["findings"],
  },
  {
    title: "Follow devices and services",
    body: "Pivot on IPs, services, ports, manufacturers, subnets, and connection states to carry one investigation across the report.",
    section: "devices",
    scrollTarget: "devices",
    highlightTargets: ["devices", "services"],
  },
  {
    title: "Explore the topology",
    body: "Use the network topology to see relationships, finding-related paths, suspicious flows, and neighborhood context without treating observed communication as authorization.",
    section: "connections",
    scrollTarget: "network-topology",
    highlightTargets: ["network-topology"],
  },
  {
    title: "Use Analysis Context and module help",
    body: "The title-bar Context and Modules actions explain site policy, provenance, detector inputs, thresholds, false positives, and validation guidance.",
    scrollTarget: "report-context-action",
    highlightTargets: ["report-context-action", "report-modules-action"],
  },
  {
    title: "Finish with notes and export",
    body: "Record analyst notes or reviewed overrides, customize the long-form report, then share, print, or export the derivative view. Help can replay this walkthrough at any time.",
    scrollTarget: "report-notes-action",
    highlightTargets: [
      "report-notes-action",
      "report-customize-action",
      "report-export-action",
    ],
  },
];

const FirstRunTour: React.FC<Props> = ({ isOpen, onClose, onGoTo }) => {
  const [index, setIndex] = useState(0);
  const initialScrollPosition = useRef<{ x: number; y: number } | null>(null);

  useEffect(() => {
    if (!isOpen) return;
    initialScrollPosition.current = { x: window.scrollX, y: window.scrollY };
    setIndex(0);
  }, [isOpen]);

  const step = steps[index];

  useEffect(() => {
    if (!isOpen || !step) return;

    // First move the report to the owning report section, when the step has one.
    // Then scroll the exact control/panel into view and spotlight every element the
    // step describes. This keeps later steps tied to real controls instead of
    // falling back to the Summary section.
    if (step.section) onGoTo(step.section);

    const frame = window.requestAnimationFrame(() => {
      const scrollTarget = document.getElementById(step.scrollTarget);
      scrollTarget?.scrollIntoView({
        behavior: "smooth",
        block: "center",
        inline: "nearest",
      });

      step.highlightTargets.forEach((id) => {
        const target = document.getElementById(id);
        target?.classList.add("tour-highlight-target");
        const layer = target?.closest(".titlebar, .sidebar");
        layer?.classList.add("tour-highlight-layer");
        // content-visibility:auto on report sections creates paint containment.
        // Temporarily relax that containment so a nested panel (notably Network
        // Topology) can actually rise above the walkthrough scrim.
        const host = target?.closest(".dashboard-section");
        host?.classList.add("tour-highlight-host");
      });
    });

    return () => {
      window.cancelAnimationFrame(frame);
      step.highlightTargets.forEach((id) => {
        const target = document.getElementById(id);
        target?.classList.remove("tour-highlight-target");
        const layer = target?.closest(".titlebar, .sidebar");
        layer?.classList.remove("tour-highlight-layer");
        const host = target?.closest(".dashboard-section");
        host?.classList.remove("tour-highlight-host");
      });
    };
  }, [index, isOpen, onGoTo, step]);

  if (!isOpen) return null;

  const finish = () => {
    localStorage.setItem("elevadr-tour-seen", "1");
    const restorePosition = initialScrollPosition.current;
    initialScrollPosition.current = null;
    onClose();
    if (restorePosition) {
      window.requestAnimationFrame(() => {
        window.scrollTo({
          left: restorePosition.x,
          top: restorePosition.y,
          behavior: "auto",
        });
      });
    }
  };

  const goBack = () => setIndex((current) => Math.max(0, current - 1));
  const goNext = () => {
    if (index === steps.length - 1) finish();
    else setIndex((current) => Math.min(steps.length - 1, current + 1));
  };

  return (
    <>
      <div className="tour-backdrop" aria-hidden="true" />
      <section
        className="tour-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="tour-title"
        aria-describedby="tour-description"
      >
        <div className="tour-progress" aria-hidden="true">
          {steps.map((_, i) => (
            <span
              key={i}
              className={i === index ? "active" : i < index ? "done" : ""}
            />
          ))}
        </div>
        <p className="tour-step">
          Report walkthrough · {index + 1} of {steps.length}
        </p>
        <h2 id="tour-title">{step.title}</h2>
        <p id="tour-description">{step.body}</p>
        <p className="tour-location-note">
          The related report section is highlighted behind this walkthrough.
        </p>
        <div className="tour-actions">
          <button type="button" className="tour-skip" onClick={finish}>
            Skip walkthrough
          </button>
          <div>
            {index > 0 && (
              <button type="button" onClick={goBack}>
                Back
              </button>
            )}
            <button type="button" className="tour-next" onClick={goNext}>
              {index === steps.length - 1 ? "Finish" : "Next"}
            </button>
          </div>
        </div>
      </section>
    </>
  );
};

export default FirstRunTour;
