from __future__ import annotations

from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[2]
UPLOAD = ROOT / "frontend" / "src" / "app" / "components" / "UploadForm" / "UploadForm.tsx"
APP = ROOT / "frontend" / "src" / "app" / "App.tsx"
COMPAT = ROOT / "frontend" / "src" / "app" / "utils" / "reportCompatibility.ts"
PROFILE = ROOT / "frontend" / "src" / "app" / "components" / "DetectionConfiguration" / "profile.ts"
APP_CSS = ROOT / "frontend" / "src" / "app" / "App.css"
REPORT_CONSISTENCY_CSS = ROOT / "frontend" / "src" / "app" / "report-consistency.css"
MODULE_SELECTOR = ROOT / "frontend" / "src" / "app" / "components" / "DetectionModuleSelector" / "DetectionModuleSelector.tsx"
MODULE_REFERENCES = ROOT / "frontend" / "src" / "app" / "components" / "DetectionConfiguration" / "moduleReferences.ts"
MODULE_HELP = ROOT / "frontend" / "src" / "app" / "components" / "DetectionConfiguration" / "moduleHelp.ts"
ENTITY_DRAWER = ROOT / "frontend" / "src" / "app" / "components" / "EntityDrawer" / "EntityDrawer.tsx"
DEVICES_PANEL = ROOT / "frontend" / "src" / "app" / "components" / "DevicesPanel" / "DevicesPanel.tsx"
SERVICE_INVENTORY = ROOT / "frontend" / "src" / "app" / "components" / "ServiceInventoryPanel.tsx"
ZEEK_FLOWS = ROOT / "frontend" / "src" / "app" / "components" / "ZeekFlowAnalysis.tsx"
NETWORK_TOPOLOGY = ROOT / "frontend" / "src" / "app" / "components" / "NetworkTopology" / "NetworkTopology.tsx"
PIVOT_VALUE = ROOT / "frontend" / "src" / "app" / "components" / "PivotValue" / "PivotValue.tsx"
REPORT_SEARCH = ROOT / "frontend" / "src" / "app" / "components" / "ReportSearch" / "ReportSearch.tsx"
SECURITY_OVERVIEW = ROOT / "frontend" / "src" / "app" / "components" / "SecurityOverview" / "SecurityOverview.tsx"
FINDINGS_PANEL = ROOT / "frontend" / "src" / "app" / "components" / "FindingsPanel" / "FindingsPanel.tsx"
OT_CROSS_SEGMENT = ROOT / "frontend" / "src" / "app" / "components" / "OTCrossSegmentPanel" / "OTCrossSegmentPanel.tsx"
DETECTION_CONTEXT = ROOT / "frontend" / "src" / "app" / "components" / "DetectionConfiguration" / "DetectionConfiguration.tsx"
DETECTION_CONTEXT_CSS = ROOT / "frontend" / "src" / "app" / "components" / "DetectionConfiguration" / "DetectionConfiguration.css"
HELP_DRAWER = ROOT / "frontend" / "src" / "app" / "components" / "HelpDrawer" / "HelpDrawer.tsx"
HELP_DRAWER_CSS = ROOT / "frontend" / "src" / "app" / "components" / "HelpDrawer" / "HelpDrawer.css"
FIRST_RUN_TOUR = ROOT / "frontend" / "src" / "app" / "components" / "FirstRunTour" / "FirstRunTour.tsx"
FIRST_RUN_TOUR_CSS = ROOT / "frontend" / "src" / "app" / "components" / "FirstRunTour" / "FirstRunTour.css"
REPORT_GUIDANCE = ROOT / "frontend" / "src" / "app" / "components" / "ReportGuidance" / "ReportGuidance.tsx"
REPORT_GUIDANCE_CSS = ROOT / "frontend" / "src" / "app" / "components" / "ReportGuidance" / "ReportGuidance.css"
AUTH_SERVICE = ROOT / "frontend" / "src" / "app" / "services" / "authService.ts"


def run_cases(verbose: bool = True) -> list[str]:
    failures: list[str] = []
    passed = 0
    upload = UPLOAD.read_text(encoding="utf-8")
    app = APP.read_text(encoding="utf-8")
    compat = COMPAT.read_text(encoding="utf-8")
    profile = PROFILE.read_text(encoding="utf-8")
    app_css = APP_CSS.read_text(encoding="utf-8")
    report_consistency_css = REPORT_CONSISTENCY_CSS.read_text(encoding="utf-8")
    module_selector = MODULE_SELECTOR.read_text(encoding="utf-8")
    module_references = MODULE_REFERENCES.read_text(encoding="utf-8")
    module_help = MODULE_HELP.read_text(encoding="utf-8")
    entity_drawer = ENTITY_DRAWER.read_text(encoding="utf-8")
    devices_panel = DEVICES_PANEL.read_text(encoding="utf-8")
    service_inventory = SERVICE_INVENTORY.read_text(encoding="utf-8")
    zeek_flows = ZEEK_FLOWS.read_text(encoding="utf-8")
    network_topology = NETWORK_TOPOLOGY.read_text(encoding="utf-8")
    pivot_value = PIVOT_VALUE.read_text(encoding="utf-8")
    report_search = REPORT_SEARCH.read_text(encoding="utf-8")
    security_overview = SECURITY_OVERVIEW.read_text(encoding="utf-8")
    findings_panel = FINDINGS_PANEL.read_text(encoding="utf-8")
    ot_cross_segment = OT_CROSS_SEGMENT.read_text(encoding="utf-8")
    detection_context = DETECTION_CONTEXT.read_text(encoding="utf-8")
    detection_context_css = DETECTION_CONTEXT_CSS.read_text(encoding="utf-8")
    help_drawer = HELP_DRAWER.read_text(encoding="utf-8")
    help_drawer_css = HELP_DRAWER_CSS.read_text(encoding="utf-8")
    first_run_tour = FIRST_RUN_TOUR.read_text(encoding="utf-8")
    first_run_tour_css = FIRST_RUN_TOUR_CSS.read_text(encoding="utf-8")
    report_guidance = REPORT_GUIDANCE.read_text(encoding="utf-8")
    report_guidance_css = REPORT_GUIDANCE_CSS.read_text(encoding="utf-8")
    auth_service = AUTH_SERVICE.read_text(encoding="utf-8")
    sortable_table = (ROOT / "frontend" / "src" / "app" / "components" / "SortableTable" / "SortableTable.tsx").read_text(encoding="utf-8")

    def require_tokens(label: str, source: str, tokens: tuple[str, ...]) -> None:
        missing = [token for token in tokens if token not in source]
        if missing:
            raise AssertionError(f"{label}: missing {missing!r}")

    def check(label: str, fn: Callable[[], None]) -> None:
        nonlocal passed
        try: fn()
        except Exception as exc:
            failures.append(f"{label}: {type(exc).__name__}: {exc}")
            if verbose: print(f"FAIL  {label} ({type(exc).__name__}: {exc})")
        else:
            passed += 1
            if verbose: print(f"PASS  {label}")

    if verbose:
        print("\n=== 13_ui_workflow_resilience: JSON/PCAP switching, cancellation, profile lifecycle, and compatibility ===")

    check("Both direct JSON and generated PCAP reports pass through the same report normalizer", lambda: (
        (upload.count("normalizeElevadrReport(") >= 2) or (_ for _ in ()).throw(AssertionError("normalizer not shared"))
    ))
    check("A PCAP failure cannot replace report state because onReportLoaded occurs only after completed normalization", lambda: (
        ("if (status.status === \"completed\")" in upload and "onReportLoaded(normalized);" in upload) or (_ for _ in ()).throw(AssertionError())
    ))
    check("Active analysis exposes a cancellation action backed by the job DELETE endpoint", lambda: (
        ("cancelActiveAnalysis" in upload and 'method: "DELETE"' in upload and "Cancel analysis" in upload) or (_ for _ in ()).throw(AssertionError())
    ))
    check("Canceled polling is distinguished from a failed analysis and does not surface a false failure", lambda: (
        ("AnalysisCanceledError" in upload and "status.status === \"canceled\"" in upload) or (_ for _ in ()).throw(AssertionError())
    ))
    check("PCAP context profile creation/deletion stays in the PCAP chooser workflow", lambda: (
        ("createNewDetectionContext" in upload and "deleteSelectedDetectionContext" in upload and "+ New Context" in upload) or (_ for _ in ()).throw(AssertionError())
    ))
    check("PCAP context chooser summarizes selected detection modules and can open module selection", lambda: (
        ("Module Selection" in upload and "Context Profile" in upload and "detection modules selected for this context" in upload and "aria-label=\"Edit Modules\"" in upload and "aria-label={" in upload and "onOpenDetectionModules=" in app)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Modules list supports stable user-selected sorting", lambda: (
        ("Sort modules" in module_selector
         and "name-asc" in module_selector
         and "name-desc" in module_selector
         and "ready-first" in module_selector
         and "needs-context-first" in module_selector
         and "setSortMode" in module_selector)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Modules expose standardized help beside readiness status", lambda: (
        ("View details for" in module_selector
         and "Module details" in module_selector
         and "Purpose" in module_selector
         and "Inputs" in module_selector
         and "Detection logic" in module_selector
         and "Thresholds and tunable settings" in module_selector
         and "Detection Context influence" in module_selector
         and "Typical true positive" in module_selector
         and "Potential false positives" in module_selector
         and "Analyst validation" in module_selector
         and "standardizedModuleHelp" in module_selector
         and "ADVANCED_POLICY_SCHEMA_BY_MODULE" in module_help
         and "DETECTION_MODULE_DETAILS" in module_selector)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Module help distinguishes implementation-backed facts from analyst guidance", lambda: (
        ("Implementation-backed:" in module_selector
         and "analyst guidance" in module_selector
         and "MODULE_HELP_NUMERIC_DEFAULTS" in module_help
         and "This value is taken from the detector implementation" in module_help)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Global Help Center provides workflow, searchable glossary, diagnostics, and replayable walkthrough", lambda: (
        (
            'onClick={() => setHelpOpen(true)}' in app
            and "Getting started" in help_drawer
            and "Search glossary" in help_drawer
            and "Diagnostics" in help_drawer
            and "Copy diagnostics" in help_drawer
            and "Replay report walkthrough" in help_drawer
            and "Observed traffic is evidence, not authorization" in help_drawer
            and "navigator.userAgent" in help_drawer
            and "analysis_provenance" in help_drawer
            and "Report walkthrough" in first_run_tour
            and "initialScrollPosition.current = { x: window.scrollX, y: window.scrollY }" in first_run_tour
            and "window.scrollTo({" in first_run_tour
            and "initialScrollPosition.current = null" in first_run_tour
            and "Why flagged?" in first_run_tour
            and "if (step.section) onGoTo(step.section)" in first_run_tour
            and 'classList.add("tour-highlight-target")' in first_run_tour
            and 'classList.remove("tour-highlight-target")' in first_run_tour
            and 'scrollTarget: "network-topology"' in first_run_tour
            and 'highlightTargets: ["report-context-action", "report-modules-action"]' in first_run_tour
            and 'scrollTarget: "report-notes-action"' in first_run_tour
            and 'id="report-context-action"' in app
            and 'id="report-modules-action"' in app
            and 'id="report-notes-action"' in app
            and 'id="report-customize-action"' in app
            and 'id="report-export-action"' in app
            and 'classList.add("tour-highlight-layer")' in first_run_tour
            and 'classList.add("tour-highlight-host")' in first_run_tour
            and 'classList.remove("tour-highlight-host")' in first_run_tour
            and ".dashboard-section.tour-highlight-host" in first_run_tour_css
            and "content-visibility:visible!important" in first_run_tour_css.replace(" ", "")
            and ".titlebar.tour-highlight-layer" in first_run_tour_css
            and "backdrop-filter:none" in first_run_tour_css.replace(" ", "")
            and ".tour-highlight-target" in first_run_tour_css
            and "z-index: 3100" in help_drawer_css
            and "z-index: 3110" in help_drawer_css
            and ".help-tabs button:focus-visible {" in help_drawer_css and "outline-offset: -2px;" in help_drawer_css
        ) or (_ for _ in ()).throw(AssertionError())
    ))
    check("Module detail dialogs provide authoritative external concept references", lambda: (
        ("Learn more" in module_selector
         and "DETECTION_MODULE_REFERENCES" in module_selector
         and 'target="_blank"' in module_selector
         and 'rel="noopener noreferrer"' in module_selector
         and "NIST SP 800-82 Rev. 3" in module_references
         and "MITRE ATT&CK" in module_references
         and "Zeek Documentation" in module_references)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("PCAP workflow reuses the one-time Zeek evidence token instead of re-uploading/rerunning Zeek", lambda: (
        ("evidenceToken" in upload and 'formData.append("evidenceToken", evidenceToken)' in upload and "without running Zeek again" in upload) or (_ for _ in ()).throw(AssertionError())
    ))
    check("Retained evidence reuse is bound to the discovered PCAP SHA-256", lambda: (
        ('formData.append("evidencePcapSha256", evidencePcapSha256)' in upload and "pcapSha256" in upload) or (_ for _ in ()).throw(AssertionError())
    ))
    check("Returning Home explicitly clears the active report rather than mutating it during a failed upload", lambda: (
        ("const returnToWelcome" in app and "setReport(null);" in app) or (_ for _ in ()).throw(AssertionError())
    ))
    check("Legacy/current JSON compatibility remains centralized rather than duplicated in UI components", lambda: (
        ("normalizeElevadrReport" in compat and "Unsupported" in compat) or (_ for _ in ()).throw(AssertionError())
    ))
    check("Detection Context storage exposes explicit save/remove/activate lifecycle operations", lambda: (
        all(token in profile for token in ("saveProfile", "removeProfile", "activateProfile")) or (_ for _ in ()).throw(AssertionError())
    ))
    check("The report viewer remains a single long-scroll state selected by report presence", lambda: (
        ("report &&" in app and 'report ? "is-hidden" : ""' in app) or (_ for _ in ()).throw(AssertionError())
    ))
    check("Responsive layouts retain dedicated narrow-window breakpoints", lambda: (
        ("@media (max-width: 620px)" in app_css and "@media (max-width: 380px)" in app_css) or (_ for _ in ()).throw(AssertionError())
    ))
    check("Share, print, customization, and filtered JSON export actions remain available when a report is loaded", lambda: (
        all(token in app for token in ("shareCurrentView", "window.print()", "handleDownloadJson", "Customize", "Export")) or (_ for _ in ()).throw(AssertionError())
    ))
    check("Report customization is non-destructive and controls navigation, print/view sections, and derivative export metadata", lambda: (
        ("visibleReportSections" in app
         and "buildFilteredReport" in app
         and "included_sections" in app
         and "excluded_sections" in app
         and "source report was not modified" in app
         and 'base.filter((item) =>' in app
         and 'visibleReportSections.has("connections")' in app
         and "reportSections" in app)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Report section headings expose subtle detector-contribution attribution from retained detector findings", lambda: (
        ("contributingModules" in app and "module-contribution-badge" in app and "detector_findings" in app and "detection module" in app)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Summary uses a unified compact metrics row with findings, service activity, and key takeaways", lambda: (
        ('id="summary-environment"' in security_overview
         and 'summary-environment-title' in security_overview
         and '>Environment Overview</span>' in security_overview
         and 'className="summary-unified-metrics"' in security_overview
         and 'summary-unified-metric-findings' in security_overview
         and '>Findings</span>' in security_overview
         and 'id="summary-service-activity"' in security_overview
         and 'className="summary-takeaways"' in security_overview
         and 'Key Takeaways' in security_overview
         and 'id="summary-devices"' not in security_overview
         and 'id="summary-services"' not in security_overview
         and 'id="summary-connections"' not in security_overview)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Major report sections use a consistent chapter hierarchy and current-section indicator", lambda: (
        ("REPORT_SECTION_META" in app
         and "ReportSectionHeading" in app
         and "report-section-icon" in app
         and "report-current-section" in app
         and "Current section" in app
         and "report-section-heading--" in app
         and ".dashboard-section > .report-section-heading" in app_css
         and ".report-section-heading-copy p" in app_css
         and ".report-current-section" in app_css)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Findings, devices, services, and connections share one right-side investigation drawer", lambda: (
        ("<EntityDrawer" in app
         and "DeviceDetailsModal" not in app
         and 'entity.type === "device"' in entity_drawer
         and 'entity.type === "service"' in entity_drawer
         and 'entity.type === "connection"' in entity_drawer
         and 'entity.type === "finding"' in entity_drawer
         and "Identity and network" in entity_drawer
         and "Observed services" in entity_drawer
         and "Connected peers" in entity_drawer
         and "Suspicious outbound observations" in entity_drawer
         and "Observed connections" in entity_drawer
         and "Observed flow data" in entity_drawer
         and "onRowClick={inspectDevice}" in devices_panel
         and "onRowLongPress" not in devices_panel
         and '<PivotValue filter={filter} filters={filters} onFilter={onFilter}>' in devices_panel
         and 'onSelect?.({ type: "service", id: row.name })' in service_inventory
         and 'filter={{ key: "service", value: name, label: "Service" }}' in service_inventory
         and "onRowLongPress" not in service_inventory
         and '>Service Inventory</span>' in service_inventory
         and '"OT"' in service_inventory
         and '"IT"' in service_inventory
         and '"Other / Unclassified"' in service_inventory
         and 'DetailModal' not in service_inventory
         and 'id: `${src}|${dst}|${service}`' in zeek_flows
         and 'onSelect({ type: "connection", id: edge.id });' in network_topology
         and "onRowLongPress" not in sortable_table
         and 'className="pivot-value-icon"' in pivot_value
         and 'event.stopPropagation()' in pivot_value)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Service inventory classifies OT, IT, and unclassified services without duplicating service panels", lambda: (
        ("<ServiceInventoryPanel" in app
         and "<ServicePanel" not in app
         and "<ServiceCountPanel" not in app
         and "<OTServices" not in app
         and 'id="service-inventory-panel"' in service_inventory
         and 'classification: otDefinition ? "OT" : "IT"' in service_inventory
         and 'classification: "Other / Unclassified"' in service_inventory
         and '>Implicated in Findings</span>' in service_inventory
         and app.index("<ServiceInventoryPanel") < app.index("<ServiceRiskBreakdownPanel")
         and 'Service classification' in entity_drawer)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Network topology uses the shared drawer/filter contract and finding-aware investigation controls", lambda: (
        ("setFocusedNodeId(node.id)" in network_topology
         and "setFocusedEdgeId(edge.id)" in network_topology
         and 'onSelect({ type: "device", id: node.id });' in network_topology
         and 'onSelect({ type: "connection", id: edge.id });' in network_topology
         and "topology-selection-bar" in network_topology
         and "topology-filter-action" in network_topology
         and 'onFilter({ key: "ip", value: focusedNode.id, label: "Device" })' in network_topology
         and 'onFilter({ key: "service", value: focusedEdge.service, label: "Service" })' in network_topology
         and 'value={activeService}' in network_topology
         and 'value={selectedClass}' in network_topology
         and "findingIndex" in network_topology
         and "Finding-related" in network_topology
         and "focusedNodeId && !neighborIds.has(node.id)" in network_topology
         and "toggleFullScreen" in network_topology
         and "Export SVG" in network_topology
         and "Fit" in network_topology
         and "Reset" in network_topology
         and 'type LabelMode = "minimal" | "full" | "off"' in network_topology
         and 'value={labelMode}' in network_topology
         and '>Minimal<' in network_topology
         and '>Full<' in network_topology
         and '>Off<' in network_topology
         and "hoveredNodeId === node.id" in network_topology
         and "hoveredEdgeId === edge.id" in network_topology
         and "const [hideIsolated, setHideIsolated] = useState(true);" in network_topology
         and "Hide isolated" in network_topology
         and "const [neighborsOnly, setNeighborsOnly] = useState(false);" in network_topology
         and "Selected + neighbors" in network_topology
         and "focusedNeighborIds" in network_topology
         and "!hideIsolated ||" not in network_topology
         and "if (hideIsolated && observedDegree === 0) return false;" in network_topology
         and "!focusedNeighborIds.has(node.id)" in network_topology
         and 'aria-label="Topology view"' in network_topology
         and '<option value="subnet">Subnet</option>' in network_topology
         and 'type LayoutMode = "class" | "subnet" | "role" | "purdue"' in network_topology
         and '<option value="role">Role group</option>' in network_topology
         and '<option value="purdue">Purdue level</option>' in network_topology
         and 'const groupRegions = useMemo<GroupRegion[]>' in network_topology
         and 'className="topology-subnet-region topology-group-region"' in network_topology
         and 'source.subnet !== target.subnet' in network_topology
         and 'source.roleGroup !== target.roleGroup' in network_topology
         and 'source.purdueLevel !== target.purdueLevel' in network_topology
         and '"cross-boundary"' in network_topology
         and 'legend-cross-subnet' in network_topology
         and 'Purdue unassigned' in network_topology)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Entity inspection and funnel filtering follow one interaction contract across report surfaces", lambda: (
        ("if (result.entity) onSelect?.(result.entity);" in report_search
         and "else if (result.filter) onFilter?.(result.filter);" in report_search
         and 'pivot("services", undefined, {' in security_overview
         and 'onSelect({ type: "finding", id: finding.id })' in findings_panel
         and 'onSelect?.({ type: "device", id: row.src_device_ip })' in ot_cross_segment
         and 'key: "ip"' in ot_cross_segment and 'value: String(value)' in ot_cross_segment
         and "tabIndex={onRowClick ? 0 : undefined}" in sortable_table
         and 'role={onRowClick ? "button" : undefined}' in sortable_table
         and 'className="pivot-value-icon"' in pivot_value
         and 'event.stopPropagation()' in pivot_value)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Entity drawers support persistent notes without mixing commentary into detector evidence", lambda: (
        ("entityNotes" in app
         and "elevadr-entity-notes:" in app
         and "entity_notes" in app
         and "saveEntityNote" in app
         and '<DrawerSection title="Notes">' in entity_drawer
         and "+ Add note" in entity_drawer
         and "onSaveNote" in entity_drawer
         and "onDeleteNote" in entity_drawer
         and "stored separately from detector and Zeek evidence" in entity_drawer)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Entity drawers preserve generated evidence while supporting dark-blue reviewed overrides", lambda: (
        ("entityOverrides" in app
         and "elevadr-entity-overrides:" in app
         and "entity_overrides" in app
         and "saveEntityOverrides" in app
         and "resetEntityOverrides" in app
         and '<DrawerSection title="Review details">' in entity_drawer
         and "Reset edits" in entity_drawer
         and "Generated value:" in entity_drawer
         and "entity-review-field" in entity_drawer
         and "onSaveOverrides" in entity_drawer
         and "onResetOverrides" in entity_drawer
         and "#1f5f8f" in (ROOT / "frontend/src/app/components/EntityDrawer/EntityDrawer.css").read_text(encoding="utf-8"))
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Network topology state persists per report and is included in exports/print", lambda: (
        ("elevadr-topology-state:" in network_topology
         and "localStorage.getItem(graphStateStorageKey)" in network_topology
         and "localStorage.setItem(graphStateStorageKey" in network_topology
         and "onStateChange?.(state)" in network_topology
         and "beforeprint" in network_topology
         and "afterprint" in network_topology
         and "metadata.textContent = JSON.stringify" in network_topology
         and 'aria-label="Reset graph view"' in network_topology
         and 'graph_view: visibleReportSections.has("topology")' in app
         and 'graph_view: graphViewState' in app
         and "onStateChange={setGraphViewState}" in app)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Network topology bounds dense rendering and throttles interaction persistence", lambda: (
        ("STATE_PERSIST_DELAY_MS" in network_topology
         and "EDGE_LIMITS" in network_topology
         and "NODE_LIMITS" in network_topology
         and "requestAnimationFrame" in network_topology
         and "deviceIndex = useMemo" in network_topology
         and "contextLookup = useMemo" in network_topology
         and "topology-performance-note" in network_topology
         and "Dense topology:" in network_topology)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Network topology separates display mode from Group by and Labels", lambda: (
        require_tokens("topology controls", network_topology, (
            'className="topology-view-mode"', 'aria-label="Topology view"',
            '<option value="communication">Communication</option>',
            '<option value="findings">Findings</option>',
            'id="topology-cluster-mode"', 'Group by',
            '<option value="subnet">Subnet</option>',
            '<option value="role">Role group</option>',
            '<option value="purdue">Purdue level</option>',
            'className="topology-label-mode"',
        ))
    ))
    check("Network topology uses the compact Option 1 horizontal control deck and collapsible legend", lambda: (
        (('topology-toolbar topology-toolbar-option1' in network_topology
          and 'className="topology-view-mode"' in network_topology
          and 'topology-filter-group' in network_topology
          and 'topology-refinement-group' in network_topology
          and 'aria-label="Topology actions"' in network_topology
          and 'const [legendOpen, setLegendOpen] = useState(true);' in network_topology
          and 'topology-legend-toggle' in network_topology
          and 'aria-expanded={legendOpen}' in network_topology
          and 'topology-legend-items' in network_topology
          and 'topology-toolbar-option1' in (ROOT / "frontend/src/app/components/NetworkTopology/NetworkTopology.css").read_text(encoding="utf-8")))
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Network topology panel expansion, keyboard activation and empty recovery", lambda: (
        require_tokens("topology interaction", network_topology, (
            'toggleFullScreen', 'Collapse panel', 'Expand panel',
            'aria-pressed={isFullScreen}', 'inspectEdge(edge)', 'inspectNode(node)',
            'Clear topology refinements', 'clearGraphRefinements',
            'aria-label="Topology view"',
        ))
        and require_tokens("topology focus styling", (ROOT / "frontend/src/app/components/NetworkTopology/NetworkTopology.css").read_text(encoding="utf-8"), (':focus-visible',))
    ))
    check("Network topology click, drawer, and funnel interactions avoid SVG focus boxes", lambda: (
        (('Math.hypot(dxClient, dyClient) < 5' in network_topology
          and '.closest(".topology-node, .topology-edge")' in network_topology
          and 'onPointerDown={(event) => event.stopPropagation()}' in network_topology
          and 'className="node-drag-handle"' in network_topology
          and 'onPointerDown={(event) => beginNodeDrag(event, node)}' in network_topology
          and 'dragRef.current = null;' in network_topology
          and 'setIsInteracting(false);' in network_topology
          and 'inspectNode(node);' in network_topology
          and 'focusNodeNeighborhood(node);' in network_topology
          and 'className="topology-edge-hit"' in network_topology
          and 'Math.max(16, width + 12)' in network_topology
          and 'onSelect({ type: "device", id: node.id })' in network_topology
          and 'onSelect({ type: "connection", id: edge.id })' in network_topology
          and 'focusedDeviceFilterActive' in network_topology
          and 'focusedServiceFilterActive' in network_topology
          and 'event.key !== "Escape"' in network_topology
          and '.node-drag-handle' in (ROOT / "frontend/src/app/components/NetworkTopology/NetworkTopology.css").read_text(encoding="utf-8")
          and 'outline: none !important' in (ROOT / "frontend/src/app/components/NetworkTopology/NetworkTopology.css").read_text(encoding="utf-8")))
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Report sections share one typography, spacing, table, and control presentation contract", lambda: (
        ('import "./report-consistency.css";' in app
         and '.app-shell .dashboard-section .panel-header' in report_consistency_css
         and '.app-shell .dashboard-section .panel-title' in report_consistency_css
         and '.app-shell .dashboard-section table th' in report_consistency_css
         and '.app-shell .dashboard-section table td' in report_consistency_css
         and '.app-shell .dashboard-section .data-label' in report_consistency_css
         and '.app-shell .dashboard-section .service-inventory-summary > div' in report_consistency_css)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Print styling remains explicitly defined for the long-scroll report", lambda: (
        ("@media print" in app_css) or (_ for _ in ()).throw(AssertionError())
    ))
    check("Detection Context distinguishes observed evidence, inference, user input, and policy", lambda: (
        ("How Context affects analysis" in detection_context
         and 'kind="observed"' in detection_context
         and 'kind="inferred"' in detection_context
         and 'kind="user"' in detection_context
         and 'kind="policy"' in detection_context
         and 'kind="imported"' in detection_context
         and "Observed traffic is evidence, not authorization" in detection_context
         and "Observed traffic is evidence, not authorization" in detection_context
         and ".context-provenance-badge" in detection_context_css
         and ".context-guidance-note" in detection_context_css)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Detection Context provides keyboard-accessible contextual help for high-impact policy areas", lambda: (
        ("ContextHelp" in detection_context
         and 'aria-label={`Help: ${label}`}' in detection_context
         and 'label="Capture Scope"' in detection_context
         and 'label="Network Segments"' in detection_context
         and 'label="Asset Inventory"' in detection_context
         and 'label="Trusted Infrastructure"' in detection_context
         and 'label="Control Authorization"' in detection_context
         and 'label="Advanced Module Overrides"' in detection_context
         and ".context-inline-help" in detection_context_css
         and ".context-inline-help-panel" in detection_context_css
         and ":focus-visible" in detection_context_css)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Report empty and unavailable states explain why and provide next actions", lambda: (
        ("No findings were generated" in app
         and "Review Modules" in app
         and "Review Context" in app
         and "How findings are generated" in app
         and "No device inventory is available" in app
         and "No services were identified" in app
         and "No endpoint connection records are available" in app
         and "No findings match the current view" in findings_panel
         and "This is a filtered empty state, not a zero-finding analysis" in findings_panel
         and "Clear finding filters" in findings_panel
         and 'Create or select a Context before analyzing this PCAP.' in upload
         and "report-guidance-actions" in report_guidance
         and ".report-guidance-action:focus-visible" in report_guidance_css)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Authentication-aware frontend gates analysis and carries bearer tokens to backend requests", lambda: (
        ("fetchAuthState" in app
         and "authenticationRequired" in app
         and "Sign in to eleVADR" in app
         and "Your session expired. Sign in again to continue." in app
         and "handleSignOut" in app
         and "sessionStorage" in auth_service
         and 'headers.set("Authorization", `Bearer ${value}`)' in auth_service
         and "AUTH_EXPIRED_EVENT" in auth_service
         and "VITE_AUTH_BASE_URL" in auth_service
         and "VITE_DETECTION_ANALYSIS_URL" in auth_service
         and "new URL(configuredApi, window.location.origin).origin" in auth_service
         and "authenticatedFetch" in upload
         and "mocked in this frontend build" not in app)
        or (_ for _ in ()).throw(AssertionError())
    ))
    check("Saved Detection Context/module changes regenerate an open PCAP report in place", lambda: (
        ("markReportConfigurationChanged" in app
         and 'markReportConfigurationChanged("Modules")' in app
         and 'markReportConfigurationChanged("Detection Context")' in app
         and "reportConfigurationStale" in app
         and "Reload report with the updated configuration" in app
         and "Generate and load updated report" in app
         and "requestUpdatedReport" in app
         and "refreshRequestRevision" in upload
         and "lastPcapSession" in upload
         and "evidenceToken" in upload
         and "returnToWelcome}>Load updated report" not in app)
        or (_ for _ in ()).throw(AssertionError())
    ))

    if verbose:
        print(f"{'FAIL' if failures else 'PASS'}: Dataset 13 verified {passed} UI-workflow resilience cases.")
    return failures


def main() -> int:
    return 1 if run_cases(True) else 0

if __name__ == "__main__":
    raise SystemExit(main())
