# eleVADR DHS/CISA frontend accessibility audit

This source pass aligns the eleVADR frontend with applicable DHS Section 508 baseline testing concepts and USWDS component accessibility guidance. It is an implementation hardening pass, not a certification.

## Implemented in this pass

- Native keyboard-operable file input overlays the drag/drop surface; drag is not required.
- File-type instructions and errors are programmatically associated with the upload control.
- Search input has an explicit label and keyboard-accessible suggestion buttons without incomplete ARIA listbox behavior.
- Raw JSON filtering has an explicit label and live result-count status.
- Modal/dialog headings programmatically name dialogs; Escape/focus behavior remains handled by the dialog hook.
- Tooltips expose their relationship to the trigger and can be dismissed with Escape.
- Sortable table headers retain `aria-sort`; filter/pagination controls have unique labels; clickable rows get keyboard activation; clickable cells use native buttons.
- Findings and summary tables have accessible names/captions and column header scopes.
- Topology filter checkboxes are grouped with `fieldset`/`legend`; SVG nodes/links support Enter/Space activation.
- Interactive charts include native-button alternatives for risk, device class, and service filtering.
- The activity timeline chart has an expandable data-table equivalent.
- Report detail-level toggles expose pressed state.
- Status dots are decorative; status text remains in a live status region.
- Focus, forced-colors, reduced-motion, responsive, and print behavior from the prior DHS/CISA layer are preserved.

## Required validation before a formal Section 508 review

Run the actual deployed application through keyboard-only navigation, Windows high-contrast/forced-colors, 200% and 400% zoom/reflow, screen-reader testing (for example Narrator/JAWS), and the organization's approved automated accessibility scanner. Validate report data at realistic maximum lengths and test all modal, filtering, export, upload, topology, and error paths.

Brand/logo usage and public-site content requirements (government banner, privacy/FOIA links, agency footer, etc.) still depend on the final CISA hosting and External Affairs requirements.


## Final QA checkpoint follow-up

- Mobile report navigation now traps keyboard focus while open, closes with Escape, and restores focus to the hamburger control.
- The hamburger control exposes explicit Open/Close accessible names and `aria-expanded`.
- Masthead report actions and chart/report-guide action collections now expose programmatic group/region semantics where visible labels are represented by `aria-label`.
- The pre-final-QA source bundle was preserved separately as `eleVADR_checkpoint_pre_final_508_QA.zip`.

### Runtime validation still required

Formal DHS Section 508 acceptance still requires testing the running application with keyboard-only navigation, supported screen readers, 200%/400% zoom and reflow, Windows High Contrast/forced colors, and the target browser matrix. Static source review cannot certify those runtime behaviors.
