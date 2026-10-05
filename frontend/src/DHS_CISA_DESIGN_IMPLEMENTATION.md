# DHS/CISA design implementation

This frontend keeps the customer-approved eleVADR application layout and adds
an isolated DHS/CISA visual and accessibility theme.

## What remains unchanged

- Fixed application titlebar and action placement
- Collapsible left report navigation
- Main content order, panel grid, and report workflow
- Existing React component behavior and data contracts
- Light/dark theme control

## Applied design-system treatment

- DHS/CISA navy and blue brand family with restrained DHS red accents
- USWDS role-based neutral, status, focus, and accent colors
- Source Sans Pro typography already bundled with the project
- CISA agency seal in the upper-left brand area, kept visually separate from
  the eleVADR product name
- Borderless masthead icons and lightweight icon actions
- Single-boundary report search and borderless information icons
- Uncluttered masthead with the redundant report-status indicator removed
- Simplified navigation chrome without the Report workspace label or dark-mode
  control
- Flat, bordered cards with minimal shadow and small corner radius
- Square, explicit form controls with visible disabled and focus states
- USWDS-style primary, outline, and segmented control states
- Bordered tables with strong headers, zebra rows, and hover reinforcement
- Persistent underlines on links
- Skip navigation, current-location semantics, forced-colors support, and
  reduced-motion behavior

## Integration

`App.tsx` loads `dhs-cisa-theme.css` after the original `App.css`, followed by
`dhs-a11y-hardening.css`. The original component styles remain the structural
baseline; the new files form the final visual/accessibility override layer.

The older `dhs-cisa-compliance.css` and `dhs-forms.css` files are retained for
reference but intentionally are not loaded. They contain an alternate masthead
and horizontal-navigation concept that would replace the approved layout.

## Validation still required

This is design-system alignment, not a Section 508 certification. Validate the
running application with the target dependency/build configuration, realistic
report data, keyboard-only navigation, supported screen readers, 200% and 400%
zoom/reflow, Windows High Contrast/forced colors, and the approved automated
accessibility scanner and browser matrix.
