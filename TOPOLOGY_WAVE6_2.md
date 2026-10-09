# Topology Wave 6.2 - aggregate clusters

The default Topology graph now renders aggregate nodes for the selected Group by dimension (asset class, subnet, Purdue level, role group). Each node displays its group and asset count. Directed communications between displayed groups are aggregated by group pair, with observation totals, underlying relationship counts, protocol names and risk flags available in SVG tooltips. Activate a group with click, Enter, or Space to expand to individual assets. Use **Collapse to clusters** to return.

The aggregation is intentionally based on the bounded display-candidate graph, not the full report; the Query Explorer still evaluates report-derived relationships independently. A multi-hop observed communication path is not proof of routing or physical connectivity. Internal group communications are omitted from the aggregate inter-group edge view but remain available on drill-down.

## Validate on Windows

From `frontend`: `npm run type-check` and `npm run build`. Load a report, test every grouping dimension, expand and collapse a cluster, and verify the query explorer is unaffected. These frontend commands could not be executed here because Node 22.16.0 does not meet the project's Node >=22.22.3 requirement.
