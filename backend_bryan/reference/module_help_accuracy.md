# Detection-module help accuracy contract

The module-detail help shown by the frontend is divided into two categories.

## Implementation-backed content

The following content is treated as part of the detector implementation contract and is regression checked:

- the complete 75-module ID set;
- detector display names;
- detector descriptions used as the **Detection logic** explanation;
- required Zeek logs and `required_any_logs` used by **Inputs**;
- numeric Detection Context fields exposed by `advancedPolicySchema.ts`; and
- the implementation default for every exposed numeric Detection Context field.

`backend_bryan/integration/module_help_accuracy.py` compares the frontend help catalog with `module_registry_snapshot.json` and with each detector's `ModuleMetadata`. It also verifies the numeric help defaults against the detector source. `backend_bryan/tests/test_module_help_accuracy.py` makes drift a regression failure.

## Analyst guidance

The **Typical true positive**, **Potential false positives**, and **Analyst validation** sections are intentionally analyst guidance. They illustrate how to investigate detector output, but they are not detector conditions and do not alter firing logic, severity, confidence, or policy evaluation.

The UI labels this distinction so an operator does not mistake an example or troubleshooting suggestion for executable detector logic.

## Maintenance rule

When detector metadata, required logs, an exposed policy field, or a numeric policy default changes, update the corresponding frontend help contract in the same change. Do not change a documented default merely to satisfy the test; the detector implementation remains authoritative.
