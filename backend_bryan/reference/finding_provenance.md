# Finding-level Zeek provenance

Every detector finding emitted through the eleVADR analysis service or PCAP report pipeline is annotated after detection with machine-readable Zeek provenance. Detection modules themselves are not allowed to mutate the shared Zeek evidence or invent authorization policy.

## Finding contract

Each serialized detector finding contains a top-level `provenance` object and an identical `metadata.zeek_provenance` mirror:

```json
{
  "schema_version": 1,
  "resolution": "representative_flow",
  "sources": [
    {
      "log_type": "s7comm.log",
      "record_index": 0,
      "fields": {
        "function": "write",
        "id.orig_h": "10.10.1.50",
        "id.resp_h": "10.10.2.20"
      },
      "match_method": "object_identity"
    }
  ]
}
```

`log_type` is the originating Zeek log filename. `record_index` is the zero-based row index in the parsed retained log. `fields` contains the exact field/value pairs retained by the finding and resolved back to that Zeek row. Credential-like values are redacted. Up to ten representative source rows are retained per finding.

## Resolution modes

- `representative_flow` — the detector retained a representative flow/event that can be resolved directly to a Zeek row. This is preferred.
- `correlated_declared_log` — an absence/baseline/derived finding did not retain a direct source row, so eleVADR correlates the finding's devices, ports, services, or timestamps against the detector's declared Zeek inputs.
- `declared_log_without_representative_row` — the detector is driven by absence/state and no concrete row can be correlated. The evaluated Zeek log type is still recorded, but no field values are fabricated.

## Security and policy boundary

Finding provenance is observation only. It does not create trusted infrastructure, approved peers, control authorization, or other Detection Context policy. Fields with names indicating passwords, credentials, communities, secrets, tokens, authorization material, or cookies are redacted in provenance output.

The finding details UI exposes these references under **Zeek provenance** so analysts can pivot from a finding to the exact log and retained fields that support it.
