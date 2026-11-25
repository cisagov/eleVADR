# Dataset 05 - Parser and malformed evidence edge cases

This fixture intentionally contains:

- short and over-wide Zeek ASCII rows;
- invalid numeric values in otherwise usable rows;
- malformed and non-object JSON-lines entries;
- a whole Zeek log missing its `#fields` header;
- partial Modbus records with missing endpoints and malformed values;
- expected, unexpected, allowed Q-in-Q, and unapproved double-tag VLAN observations;
- Zeek weird events that exercise checksum, malformed-header, capture-artifact, and state-violation handling.

The fixture is designed to prove that malformed evidence remains data-quality context and cannot abort the rest of an analysis.

## Provenance note

`conn.log` and `dns.log` were reconstructed (the originals were excluded by the
`*.log` rule in `.gitignore`). They satisfy the same assertions as the originals:
5 retained `conn` rows (2 short, 1 over-wide, 1 with an invalid numeric value),
VLAN observations producing exactly 3 `vlan_tag_mismatch_double_tag` findings, and
a `dns.log` with no `#fields` header. Prefer the original frozen files if recovered.
