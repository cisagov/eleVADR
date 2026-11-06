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
