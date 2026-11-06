# Platform storage and PCAP retention

Stage 9 adds optional retention and quota controls for retained PCAPs. Saved report JSON is not subject to PCAP expiry and remains available after its source capture is removed.

## Configuration

- `ELEVADR_PCAP_RETENTION_DAYS=0` disables automatic PCAP expiry (default). Set a positive number of days to expire captures that have not been used within that interval.
- `ELEVADR_PCAP_STORAGE_LIMIT_GB=0` disables the per-user retained-PCAP quota (default). Set a positive number of GiB to reject retention of a new unique capture when it would exceed the account limit.
- `ELEVADR_STORAGE_ROOT` continues to control the filesystem root for retained reports and captures.

Deduplicated uploads do not consume additional quota. Re-analyzing or rediscovering an already-retained capture refreshes `last_used_at`, which moves its expiry date forward when retention is enabled.

## Cleanup

Expired captures are cleaned at backend startup and when a user's capture library is listed or a new capture is retained. Administrators can also run cleanup from the Storage & Retention dashboard. Orphan cleanup removes files under `storage/users/*/pcaps/` that have no MongoDB capture metadata; it never removes report JSON.

## Safety

Deleting or expiring a PCAP does not delete saved reports. Storage paths remain constrained beneath the configured storage root. The admin storage view reports metadata-derived capture usage and filesystem-derived report usage; it does not expose packet contents.
