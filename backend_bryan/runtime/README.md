# Zeek Runtime Resolution

`backend_bryan.runtime.zeek_runtime` is the only Zeek execution boundary used by the isolated PCAP workflows.

Runtime priority:

1. `ELEVADR_ZEEK_COMMAND` if explicitly configured.
2. A native `zeek` executable on `PATH`.
3. Docker using the pinned official image `zeek/zeek:9.0.0`.

The image can be overridden for controlled testing with `ELEVADR_ZEEK_DOCKER_IMAGE`.

On Windows, Docker Desktop is the expected fallback when native Zeek is not installed. The image is not copied into the eleVADR ZIP; Docker downloads it on first PCAP analysis and then reuses its local cache.
