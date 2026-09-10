Corporate CA certificates (optional)
====================================

By default, the dev container auto-detects corporate CA certificates. If neither
certificate is present, no custom certificate handling runs.

If your network requires additional corporate CA certificates:

1. Put both PEM-encoded CA certificate files in this directory:
   - corp-intermediate.crt
   - corp-root.crt

2. Rebuild the dev container. The certificates are detected and installed
   automatically.

You can override auto-detection by setting ELEVADR_USE_CORP_CA=true or
ELEVADR_USE_CORP_CA=false in the host environment before rebuilding the
dev container. Explicitly enabling support requires both certificate files.

Do not commit private or environment-specific certificate files unless your
organization's distribution policy explicitly allows it.
