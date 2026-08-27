Corporate CA certificates (optional)
====================================

By default, no custom certificate handling runs.

If your network requires additional corporate CA certificates:

1. Put the following PEM-encoded CA certificate files in this directory:
   - corp-intermediate.crt
   - corp-root.crt

2. Edit .devcontainer/post-create.sh and change:

     ELEVADR_USE_CORP_CA=false

   to:

     ELEVADR_USE_CORP_CA=true

3. Rebuild the dev container.

When the flag is true, post-create.sh installs these certificates into the
Linux system trust store and configures Python/Node tooling to use that trust.

Do not commit private or environment-specific certificate files unless your
organization's distribution policy explicitly allows it.
