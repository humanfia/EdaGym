# Open EDA runtime image

This image is the rootless execution substrate for participant-controlled open
EDA tasks. The Containerfile fixes the base image digest and every directly
requested package version. It also records the complete installed Debian
package manifest and its SHA-256 digest inside `/usr/share/edagym`.

The Ubuntu package repositories are not snapshot-pinned. The Containerfile is
therefore an auditable build recipe, not a claim that a later build will be
byte-for-byte identical or that these package versions will remain available.
Every released environment binds the resulting OCI manifest digest and uses a
local `repository@sha256:...` reference with pulling disabled.
