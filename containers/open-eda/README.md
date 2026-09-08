# User-supplied EDA runtime

EdaGym does not build or distribute an EDA runtime image. Supply an image that
you already own, record its immutable OCI digest in a private configuration,
and grant only the task-specific tool and library view to the rootless
executor. The framework never pulls, updates, or installs software in that
image.

The image must satisfy the runtime contract documented in
`docs/environment-contract.md`. Keep its package inventory and installation
paths outside the repository and outside public reports.
