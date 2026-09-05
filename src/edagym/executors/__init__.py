"""Execution providers and their typed protocol.

Import concrete providers from their owning modules. Keeping this package boundary
free of eager imports prevents provider implementations from becoming a dependency
of shared executor protocols.
"""
