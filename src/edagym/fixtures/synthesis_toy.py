"""External asset identities used by synthesis qualification fixtures.

The actual Liberty data is supplied by the user through a private asset
registry. This module intentionally contains identifiers only.
"""

from __future__ import annotations

SYNTHESIS_LIBRARY_ASSET_ID = "synthesis_reference_library"
SYNTHESIS_LIBRARY_PATH = "technology/cells.lib"

__all__ = ["SYNTHESIS_LIBRARY_ASSET_ID", "SYNTHESIS_LIBRARY_PATH"]
