"""Projection failure distinctions shared by ecosystem adapters."""


class ProjectionUnavailable(ValueError):
    """The journal has not recorded the facts required by an export contract."""
