"""Shared runtime orchestration failures."""


class OrchestrationError(RuntimeError):
    """A bound runtime component violates the resolved run contract."""
