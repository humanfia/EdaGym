"""Shared vocabulary for an external participant and trace boundary."""

from enum import StrEnum


class HumanizeSessionStrategy(StrEnum):
    FRESH = "fresh"
    STATEFUL = "stateful"
