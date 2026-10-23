"""SAP error types."""
from __future__ import annotations


class SAPError(Exception):
    """Anything that went wrong while preparing or producing a SAP signature."""


class SAPUnavailableError(SAPError):
    """The ``unicorn`` emulator package isn't installed on this machine."""
