"""Helpers for comparing physical device addresses."""

from __future__ import annotations

import re


def canonical_mac(value: str | None) -> str | None:
    """Return a comparable 12-digit MAC, or None for non-MAC identifiers."""
    if not isinstance(value, str):
        return None
    compact = value.replace(":", "").replace("-", "")
    if not re.fullmatch(r"[0-9a-fA-F]{12}", compact):
        return None
    return compact.lower()


def same_mac(first: str | None, second: str | None) -> bool:
    """Match only valid identical MACs, ignoring case and separators."""
    canonical = canonical_mac(first)
    return canonical is not None and canonical == canonical_mac(second)
