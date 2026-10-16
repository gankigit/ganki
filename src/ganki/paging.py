"""Slice a list into pages, and format sizes for people."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")
PAGE_SIZE = 50


@dataclass(frozen=True)
class Page(Generic[T]):  # noqa: UP046 - kept compatible with Python 3.10
    items: list[T]
    number: int  # 1-based
    pages: int
    total: int


def paginate(items: list[T], number: int = 1, size: int = PAGE_SIZE) -> Page[T]:
    """One page of ``items``; out-of-range page numbers are clamped."""
    pages = max(1, -(-len(items) // size))
    number = min(max(number, 1), pages)
    start = (number - 1) * size
    return Page(items[start : start + size], number, pages, len(items))


def human_size(kib: int) -> str:
    """``1536`` -> ``1.5 MiB``."""
    value = float(kib)
    for unit in ("KiB", "MiB", "GiB"):
        if value < 1024:
            return f"{value:.0f} {unit}" if unit == "KiB" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"
