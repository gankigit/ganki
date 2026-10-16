"""Summarise the Downloads folder by kind of file. Read-only: names and sizes only."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

MAX_ENTRIES = 200_000  # stop on absurdly large folders instead of freezing

# (key, suffixes). Order matters: the first matching group wins.
GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("archives", (".zip", ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".tar", ".7z", ".rar", ".gz")),
    ("images", (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".heic")),
    ("installers", (".deb", ".appimage", ".rpm", ".run", ".snap", ".flatpakref")),
    ("pdf", (".pdf",)),
    (
        "documents",
        (".doc", ".docx", ".odt", ".xls", ".xlsx", ".ods", ".ppt", ".pptx", ".odp", ".txt", ".csv"),
    ),
)


@dataclass(frozen=True)
class DownloadGroup:
    key: str  # one of GROUPS' keys, or "other"
    files: int
    size_bytes: int


def classify(filename: str) -> str:
    lower = filename.lower()
    for key, suffixes in GROUPS:
        if lower.endswith(suffixes):
            return key
    return "other"


def downloads_dir(home: Path | None = None) -> Path:
    """The user's Downloads folder (from ``user-dirs.dirs``), else ``~/Downloads``."""
    base = home or Path.home()
    try:
        for line in (base / ".config" / "user-dirs.dirs").read_text().splitlines():
            if line.startswith("XDG_DOWNLOAD_DIR="):
                value = line.split("=", 1)[1].strip().strip('"').replace("$HOME", str(base))
                path = Path(value)
                if path.is_absolute() and path.is_relative_to(base):
                    return path
    except OSError:
        pass
    return base / "Downloads"


def scan_downloads(folder: Path) -> list[DownloadGroup]:
    """Count files and bytes per kind, biggest first. Symlinks are never followed."""
    counts: dict[str, list[int]] = {}
    seen = 0
    for root, _dirs, names in os.walk(folder, followlinks=False):
        for name in names:
            seen += 1
            if seen > MAX_ENTRIES:
                break
            try:
                info = os.lstat(os.path.join(root, name))
            except OSError:
                continue
            if not os.path.isfile(os.path.join(root, name)) or os.path.islink(
                os.path.join(root, name)
            ):
                continue
            entry = counts.setdefault(classify(name), [0, 0])
            entry[0] += 1
            entry[1] += info.st_size
        if seen > MAX_ENTRIES:
            break
    groups = [DownloadGroup(key, files, size) for key, (files, size) in counts.items()]
    return sorted(groups, key=lambda g: -g.size_bytes)
