"""Estimate how much space could be recovered. Read-only: nothing is removed here."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ganki.collectors.apt import Package
from ganki.runner import APT_GET, run

APT_CACHE = Path("/var/cache/apt/archives")
_KERNEL_PACKAGE = re.compile(
    r"^linux-(?:image|modules|modules-extra|headers|tools)-(\d+\.\d+\.\d+-\d+)"
)
_REMOVE_LINE = re.compile(r"^Remv\s+(\S+)")


@dataclass(frozen=True)
class Reclaimable:
    old_kernel_kib: int = 0
    old_kernel_packages: list[str] = field(default_factory=list)
    apt_cache_kib: int = 0
    orphan_kib: int = 0
    orphan_packages: list[str] = field(default_factory=list)

    @property
    def total_kib(self) -> int:
        return self.old_kernel_kib + self.apt_cache_kib + self.orphan_kib


def running_abi(release: str) -> str | None:
    """``6.8.0-137-generic`` -> ``6.8.0-137``."""
    match = re.match(r"^(\d+\.\d+\.\d+-\d+)", release)
    return match.group(1) if match else None


def old_kernel_packages(packages: list[Package], running_release: str) -> list[Package]:
    """Kernel packages (image, modules, headers, tools) of versions that are not running."""
    abi = running_abi(running_release)
    if abi is None:
        return []
    found = []
    for pkg in packages:
        match = _KERNEL_PACKAGE.match(pkg.name)
        if match and match.group(1) != abi:
            found.append(pkg)
    return found


def apt_cache_kib(directory: Path = APT_CACHE) -> int:
    """Size of the downloaded .deb files apt keeps (they can be deleted safely)."""
    total = 0
    try:
        for entry in directory.iterdir():
            if entry.suffix == ".deb" and entry.is_file() and not entry.is_symlink():
                total += entry.stat().st_size
    except OSError:
        return 0
    return total // 1024


def parse_autoremove(output: str) -> list[str]:
    """Package names from ``apt-get -s autoremove`` (``Remv name [version]`` lines)."""
    return [m[1] for line in output.splitlines() if (m := _REMOVE_LINE.match(line))]


def orphan_packages() -> list[str]:
    """Packages nothing needs any more, according to a simulated ``autoremove``."""
    try:
        return parse_autoremove(run([APT_GET, "-s", "autoremove"]))
    except Exception:  # an unavailable simulation must not break the dashboard
        return []


def estimate(packages: list[Package], running_release: str) -> Reclaimable:
    """Combine the three sources of recoverable space."""
    old = old_kernel_packages(packages, running_release)
    orphans = orphan_packages()
    sizes = {p.name: p.size_kib for p in packages}
    return Reclaimable(
        old_kernel_kib=sum(p.size_kib for p in old),
        old_kernel_packages=[p.name for p in old],
        apt_cache_kib=apt_cache_kib(),
        orphan_kib=sum(sizes.get(name, 0) for name in orphans),
        orphan_packages=orphans,
    )
