"""Facts about this machine: system, uptime, disk and memory (read-only, from /proc and the OS)."""

from __future__ import annotations

import getpass
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from ganki.release import OS_RELEASE, parse_os_release

REBOOT_FLAG = Path("/var/run/reboot-required")


@dataclass(frozen=True)
class SystemInfo:
    os_name: str
    kernel: str  # running kernel release, e.g. "6.8.0-137-generic"
    architecture: str
    user: str
    uptime_seconds: int
    disk_total: int  # bytes
    disk_used: int
    ram_total_kib: int
    ram_used_kib: int
    reboot_required: bool

    @property
    def disk_free(self) -> int:
        return self.disk_total - self.disk_used

    @property
    def disk_percent(self) -> int:
        return round(100 * self.disk_used / self.disk_total) if self.disk_total else 0

    @property
    def ram_percent(self) -> int:
        return round(100 * self.ram_used_kib / self.ram_total_kib) if self.ram_total_kib else 0


def parse_meminfo(text: str) -> tuple[int, int]:
    """(total, used) in KiB from ``/proc/meminfo``; used = total - available."""
    values: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        parts = rest.split()
        if parts and parts[0].isdigit():
            values[key] = int(parts[0])
    total = values.get("MemTotal", 0)
    return total, max(0, total - values.get("MemAvailable", total))


def parse_uptime(text: str) -> int:
    """Seconds since boot from ``/proc/uptime`` (0 if unreadable)."""
    try:
        return int(float(text.split()[0]))
    except (IndexError, ValueError):
        return 0


def _read(path: Path) -> str:
    try:
        return path.read_text()
    except OSError:
        return ""


def read_system(
    os_release: Path = OS_RELEASE,
    proc: Path = Path("/proc"),
    disk_path: str = "/",
    reboot_flag: Path = REBOOT_FLAG,
) -> SystemInfo:
    """Collect the facts. Anything unreadable becomes a neutral value, never an error."""
    release = parse_os_release(_read(os_release))
    total_kib, used_kib = parse_meminfo(_read(proc / "meminfo"))
    disk = shutil.disk_usage(disk_path)
    uname = os.uname()
    try:
        user = getpass.getuser()
    except (KeyError, OSError):
        user = ""
    return SystemInfo(
        os_name=release.get("PRETTY_NAME") or release.get("NAME") or "Linux",
        kernel=uname.release,
        architecture=uname.machine,
        user=user,
        uptime_seconds=parse_uptime(_read(proc / "uptime")),
        disk_total=disk.total,
        disk_used=disk.used,
        ram_total_kib=total_kib,
        ram_used_kib=used_kib,
        reboot_required=reboot_flag.exists(),
    )
