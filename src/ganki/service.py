"""One full scan of this machine: what is installed, what is affected, what can be updated.

Shared by the command-line scan and the web dashboard so both show the same data.
Everything is read-only and local; the only network access is the public
vulnerability feed download in ``feed.refresh``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ganki import cleanup
from ganki import downloads as downloads_mod
from ganki.collectors.apt import collect
from ganki.collectors.updates import collect_updates
from ganki.feed import refresh
from ganki.osv import Finding, find_findings, is_snap_stub, load_advisories
from ganki.release import detect_ecosystem
from ganki.summary import PackageRisk, summarize
from ganki.system import SystemInfo, read_system
from ganki.tools import Tool, build_tools


@dataclass(frozen=True)
class ScanResult:
    """Everything one scan found."""

    ecosystem: str
    feed_downloaded: bool  # True when a newer feed was downloaded for this scan
    feed_date: str  # the feed's Last-Modified, as the server reported it ("" if unknown)
    findings: list[Finding]
    risks: list[PackageRisk]
    snap_stubs: list[str]  # placeholder packages whose real app is a snap (not checked)
    pending_updates: int
    scanned_at: datetime
    system: SystemInfo | None = None
    reclaimable: cleanup.Reclaimable = field(default_factory=cleanup.Reclaimable)
    download_groups: list[downloads_mod.DownloadGroup] = field(default_factory=list)
    downloads_folder: str = ""  # shown as "~/Descargas", never the full home path
    tools: list[Tool] = field(default_factory=list)


def run_scan() -> ScanResult:
    """Download the feed if it changed, then match it against the installed packages.

    Raises ``UnsupportedReleaseError`` on systems the feed does not cover.
    """
    ecosystem = detect_ecosystem()
    status = refresh()
    index = load_advisories(status.path, ecosystem)
    packages = collect()
    findings = find_findings(packages, index)
    updates = collect_updates()
    system = read_system()
    folder = downloads_mod.downloads_dir()
    return ScanResult(
        ecosystem=ecosystem,
        feed_downloaded=status.downloaded,
        feed_date=status.last_modified or "",
        findings=findings,
        risks=summarize(findings, os.uname().release),
        snap_stubs=sorted(
            {p.name for p in packages if is_snap_stub(p.source_version or p.version)}
        ),
        pending_updates=len(updates),
        scanned_at=datetime.now(timezone.utc),
        system=system,
        reclaimable=cleanup.estimate(packages, system.kernel),
        download_groups=downloads_mod.scan_downloads(folder),
        downloads_folder="~/" + folder.name,
        tools=build_tools(packages, findings, updates),
    )
