"""The list of installed tools with one status each: vulnerable, outdated or up to date."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from ganki import debversion
from ganki.collectors.apt import Package
from ganki.collectors.updates import Update
from ganki.osv import PRIORITY_ORDER, Finding

VULNERABLE, OUTDATED, OK = "vulnerable", "outdated", "ok"
_STATE_RANK = {VULNERABLE: 0, OUTDATED: 1, OK: 2}
_UNKNOWN = len(PRIORITY_ORDER)
MAX_CVE_LINES = 5  # most urgent CVEs shown per tool


@dataclass(frozen=True)
class CveLine:
    cve_id: str
    priority: str
    summary: str
    fixed_version: str | None
    status: str  # fix_available / fix_with_pro / no_fix


@dataclass(frozen=True)
class Tool:
    name: str
    version: str
    size_kib: int
    description: str
    manual: bool  # installed on purpose (True) or pulled in as a dependency (False)
    state: str  # VULNERABLE, OUTDATED or OK
    update_to: str | None = None  # newer version available from the repositories
    cve_count: int = 0
    top_priority: str = ""
    fixable: int = 0  # CVEs fixed by updating (or by Ubuntu Pro)
    unfixable: int = 0  # CVEs with no fix published yet
    fixed_in: str | None = None  # version that fixes everything fixable
    cves: tuple[CveLine, ...] = ()


def _rank(priority: str) -> int:
    return PRIORITY_ORDER.get(priority, _UNKNOWN)


def build_tools(
    packages: list[Package], findings: list[Finding], updates: list[Update]
) -> list[Tool]:
    """One ``Tool`` per installed package, most urgent first."""
    by_name: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        for name in finding.packages:
            by_name[name].append(finding)
    pending = {u.name: u.candidate_version for u in updates}

    tools = []
    for pkg in packages:
        found = by_name.get(pkg.name, [])
        candidate = pending.get(pkg.name.split(":")[0])
        if found:
            state = VULNERABLE
        elif candidate:
            state = OUTDATED
        else:
            state = OK
        unique: dict[str, Finding] = {}
        for item in sorted(found, key=lambda f: (_rank(f.priority), f.cve_id)):
            unique.setdefault(item.cve_id, item)
        fixes = [f.fixed_version for f in unique.values() if f.fixed_version]
        fixed_in = None
        for version in fixes:
            if fixed_in is None or debversion.compare(version, fixed_in) > 0:
                fixed_in = version
        tools.append(
            Tool(
                name=pkg.name,
                version=pkg.version,
                size_kib=pkg.size_kib,
                description=pkg.description,
                manual=pkg.manual,
                state=state,
                update_to=candidate,
                cve_count=len(unique),
                top_priority=min((f.priority for f in unique.values()), key=_rank, default=""),
                fixable=sum(1 for f in unique.values() if f.status != "no_fix"),
                unfixable=sum(1 for f in unique.values() if f.status == "no_fix"),
                fixed_in=fixed_in,
                cves=tuple(
                    CveLine(f.cve_id, f.priority, f.summary, f.fixed_version, f.status)
                    for f in list(unique.values())[:MAX_CVE_LINES]
                ),
            )
        )
    return sorted(
        tools,
        key=lambda t: (_STATE_RANK[t.state], _rank(t.top_priority), -t.cve_count, t.name),
    )
