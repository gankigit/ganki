# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Tests for estimating recoverable space."""

from ganki import cleanup
from ganki.collectors.apt import Package


def pkg(name, size):
    return Package(name, "1", "amd64", size, "")


KERNELS = [
    pkg("linux-image-6.8.0-137-generic", 14000),
    pkg("linux-image-6.8.0-90-generic", 14000),
    pkg("linux-modules-6.8.0-90-generic", 38000),
    pkg("linux-headers-6.8.0-56", 83000),
    pkg("linux-generic", 20),  # meta package: never counted
    pkg("bash", 1500),
]


def test_old_kernel_packages_exclude_the_running_one_and_other_software():
    names = [p.name for p in cleanup.old_kernel_packages(KERNELS, "6.8.0-137-generic")]
    assert names == [
        "linux-image-6.8.0-90-generic",
        "linux-modules-6.8.0-90-generic",
        "linux-headers-6.8.0-56",
    ]


def test_without_a_known_running_kernel_nothing_is_old():
    assert cleanup.old_kernel_packages(KERNELS, "") == []


def test_apt_cache_counts_only_deb_files(tmp_path):
    (tmp_path / "a.deb").write_bytes(b"x" * 2048)
    (tmp_path / "b.deb").write_bytes(b"x" * 1024)
    (tmp_path / "lock").write_bytes(b"x" * 9999)
    (tmp_path / "partial").mkdir()
    assert cleanup.apt_cache_kib(tmp_path) == 3
    assert cleanup.apt_cache_kib(tmp_path / "missing") == 0


def test_parse_autoremove_reads_remv_lines():
    output = "Reading...\nRemv libold1 [1.0]\nRemv other:amd64 [2]\nInst x [1]\n"
    assert cleanup.parse_autoremove(output) == ["libold1", "other:amd64"]


def test_estimate_adds_up_the_three_sources(tmp_path, monkeypatch):
    monkeypatch.setattr(cleanup, "orphan_packages", lambda: ["bash"])
    monkeypatch.setattr(cleanup, "apt_cache_kib", lambda: 700)
    result = cleanup.estimate(KERNELS, "6.8.0-137-generic")
    assert result.old_kernel_kib == 14000 + 38000 + 83000
    assert (result.apt_cache_kib, result.orphan_kib) == (700, 1500)
    assert result.total_kib == 135000 + 700 + 1500


def test_failing_simulation_gives_no_orphans(monkeypatch):
    def boom(*_a, **_k):
        raise OSError("no apt-get here")

    monkeypatch.setattr(cleanup, "run", boom)
    assert cleanup.orphan_packages() == []
