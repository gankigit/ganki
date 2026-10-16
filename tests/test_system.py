# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Tests for reading facts about the machine."""

from ganki.system import SystemInfo, parse_meminfo, parse_uptime, read_system


def test_parse_meminfo_uses_available_memory():
    text = "MemTotal:       16000000 kB\nMemFree: 100 kB\nMemAvailable:   10000000 kB\n"
    assert parse_meminfo(text) == (16000000, 6000000)


def test_parse_meminfo_survives_garbage():
    assert parse_meminfo("nonsense\n\nMemTotal: x kB") == (0, 0)


def test_parse_uptime():
    assert parse_uptime("273600.55 1000.0\n") == 273600
    assert parse_uptime("") == 0
    assert parse_uptime("abc") == 0


def test_read_system_reads_files_and_tolerates_missing_ones(tmp_path):
    (tmp_path / "os-release").write_text('PRETTY_NAME="Test OS 1.0"\n')
    (tmp_path / "meminfo").write_text("MemTotal: 2000 kB\nMemAvailable: 500 kB\n")
    (tmp_path / "uptime").write_text("90.0 1.0\n")
    flag = tmp_path / "reboot-required"
    flag.write_text("")
    info = read_system(tmp_path / "os-release", tmp_path, str(tmp_path), flag)
    assert info.os_name == "Test OS 1.0"
    assert (info.ram_total_kib, info.ram_used_kib, info.uptime_seconds) == (2000, 1500, 90)
    assert info.reboot_required is True
    assert (
        read_system(tmp_path / "missing", tmp_path / "none", "/", tmp_path / "no").os_name
        == "Linux"
    )


def test_percentages_and_free_space():
    info = SystemInfo("os", "k", "x", "u", 0, 1000, 250, 400, 100, False)
    assert (info.disk_percent, info.disk_free, info.ram_percent) == (25, 750, 25)
    empty = SystemInfo("os", "k", "x", "u", 0, 0, 0, 0, 0, False)
    assert (empty.disk_percent, empty.ram_percent) == (0, 0)
