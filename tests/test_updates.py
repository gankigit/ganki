# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Tests for the updates collector and the command runner (no real system access)."""

import pytest

from ganki.collectors.updates import last_index_refresh, parse_upgradable
from ganki.runner import CommandNotAllowedError, run

SAMPLE = """Listing...
bash/noble-updates 5.2.21-2ubuntu4.1 amd64 [upgradable from: 5.2.21-2ubuntu4]
openssl/noble-updates,noble-security 3.0.13-0ubuntu3.6 amd64 [upgradable from: 3.0.13-0ubuntu3.5]
libfoo/noble 1.0 all [upgradable from: 0.9]
this line is not a package
"""


def test_header_and_garbage_are_ignored():
    names = [u.name for u in parse_upgradable(SAMPLE)]
    assert names == ["bash", "openssl", "libfoo"]


def test_versions_and_arch_are_parsed():
    bash = parse_upgradable(SAMPLE)[0]
    assert bash.current_version == "5.2.21-2ubuntu4"
    assert bash.candidate_version == "5.2.21-2ubuntu4.1"
    assert bash.architecture == "amd64"


def test_security_pocket_is_detected():
    flags = {u.name: u.is_security for u in parse_upgradable(SAMPLE)}
    assert flags == {"bash": False, "openssl": True, "libfoo": False}


def test_empty_output_gives_no_updates():
    assert parse_upgradable("Listing...\n") == []


def test_last_index_refresh_reads_mtime(tmp_path):
    stamp = tmp_path / "update-success-stamp"
    stamp.write_text("")
    result = last_index_refresh(stamp)
    assert result is not None
    assert result.tzinfo is not None


def test_last_index_refresh_missing_file_returns_none(tmp_path):
    assert last_index_refresh(tmp_path / "missing") is None


@pytest.mark.parametrize(
    "command",
    [
        ["rm", "-rf", "/"],
        ["/bin/sh", "-c", "echo hi"],
        ["/usr/bin/apt-get", "remove", "bash"],
        [],
    ],
)
def test_runner_rejects_commands_not_on_the_allowlist(command):
    with pytest.raises(CommandNotAllowedError):
        run(command)


def test_apt_get_is_limited_to_the_simulated_autoremove():
    from ganki import runner

    for args in (
        ["/usr/bin/apt-get", "remove", "bash"],
        ["/usr/bin/apt-get", "autoremove"],
        ["/usr/bin/apt-get", "-s", "remove", "bash"],
        ["/usr/bin/apt-get", "-s", "autoremove", "--purge"],
        ["/usr/bin/apt-get"],
    ):
        with pytest.raises(runner.CommandNotAllowedError):
            runner.run(args)


def test_apt_get_simulated_autoremove_is_allowed(monkeypatch):
    from ganki import runner

    seen = []

    def fake(args, **_kwargs):
        seen.append(args)

        class Done:
            stdout = "ok"

        return Done()

    monkeypatch.setattr(runner.subprocess, "run", fake)
    assert runner.run([runner.APT_GET, "-s", "autoremove"]) == "ok"
    assert seen == [[runner.APT_GET, "-s", "autoremove"]]
