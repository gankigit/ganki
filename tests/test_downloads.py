# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Tests for the Downloads folder summary."""

from ganki.downloads import classify, downloads_dir, scan_downloads


def test_classify_by_suffix_ignoring_case():
    assert classify("backup.TAR.GZ") == "archives"
    assert classify("photo.JPG") == "images"
    assert classify("setup.AppImage") == "installers"
    assert classify("book.pdf") == "pdf"
    assert classify("notes.docx") == "documents"
    assert classify("mystery.bin") == "other"


def test_scan_counts_files_and_bytes_per_group_biggest_first(tmp_path):
    (tmp_path / "a.zip").write_bytes(b"x" * 3000)
    (tmp_path / "b.png").write_bytes(b"x" * 100)
    (tmp_path / "c.png").write_bytes(b"x" * 100)
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "d.pdf").write_bytes(b"x" * 500)
    groups = scan_downloads(tmp_path)
    assert [(g.key, g.files, g.size_bytes) for g in groups] == [
        ("archives", 1, 3000),
        ("pdf", 1, 500),
        ("images", 2, 200),
    ]


def test_symlinks_are_not_followed_or_counted(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.zip").write_bytes(b"x" * 5000)
    folder = tmp_path / "dl"
    folder.mkdir()
    (folder / "link.zip").symlink_to(outside / "secret.zip")
    (folder / "linkdir").symlink_to(outside, target_is_directory=True)
    assert scan_downloads(folder) == []


def test_missing_folder_is_empty(tmp_path):
    assert scan_downloads(tmp_path / "nope") == []


def test_downloads_dir_reads_user_dirs_and_stays_inside_home(tmp_path):
    config = tmp_path / ".config"
    config.mkdir()
    (config / "user-dirs.dirs").write_text('XDG_DOWNLOAD_DIR="$HOME/Descargas"\n')
    assert downloads_dir(tmp_path) == tmp_path / "Descargas"
    (config / "user-dirs.dirs").write_text('XDG_DOWNLOAD_DIR="/etc"\n')
    assert downloads_dir(tmp_path) == tmp_path / "Downloads"
    assert downloads_dir(tmp_path / "other-home") == tmp_path / "other-home" / "Downloads"
