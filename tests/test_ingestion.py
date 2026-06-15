from pathlib import Path

import pytest

import appsec_cli.ingestion as ingestion
from appsec_cli.ingestion import discover_files


def test_discover_files_filters_binary_empty_and_excludes(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "keep.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "src" / "skip.pyc").write_bytes(b"\x00\x01")
    (tmp_path / "src" / "empty.py").write_text("", encoding="utf-8")
    (tmp_path / "src" / "nested").mkdir()
    (tmp_path / "src" / "nested" / "keep2.py").write_text("x = 1\n", encoding="utf-8")

    discovery = discover_files(
        tmp_path,
        include_patterns=["src/**"],
        exclude_patterns=["**/empty.py"],
    )

    assert discovery.files_seen == 4
    assert discovery.files_selected == 2
    assert [item.relative_path for item in discovery.selected_files] == [
        "src/keep.py",
        "src/nested/keep2.py",
    ]


def test_discover_files_supports_single_file(tmp_path: Path) -> None:
    file_path = tmp_path / "single.py"
    file_path.write_text("print('hello')\n", encoding="utf-8")

    discovery = discover_files(file_path)

    assert discovery.files_seen == 1
    assert discovery.files_selected == 1
    assert discovery.selected_files[0].relative_path == "single.py"


def test_discover_files_survives_read_errors(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "good.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "bad.py").write_text("print('bad')\n", encoding="utf-8")

    def fake_binary_probe(path: Path) -> bool:
        if path.name == "bad.py":
            raise ingestion.DiscoveryError(f"failed to read file: {path}")
        return False

    monkeypatch.setattr(ingestion, "_is_binary_file", fake_binary_probe)

    discovery = discover_files(tmp_path)

    assert discovery.files_seen == 2
    assert discovery.files_selected == 1
    assert any("failed to read file" in note for note in discovery.notes)


def test_discover_files_respects_max_noise(tmp_path: Path) -> None:
    (tmp_path / "good.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "empty.py").write_text("", encoding="utf-8")

    discovery = discover_files(tmp_path, max_noise=True)

    assert discovery.files_seen == 2
    assert discovery.files_selected == 1
    assert any("skipped empty file" in note for note in discovery.notes)


def test_discover_files_fail_fast_aborts_on_read_error(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "bad.py").write_text("print('bad')\n", encoding="utf-8")

    def fake_binary_probe(path: Path) -> bool:
        raise ingestion.DiscoveryError(f"failed to read file: {path}")

    monkeypatch.setattr(ingestion, "_is_binary_file", fake_binary_probe)

    with pytest.raises(ingestion.DiscoveryError):
        discover_files(tmp_path, fail_fast=True)


def test_discover_files_skips_symlinks_and_notes_root_symlink(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "keep.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "src" / "linked.py").symlink_to(tmp_path / "src" / "keep.py")
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(tmp_path / "src", target_is_directory=True)

    discovery = discover_files(linked_root)

    assert discovery.files_seen == 2
    assert discovery.files_selected == 1
    assert discovery.selected_files[0].relative_path == "keep.py"
    assert any("scan root is a symlink" in note for note in discovery.notes)
    assert any("skipped symlink: linked.py" in note for note in discovery.notes)
