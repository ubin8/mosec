from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath
from typing import Iterable


class DiscoveryError(ValueError):
    pass


DEFAULT_EXCLUDE_PATTERNS: tuple[str, ...] = (
    "**/.git/**",
    "**/__pycache__/**",
    "**/node_modules/**",
    "**/dist/**",
    "**/build/**",
    "**/target/**",
)

BINARY_SUFFIXES: tuple[str, ...] = (
    ".pyc",
    ".class",
    ".dll",
    ".exe",
    ".gif",
    ".jpg",
    ".jpeg",
    ".o",
    ".png",
    ".so",
    ".wasm",
    ".zip",
)


@dataclass(slots=True, frozen=True)
class DiscoveredFile:
    path: Path
    relative_path: str
    size: int


@dataclass(slots=True)
class DiscoveryResult:
    root: Path
    files_seen: int = 0
    files_selected: int = 0
    selected_files: list[DiscoveredFile] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _matches_any(relative_path: str, patterns: Iterable[str]) -> bool:
    candidate = PurePosixPath(relative_path)
    return any(candidate.match(pattern) or fnmatch(relative_path, pattern) for pattern in patterns)


def _is_binary_file(path: Path) -> bool:
    if path.suffix.lower() in BINARY_SUFFIXES:
        return True

    try:
        sample = path.read_bytes()[:4096]
    except OSError as exc:
        raise DiscoveryError(f"failed to read file: {path}") from exc

    if not sample:
        return False

    if b"\0" in sample:
        return True

    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return True

    return False


def discover_files(
    root: Path,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
    max_noise: bool = False,
    fail_fast: bool = False,
) -> DiscoveryResult:
    expanded = root.expanduser()
    resolved = expanded.resolve()
    if not resolved.exists():
        raise DiscoveryError(f"scan path does not exist: {resolved}")

    include_patterns = [pattern for pattern in (include_patterns or []) if pattern.strip()]
    exclude_patterns = [pattern for pattern in (exclude_patterns or []) if pattern.strip()]
    all_excludes = list(DEFAULT_EXCLUDE_PATTERNS) + exclude_patterns

    result = DiscoveryResult(root=resolved)
    if expanded.is_symlink():
        result.notes.append(f"scan root is a symlink; resolved to {resolved}")

    if resolved.is_file():
        result.files_seen = 1
        relative_path = resolved.name
        if include_patterns and not _matches_any(relative_path, include_patterns):
            if max_noise:
                result.notes.append(f"excluded by include filter: {relative_path}")
            return result
        if _matches_any(relative_path, all_excludes):
            if max_noise:
                result.notes.append(f"excluded by exclude filter: {relative_path}")
            return result
        if resolved.stat().st_size == 0:
            if max_noise:
                result.notes.append(f"skipped empty file: {relative_path}")
            return result
        try:
            is_binary = _is_binary_file(resolved)
        except DiscoveryError as exc:
            if fail_fast:
                raise
            result.notes.append(str(exc))
            return result
        if is_binary:
            if max_noise:
                result.notes.append(f"skipped binary file: {relative_path}")
            return result
        result.selected_files.append(
            DiscoveredFile(path=resolved, relative_path=relative_path, size=resolved.stat().st_size)
        )
        result.files_selected = 1
        return result

    candidates = sorted(
        path for path in resolved.rglob("*") if path.is_file()
    )

    for path in candidates:
        result.files_seen += 1
        relative_path = path.relative_to(resolved).as_posix()

        if path.is_symlink():
            result.notes.append(f"skipped symlink: {relative_path}")
            continue
        if include_patterns and not _matches_any(relative_path, include_patterns):
            if max_noise:
                result.notes.append(f"excluded by include filter: {relative_path}")
            continue
        if _matches_any(relative_path, all_excludes):
            if max_noise:
                result.notes.append(f"excluded by exclude filter: {relative_path}")
            continue
        if path.stat().st_size == 0:
            if max_noise:
                result.notes.append(f"skipped empty file: {relative_path}")
            continue
        try:
            is_binary = _is_binary_file(path)
        except DiscoveryError as exc:
            if fail_fast:
                raise
            result.notes.append(str(exc))
            continue
        if is_binary:
            if max_noise:
                result.notes.append(f"skipped binary file: {relative_path}")
            continue

        result.selected_files.append(
            DiscoveredFile(
                path=path,
                relative_path=relative_path,
                size=path.stat().st_size,
            )
        )

    result.files_selected = len(result.selected_files)
    return result
