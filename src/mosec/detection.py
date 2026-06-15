from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from .ingestion import DiscoveredFile


class Language(StrEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    KOTLIN = "kotlin"
    PHP = "php"
    JSON = "json"
    TOML = "toml"
    XML = "xml"
    TEXT = "text"
    UNKNOWN = "unknown"


class Framework(StrEnum):
    DJANGO = "django"
    FLASK = "flask"
    FASTAPI = "fastapi"
    SPRING = "spring"
    LARAVEL = "laravel"
    EXPRESS = "express"
    NEXTJS = "nextjs"
    REACT = "react"
    REACT_NATIVE = "react_native"
    ANDROID = "android"
    IOS = "ios"
    UNKNOWN = "unknown"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(slots=True, frozen=True)
class FileClassification:
    path: Path
    relative_path: str
    language: Language
    framework: Framework | None = None
    confidence: Confidence = Confidence.MEDIUM
    signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "relative_path": self.relative_path,
            "language": self.language.value,
            "framework": None if self.framework is None else self.framework.value,
            "confidence": self.confidence.value,
            "signals": list(self.signals),
        }


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _detect_language(file: DiscoveredFile) -> tuple[Language, list[str]]:
    path = file.relative_path.lower()
    signals: list[str] = []

    if path.endswith(".py") or path in {"manage.py", "setup.py"}:
        signals.append("extension:python")
        return Language.PYTHON, signals
    if path.endswith((".jsx", ".js", ".mjs", ".cjs")):
        signals.append("extension:javascript")
        return Language.JAVASCRIPT, signals
    if path.endswith((".ts", ".tsx")):
        signals.append("extension:typescript")
        return Language.TYPESCRIPT, signals
    if path.endswith(".java"):
        signals.append("extension:java")
        return Language.JAVA, signals
    if path.endswith(".kt"):
        signals.append("extension:kotlin")
        return Language.KOTLIN, signals
    if path.endswith(".php"):
        signals.append("extension:php")
        return Language.PHP, signals
    if path.endswith(".json") or path.endswith("package.json"):
        signals.append("extension:json")
        return Language.JSON, signals
    if path.endswith(".toml"):
        signals.append("extension:toml")
        return Language.TOML, signals
    if path.endswith(".xml") or path.endswith(".plist"):
        signals.append("extension:xml")
        return Language.XML, signals
    if path.endswith(".txt"):
        signals.append("extension:text")
        return Language.TEXT, signals

    return Language.UNKNOWN, signals


def _detect_framework_from_python(content: str, relative_path: str) -> tuple[Framework | None, Confidence, list[str]]:
    lowered = content.lower()
    path = relative_path.lower()
    signals: list[str] = []

    if "django" in lowered or any(token in path for token in ("manage.py", "settings.py", "urls.py", "wsgi.py", "asgi.py")):
        signals.append("python:django")
        return Framework.DJANGO, Confidence.HIGH, signals
    if "from flask import" in lowered or "import flask" in lowered:
        signals.append("python:flask")
        return Framework.FLASK, Confidence.HIGH, signals
    if "fastapi" in lowered or "from fastapi import" in lowered:
        signals.append("python:fastapi")
        return Framework.FASTAPI, Confidence.HIGH, signals
    return None, Confidence.LOW, signals


def _detect_framework_from_js(content: str, relative_path: str) -> tuple[Framework | None, Confidence, list[str]]:
    lowered = content.lower()
    path = relative_path.lower()
    signals: list[str] = []

    if "react-native" in lowered or "react-native" in path:
        signals.append("js:react-native")
        return Framework.REACT_NATIVE, Confidence.HIGH, signals
    if any(token in lowered for token in ("next/server", "next/navigation", "next/router", "next/headers")):
        signals.append("js:nextjs-import")
        return Framework.NEXTJS, Confidence.HIGH, signals
    if "next" in lowered and ("next" in path or "package.json" in path or "app/" in path or "pages/" in path):
        signals.append("js:nextjs")
        return Framework.NEXTJS, Confidence.MEDIUM, signals
    if "express" in lowered:
        signals.append("js:express")
        return Framework.EXPRESS, Confidence.HIGH, signals
    if "react" in lowered:
        signals.append("js:react")
        return Framework.REACT, Confidence.MEDIUM, signals
    return None, Confidence.LOW, signals


def _detect_framework_from_java(content: str, relative_path: str) -> tuple[Framework | None, Confidence, list[str]]:
    lowered = content.lower()
    path = relative_path.lower()
    signals: list[str] = []

    android_markers = (
        "android.content.sharedpreferences",
        "sharedpreferences",
        "androidx.",
        "import android.",
        "appcompatactivity",
        "fragmentactivity",
        "android.os.",
        "android.app.",
        "android.view.",
        "android.widget.",
        "androidx.appcompat",
    )
    if any(marker in lowered for marker in android_markers):
        signals.append("java:android")
        return Framework.ANDROID, Confidence.HIGH, signals

    spring_markers = (
        "org.springframework",
        "@restcontroller",
        "@controller",
        "@requestmapping",
        "@getmapping",
        "@postmapping",
        "@putmapping",
        "@deletemapping",
        "@patchmapping",
        "requestparam",
        "pathvariable",
        "requestbody",
        "requestheader",
    )
    if any(marker in lowered for marker in spring_markers) or "src/main/java" in path or "src/main/kotlin" in path:
        if any(marker in lowered for marker in spring_markers[:5]):
            signals.append("java:spring-controller")
            return Framework.SPRING, Confidence.HIGH, signals
        if any(marker in lowered for marker in spring_markers[5:]):
            signals.append("java:spring-request")
            return Framework.SPRING, Confidence.MEDIUM, signals
        if "src/main/java" in path or "src/main/kotlin" in path:
            signals.append("java:spring-path")
            return Framework.SPRING, Confidence.LOW, signals

    return None, Confidence.LOW, signals


def _detect_framework_from_php(content: str, relative_path: str) -> tuple[Framework | None, Confidence, list[str]]:
    lowered = content.lower()
    path = relative_path.lower()
    signals: list[str] = []

    laravel_markers = (
        "illuminate\\",
        "laravel",
        "route::",
        "request $request",
        "request $req",
        "request::",
        "redirect(",
        "storage::",
        "http::",
    )
    if any(marker in lowered for marker in laravel_markers) or any(
        token in path for token in ("routes/web.php", "routes/api.php", "app/http/controllers", "app/http/middleware", "app/http/requests")
    ):
        if any(marker in lowered for marker in ("route::", "illuminate\\", "laravel")):
            signals.append("php:laravel")
            return Framework.LARAVEL, Confidence.HIGH, signals
        if any(token in path for token in ("routes/web.php", "routes/api.php", "app/http/controllers", "app/http/middleware", "app/http/requests")):
            signals.append("php:laravel-path")
            return Framework.LARAVEL, Confidence.MEDIUM, signals

    return None, Confidence.LOW, signals


def _detect_framework_from_json(content: str, relative_path: str) -> tuple[Framework | None, Confidence, list[str]]:
    path = relative_path.lower()
    signals: list[str] = []

    if path.endswith("package.json"):
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            return None, Confidence.LOW, ["json:invalid-package-json"]
        dependencies = {}
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            bucket = parsed.get(key, {})
            if isinstance(bucket, dict):
                dependencies.update({str(dep).lower(): str(ver) for dep, ver in bucket.items()})

        if "react-native" in dependencies:
            signals.append("package-json:react-native")
            return Framework.REACT_NATIVE, Confidence.HIGH, signals
        if "next" in dependencies:
            signals.append("package-json:next")
            return Framework.NEXTJS, Confidence.HIGH, signals
        if "express" in dependencies:
            signals.append("package-json:express")
            return Framework.EXPRESS, Confidence.HIGH, signals
        if "react" in dependencies:
            signals.append("package-json:react")
            return Framework.REACT, Confidence.MEDIUM, signals

    return None, Confidence.LOW, signals


def _detect_framework_from_toml(content: str, relative_path: str) -> tuple[Framework | None, Confidence, list[str]]:
    lowered = content.lower()
    path = relative_path.lower()
    signals: list[str] = []

    if "django" in lowered:
        signals.append("toml:django")
        return Framework.DJANGO, Confidence.MEDIUM, signals
    if "flask" in lowered:
        signals.append("toml:flask")
        return Framework.FLASK, Confidence.MEDIUM, signals
    if "fastapi" in lowered:
        signals.append("toml:fastapi")
        return Framework.FASTAPI, Confidence.MEDIUM, signals
    if path.endswith("pyproject.toml") and "django" in path:
        signals.append("toml:path-django")
        return Framework.DJANGO, Confidence.LOW, signals

    return None, Confidence.LOW, signals


def _detect_framework_from_xml(content: str, relative_path: str) -> tuple[Framework | None, Confidence, list[str]]:
    lowered = content.lower()
    path = relative_path.lower()
    signals: list[str] = []

    if "androidmanifest.xml" in path or "android:" in lowered:
        signals.append("xml:android")
        return Framework.ANDROID, Confidence.HIGH, signals
    if path.endswith("info.plist") or "nsapptransportsecurity" in lowered:
        signals.append("xml:ios")
        return Framework.IOS, Confidence.HIGH, signals

    return None, Confidence.LOW, signals


def classify_file(file: DiscoveredFile) -> FileClassification:
    language, language_signals = _detect_language(file)
    content = _read_text(file.path)

    framework: Framework | None = None
    confidence = Confidence.LOW
    signals = list(language_signals)

    if language == Language.PYTHON:
        framework, confidence, framework_signals = _detect_framework_from_python(content, file.relative_path)
        signals.extend(framework_signals)
    elif language in {Language.JAVASCRIPT, Language.TYPESCRIPT}:
        framework, confidence, framework_signals = _detect_framework_from_js(content, file.relative_path)
        signals.extend(framework_signals)
    elif language in {Language.JAVA, Language.KOTLIN}:
        framework, confidence, framework_signals = _detect_framework_from_java(content, file.relative_path)
        signals.extend(framework_signals)
    elif language == Language.PHP:
        framework, confidence, framework_signals = _detect_framework_from_php(content, file.relative_path)
        signals.extend(framework_signals)
    elif language == Language.JSON:
        framework, confidence, framework_signals = _detect_framework_from_json(content, file.relative_path)
        signals.extend(framework_signals)
    elif language == Language.TOML:
        framework, confidence, framework_signals = _detect_framework_from_toml(content, file.relative_path)
        signals.extend(framework_signals)
    elif language == Language.XML:
        framework, confidence, framework_signals = _detect_framework_from_xml(content, file.relative_path)
        signals.extend(framework_signals)

    if framework is None:
        if language in {Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT, Language.JSON, Language.TOML, Language.XML}:
            confidence = Confidence.MEDIUM
        else:
            confidence = Confidence.LOW

    return FileClassification(
        path=file.path,
        relative_path=file.relative_path,
        language=language,
        framework=framework,
        confidence=confidence,
        signals=signals,
    )


def classify_files(files: list[DiscoveredFile]) -> list[FileClassification]:
    return [classify_file(file) for file in files]
