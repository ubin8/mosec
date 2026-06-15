from __future__ import annotations

import ast
import json
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from .detection import FileClassification, Language
from .ingestion import DiscoveredFile
from .ir import IRDocument, build_json_ir, build_python_ir, build_toml_ir, build_xml_ir
from .detection import Framework


class ParseSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(slots=True, frozen=True)
class ParseIssue:
    severity: ParseSeverity
    message: str
    line: int | None = None
    column: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "message": self.message,
            "line": self.line,
            "column": self.column,
        }


@dataclass(slots=True, frozen=True)
class ParsedDocument:
    path: Path
    relative_path: str
    language: Language
    framework: str | None
    syntax_valid: bool
    line_count: int
    character_count: int
    ir: IRDocument | None = None
    issues: list[ParseIssue] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "relative_path": self.relative_path,
            "language": self.language.value,
            "framework": self.framework,
            "syntax_valid": self.syntax_valid,
            "line_count": self.line_count,
            "character_count": self.character_count,
            "ir": None if self.ir is None else self.ir.to_dict(),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": dict(self.metadata),
        }


class Parser(Protocol):
    def parse(self, file: DiscoveredFile, classification: FileClassification) -> ParsedDocument:
        raise NotImplementedError


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _count_lines(text: str) -> int:
    if not text:
        return 0
    return text.count("\n") + 1


class PythonParser:
    def parse(self, file: DiscoveredFile, classification: FileClassification) -> ParsedDocument:
        text = _read_text(file.path)
        issues: list[ParseIssue] = []
        syntax_valid = True

        try:
            ast.parse(text, filename=str(file.path))
        except SyntaxError as exc:
            syntax_valid = False
            issues.append(
                ParseIssue(
                    severity=ParseSeverity.ERROR,
                    message=exc.msg,
                    line=exc.lineno,
                    column=exc.offset,
                )
            )

        return ParsedDocument(
            path=file.path,
            relative_path=file.relative_path,
            language=classification.language,
            framework=None if classification.framework is None else classification.framework.value,
            syntax_valid=syntax_valid,
            line_count=_count_lines(text),
            character_count=len(text),
            ir=build_python_ir(file.path, text),
            issues=issues,
            metadata={"parser": "python"},
        )


class JsonParser:
    def parse(self, file: DiscoveredFile, classification: FileClassification) -> ParsedDocument:
        text = _read_text(file.path)
        issues: list[ParseIssue] = []
        syntax_valid = True

        try:
            json.loads(text)
        except json.JSONDecodeError as exc:
            syntax_valid = False
            issues.append(
                ParseIssue(
                    severity=ParseSeverity.ERROR,
                    message=exc.msg,
                    line=exc.lineno,
                    column=exc.colno,
                )
            )

        return ParsedDocument(
            path=file.path,
            relative_path=file.relative_path,
            language=classification.language,
            framework=None if classification.framework is None else classification.framework.value,
            syntax_valid=syntax_valid,
            line_count=_count_lines(text),
            character_count=len(text),
            ir=build_json_ir(file.path, text),
            issues=issues,
            metadata={"parser": "json"},
        )


class TomlParser:
    def parse(self, file: DiscoveredFile, classification: FileClassification) -> ParsedDocument:
        text = _read_text(file.path)
        issues: list[ParseIssue] = []
        syntax_valid = True

        try:
            tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            syntax_valid = False
            issues.append(
                ParseIssue(
                    severity=ParseSeverity.ERROR,
                    message=str(exc),
                    line=getattr(exc, "lineno", None),
                    column=getattr(exc, "colno", None),
                )
            )

        return ParsedDocument(
            path=file.path,
            relative_path=file.relative_path,
            language=classification.language,
            framework=None if classification.framework is None else classification.framework.value,
            syntax_valid=syntax_valid,
            line_count=_count_lines(text),
            character_count=len(text),
            ir=build_toml_ir(file.path, text),
            issues=issues,
            metadata={"parser": "toml"},
        )


class XmlParser:
    def parse(self, file: DiscoveredFile, classification: FileClassification) -> ParsedDocument:
        text = _read_text(file.path)
        issues: list[ParseIssue] = []
        syntax_valid = True

        try:
            ET.fromstring(text)
        except ET.ParseError as exc:
            syntax_valid = False
            position = getattr(exc, "position", None)
            line = position[0] if position else None
            column = position[1] if position else None
            issues.append(
                ParseIssue(
                    severity=ParseSeverity.ERROR,
                    message=str(exc),
                    line=line,
                    column=column,
                )
            )

        return ParsedDocument(
            path=file.path,
            relative_path=file.relative_path,
            language=classification.language,
            framework=None if classification.framework is None else classification.framework.value,
            syntax_valid=syntax_valid,
            line_count=_count_lines(text),
            character_count=len(text),
            ir=build_xml_ir(file.path, text),
            issues=issues,
            metadata={"parser": "xml"},
        )


_ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _android_attr(element: ET.Element, name: str) -> str | None:
    value = element.attrib.get(f"{{{_ANDROID_NS}}}{name}")
    if value is not None:
        return value
    return element.attrib.get(name)


def _parse_android_component(element: ET.Element, component_kind: str) -> dict[str, Any]:
    name = _android_attr(element, "name")
    exported_raw = _android_attr(element, "exported")
    permission = _android_attr(element, "permission")
    intent_filters = element.findall("intent-filter")
    return {
        "kind": component_kind,
        "name": name,
        "exported": None if exported_raw is None else exported_raw.lower() == "true",
        "permission": permission,
        "intent_filter_count": len(intent_filters),
    }


_ANDROID_PERMISSION_TAGS = ("uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m")


def _parse_android_manifest_metadata(text: str) -> dict[str, Any]:
    root = ET.fromstring(text)
    if root.tag.split("}")[-1] != "manifest":
        return {}

    manifest: dict[str, Any] = {
        "package": root.attrib.get("package"),
        "shared_user_id": root.attrib.get("sharedUserId"),
        "uses_permissions": [],
        "uses_features": [],
        "application": {},
        "components": [],
    }

    uses_permissions: list[str] = []
    for tag in _ANDROID_PERMISSION_TAGS:
        for element in root.findall(tag):
            name = _android_attr(element, "name")
            if name:
                uses_permissions.append(name)
    manifest["uses_permissions"] = uses_permissions

    uses_features: list[str] = []
    for element in root.findall("uses-feature"):
        name = _android_attr(element, "name")
        if name:
            uses_features.append(name)
    manifest["uses_features"] = uses_features

    application = root.find("application")
    if application is not None:
        manifest["application"] = {
            "label": _android_attr(application, "label"),
            "debuggable": None if _android_attr(application, "debuggable") is None else _android_attr(application, "debuggable").lower() == "true",
            "allow_backup": None if _android_attr(application, "allowBackup") is None else _android_attr(application, "allowBackup").lower() == "true",
            "uses_cleartext_traffic": None if _android_attr(application, "usesCleartextTraffic") is None else _android_attr(application, "usesCleartextTraffic").lower() == "true",
        }
        for component_kind in ("activity", "activity-alias", "receiver", "service", "provider"):
            for element in application.findall(component_kind):
                manifest["components"].append(_parse_android_component(element, component_kind))

    return {"android_manifest": manifest}


class AndroidManifestParser(XmlParser):
    def parse(self, file: DiscoveredFile, classification: FileClassification) -> ParsedDocument:
        document = super().parse(file, classification)
        metadata = dict(document.metadata)
        issues = list(document.issues)
        if document.syntax_valid:
            text = _read_text(file.path)
            metadata.update(_parse_android_manifest_metadata(text))
        return ParsedDocument(
            path=document.path,
            relative_path=document.relative_path,
            language=document.language,
            framework=document.framework,
            syntax_valid=document.syntax_valid,
            line_count=document.line_count,
            character_count=document.character_count,
            ir=document.ir,
            issues=issues,
            metadata=metadata,
        )


class TextParser:
    def parse(self, file: DiscoveredFile, classification: FileClassification) -> ParsedDocument:
        text = _read_text(file.path)
        return ParsedDocument(
            path=file.path,
            relative_path=file.relative_path,
            language=classification.language,
            framework=None if classification.framework is None else classification.framework.value,
            syntax_valid=True,
            line_count=_count_lines(text),
            character_count=len(text),
            ir=IRDocument(path=file.path, metadata={"parser": "text", "syntax_valid": True}),
            issues=[],
            metadata={"parser": "text"},
        )


class JavaScriptParser(TextParser):
    def parse(self, file: DiscoveredFile, classification: FileClassification) -> ParsedDocument:
        document = super().parse(file, classification)
        return ParsedDocument(
            path=document.path,
            relative_path=document.relative_path,
            language=document.language,
            framework=document.framework,
            syntax_valid=True,
            line_count=document.line_count,
            character_count=document.character_count,
            issues=document.issues,
            metadata={"parser": "javascript"},
        )


class JavaParser(TextParser):
    def parse(self, file: DiscoveredFile, classification: FileClassification) -> ParsedDocument:
        document = super().parse(file, classification)
        return ParsedDocument(
            path=document.path,
            relative_path=document.relative_path,
            language=document.language,
            framework=document.framework,
            syntax_valid=True,
            line_count=document.line_count,
            character_count=document.character_count,
            issues=document.issues,
            metadata={"parser": "java"},
        )


class KotlinParser(TextParser):
    def parse(self, file: DiscoveredFile, classification: FileClassification) -> ParsedDocument:
        document = super().parse(file, classification)
        return ParsedDocument(
            path=document.path,
            relative_path=document.relative_path,
            language=document.language,
            framework=document.framework,
            syntax_valid=True,
            line_count=document.line_count,
            character_count=document.character_count,
            issues=document.issues,
            metadata={"parser": "kotlin"},
        )


class PhpParser(TextParser):
    def parse(self, file: DiscoveredFile, classification: FileClassification) -> ParsedDocument:
        document = super().parse(file, classification)
        return ParsedDocument(
            path=document.path,
            relative_path=document.relative_path,
            language=document.language,
            framework=document.framework,
            syntax_valid=True,
            line_count=document.line_count,
            character_count=document.character_count,
            issues=document.issues,
            metadata={"parser": "php"},
        )


class TypeScriptParser(TextParser):
    def parse(self, file: DiscoveredFile, classification: FileClassification) -> ParsedDocument:
        document = super().parse(file, classification)
        return ParsedDocument(
            path=document.path,
            relative_path=document.relative_path,
            language=document.language,
            framework=document.framework,
            syntax_valid=True,
            line_count=document.line_count,
            character_count=document.character_count,
            issues=document.issues,
            metadata={"parser": "typescript"},
        )


class ParserRegistry:
    def __init__(self) -> None:
        self._android_manifest_parser = AndroidManifestParser()
        self._parsers: dict[Language, Parser] = {
            Language.PYTHON: PythonParser(),
            Language.JAVASCRIPT: JavaScriptParser(),
            Language.TYPESCRIPT: TypeScriptParser(),
            Language.JAVA: JavaParser(),
            Language.KOTLIN: KotlinParser(),
            Language.PHP: PhpParser(),
            Language.JSON: JsonParser(),
            Language.TOML: TomlParser(),
            Language.XML: XmlParser(),
            Language.TEXT: TextParser(),
            Language.UNKNOWN: TextParser(),
        }
        self._parsers_by_name: dict[str, Parser] = {
            "python": self._parsers[Language.PYTHON],
            "javascript": self._parsers[Language.JAVASCRIPT],
            "typescript": self._parsers[Language.TYPESCRIPT],
            "java": self._parsers[Language.JAVA],
            "kotlin": self._parsers[Language.KOTLIN],
            "php": self._parsers[Language.PHP],
            "json": self._parsers[Language.JSON],
            "toml": self._parsers[Language.TOML],
            "xml": self._parsers[Language.XML],
            "text": self._parsers[Language.TEXT],
        }

    def get(self, language: Language, parser_name: str | None = None) -> Parser:
        if parser_name is not None:
            parser = self._parsers_by_name.get(parser_name)
            if parser is None:
                raise ValueError(f"unsupported parser override: {parser_name}")
            return parser
        return self._parsers.get(language, TextParser())

    def parse(
        self,
        file: DiscoveredFile,
        classification: FileClassification,
        parser_name: str | None = None,
    ) -> ParsedDocument:
        if parser_name is None and classification.language == Language.XML and classification.framework == Framework.ANDROID:
            return self._android_manifest_parser.parse(file, classification)
        parser = self.get(classification.language, parser_name=parser_name)
        return parser.parse(file, classification)


def parse_files(
    files: list[DiscoveredFile],
    classifications: list[FileClassification],
    registry: ParserRegistry | None = None,
    parser_overrides: dict[str, str] | None = None,
) -> list[ParsedDocument]:
    registry = registry or ParserRegistry()
    parser_overrides = parser_overrides or {}
    classification_map = {item.relative_path: item for item in classifications}
    parsed_documents: list[ParsedDocument] = []

    for file in files:
        classification = classification_map.get(file.relative_path)
        if classification is None:
            classification = FileClassification(
                path=file.path,
                relative_path=file.relative_path,
                language=Language.UNKNOWN,
                framework=None,
            )
        parsed_documents.append(
            registry.parse(
                file,
                classification,
                parser_name=parser_overrides.get(classification.language.value),
            )
        )

    return parsed_documents
