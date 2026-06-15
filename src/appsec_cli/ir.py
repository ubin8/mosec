from __future__ import annotations

import ast
import json
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True, frozen=True)
class IRLocation:
    path: Path
    line: int | None = None
    column: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "line": self.line,
            "column": self.column,
        }


@dataclass(slots=True, frozen=True)
class IRNode:
    kind: str
    location: IRLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "location": None if self.location is None else self.location.to_dict(),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True, frozen=True)
class IRCall(IRNode):
    callee: str = ""
    arguments: list[str] = field(default_factory=list)
    keywords: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = super().to_dict()
        payload.update(
            {
                "callee": self.callee,
                "arguments": list(self.arguments),
                "keywords": dict(self.keywords),
            }
        )
        return payload


@dataclass(slots=True, frozen=True)
class IRAssignment(IRNode):
    target: str = ""
    value: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = super().to_dict()
        payload.update({"target": self.target, "value": self.value})
        return payload


@dataclass(slots=True, frozen=True)
class IRLiteral(IRNode):
    value_type: str = ""
    value_repr: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = super().to_dict()
        payload.update({"value_type": self.value_type, "value_repr": self.value_repr})
        return payload


@dataclass(slots=True, frozen=True)
class IRMemberAccess(IRNode):
    owner: str = ""
    attribute: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = super().to_dict()
        payload.update({"owner": self.owner, "attribute": self.attribute})
        return payload


@dataclass(slots=True, frozen=True)
class IRDocument:
    path: Path
    nodes: list[IRNode] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "nodes": [node.to_dict() for node in self.nodes],
            "metadata": dict(self.metadata),
        }


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - defensive fallback
        return node.__class__.__name__


def _location(path: Path, node: ast.AST) -> IRLocation:
    return IRLocation(
        path=path,
        line=getattr(node, "lineno", None),
        column=getattr(node, "col_offset", None),
    )


class _PythonIRExtractor(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.nodes: list[IRNode] = []

    def visit_Call(self, node: ast.Call) -> Any:
        callee = _safe_unparse(node.func)
        arguments = [_safe_unparse(arg) for arg in node.args]
        keywords = {
            keyword.arg or "": _safe_unparse(keyword.value)
            for keyword in node.keywords
            if keyword.arg is not None
        }
        self.nodes.append(
            IRCall(
                kind="call",
                location=_location(self.path, node),
                callee=callee,
                arguments=arguments,
                keywords=keywords,
                metadata={"arg_count": len(arguments), "keyword_count": len(keywords)},
            )
        )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        value = _safe_unparse(node.value)
        for target in node.targets:
            self.nodes.append(
                IRAssignment(
                    kind="assignment",
                    location=_location(self.path, node),
                    target=_safe_unparse(target),
                    value=value,
                )
            )
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is None:
            return self.generic_visit(node)
        self.nodes.append(
            IRAssignment(
                kind="assignment",
                location=_location(self.path, node),
                target=_safe_unparse(node.target),
                value=_safe_unparse(node.value),
                metadata={"annotated": True},
            )
        )
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> Any:
        self.nodes.append(
            IRAssignment(
                kind="assignment",
                location=_location(self.path, node),
                target=_safe_unparse(node.target),
                value=f"{_safe_unparse(node.target)} {node.op.__class__.__name__} {_safe_unparse(node.value)}",
                metadata={"augmented": True},
            )
        )
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> Any:
        value = node.value
        self.nodes.append(
            IRLiteral(
                kind="literal",
                location=_location(self.path, node),
                value_type=type(value).__name__,
                value_repr=repr(value),
            )
        )
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> Any:
        self.nodes.append(
            IRMemberAccess(
                kind="member_access",
                location=_location(self.path, node),
                owner=_safe_unparse(node.value),
                attribute=node.attr,
            )
        )
        self.generic_visit(node)


def build_python_ir(path: Path, source: str) -> IRDocument:
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return IRDocument(path=path, metadata={"parser": "python", "syntax_valid": False})

    extractor = _PythonIRExtractor(path)
    extractor.visit(tree)
    return IRDocument(
        path=path,
        nodes=extractor.nodes,
        metadata={"parser": "python", "syntax_valid": True},
    )


def _append_normalized_scalar_nodes(
    nodes: list[IRNode],
    path: Path,
    value_path: str,
    value: Any,
    source: str,
) -> None:
    if isinstance(value, dict):
        for key, nested_value in value.items():
            nested_path = f"{value_path}.{key}" if value_path else str(key)
            _append_normalized_scalar_nodes(nodes, path, nested_path, nested_value, source)
        return
    if isinstance(value, list):
        for index, nested_value in enumerate(value):
            nested_path = f"{value_path}[{index}]"
            _append_normalized_scalar_nodes(nodes, path, nested_path, nested_value, source)
        return

    nodes.append(
        IRAssignment(
            kind="assignment",
            location=IRLocation(path=path),
            target=value_path,
            value=repr(value),
            metadata={"source": source},
        )
    )
    nodes.append(
        IRLiteral(
            kind="literal",
            location=IRLocation(path=path),
            value_type=type(value).__name__,
            value_repr=repr(value),
            metadata={"source": source},
        )
    )


def build_json_ir(path: Path, source: str) -> IRDocument:
    try:
        payload = json.loads(source)
    except json.JSONDecodeError:
        return IRDocument(path=path, metadata={"parser": "json", "syntax_valid": False})

    nodes: list[IRNode] = []
    _append_normalized_scalar_nodes(nodes, path, "", payload, "json")
    return IRDocument(path=path, nodes=nodes, metadata={"parser": "json", "syntax_valid": True})


def build_toml_ir(path: Path, source: str) -> IRDocument:
    try:
        payload = tomllib.loads(source)
    except tomllib.TOMLDecodeError:
        return IRDocument(path=path, metadata={"parser": "toml", "syntax_valid": False})

    nodes: list[IRNode] = []
    _append_normalized_scalar_nodes(nodes, path, "", payload, "toml")
    return IRDocument(path=path, nodes=nodes, metadata={"parser": "toml", "syntax_valid": True})


def build_xml_ir(path: Path, source: str) -> IRDocument:
    try:
        root = ET.fromstring(source)
    except ET.ParseError:
        return IRDocument(path=path, metadata={"parser": "xml", "syntax_valid": False})

    nodes: list[IRNode] = []

    def visit(element: ET.Element, current_path: str) -> None:
        for name, value in element.attrib.items():
            attr_path = f"{current_path}@{name}"
            _append_normalized_scalar_nodes(nodes, path, attr_path, value, "xml")
        text = (element.text or "").strip()
        if text:
            _append_normalized_scalar_nodes(nodes, path, f"{current_path}.text", text, "xml")
        for child in element:
            child_path = f"{current_path}.{child.tag}" if current_path else child.tag
            visit(child, child_path)

    visit(root, root.tag)
    return IRDocument(path=path, nodes=nodes, metadata={"parser": "xml", "syntax_valid": True})
