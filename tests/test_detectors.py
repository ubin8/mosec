from pathlib import Path

from appsec_cli.detection import FileClassification, Framework, Language
from appsec_cli.detectors import run_detectors
from appsec_cli.parsing import ParsedDocument
from appsec_cli.sca import DependencyRecord, DependencyScope, LocalAdvisoryBackend


def test_detects_secrets_sqli_and_sca(tmp_path: Path) -> None:
    python_path = tmp_path / "app.py"
    python_path.write_text(
        "from flask import Flask\nAPI_KEY = 'abc123secretvalue'\nquery = \"SELECT * FROM users WHERE name = '\" + user_input + \"'\"\n",
        encoding="utf-8",
    )
    package_path = tmp_path / "package.json"
    package_path.write_text(
        '{"dependencies": {"express": "4.18.2", "lodash": "4.17.21"}}',
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=python_path,
            relative_path="app.py",
            language=Language.PYTHON,
            framework=Framework.FLASK.value,
            syntax_valid=True,
            line_count=3,
            character_count=0,
        ),
        ParsedDocument(
            path=package_path,
            relative_path="package.json",
            language=Language.JSON,
            framework=Framework.EXPRESS.value,
            syntax_valid=True,
            line_count=1,
            character_count=0,
        ),
    ]

    findings = run_detectors(documents)

    assert any(f.rule_id == "SEC-SECRET-001" for f in findings)
    assert any(f.rule_id == "WEB-SQLI-001" for f in findings)
    assert any(f.rule_id == "SCA-PACKAGE-001" for f in findings)
    secret_finding = next(f for f in findings if f.rule_id == "SEC-SECRET-001")
    assert secret_finding.evidence is not None
    assert "abc123secretvalue" not in secret_finding.evidence.snippet
    assert secret_finding.metadata["masked"] is True
    assert secret_finding.metadata["cleartext_hint"] == "secret value masked in report"


def test_detects_secrets_in_env_files_with_priority(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("API_KEY = 'abc123secretvalue'\n", encoding="utf-8")

    documents = [
        ParsedDocument(
            path=env_path,
            relative_path=".env",
            language=Language.TEXT,
            framework=None,
            syntax_valid=True,
            line_count=1,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.metadata["sensitive_file"] is True
    assert finding.metadata["priority"] == "high"
    assert finding.evidence is not None
    assert "abc123secretvalue" not in finding.evidence.snippet


def test_dummy_secrets_are_suppressed(tmp_path: Path) -> None:
    secret_path = tmp_path / "settings.py"
    secret_path.write_text("API_KEY = 'changeme'\n", encoding="utf-8")

    documents = [
        ParsedDocument(
            path=secret_path,
            relative_path="settings.py",
            language=Language.PYTHON,
            framework=Framework.FLASK.value,
            syntax_valid=True,
            line_count=1,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)

    assert all(f.rule_id != "SEC-SECRET-001" for f in findings)


def test_detects_dom_xss(tmp_path: Path) -> None:
    js_path = tmp_path / "dom.js"
    js_path.write_text("document.getElementById('out').innerHTML = userInput;\n", encoding="utf-8")

    documents = [
        ParsedDocument(
            path=js_path,
            relative_path="dom.js",
            language=Language.JAVASCRIPT,
            framework=Framework.REACT.value,
            syntax_valid=True,
            line_count=1,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)

    assert any(f.rule_id == "WEB-XSS-001" for f in findings)


def test_sca_distinguishes_direct_and_transitive_dependencies(tmp_path: Path) -> None:
    package_json = tmp_path / "package.json"
    package_json.write_text(
        '{"dependencies": {"express": "4.18.2"}}',
        encoding="utf-8",
    )
    package_lock = tmp_path / "package-lock.json"
    package_lock.write_text(
        '{\n'
        '  "name": "demo",\n'
        '  "lockfileVersion": 3,\n'
        '  "packages": {\n'
        '    "": {"name": "demo", "version": "1.0.0"},\n'
        '    "node_modules/express": {"version": "4.18.2"},\n'
        '    "node_modules/express/node_modules/lodash": {"version": "4.17.21"}\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=package_json,
            relative_path="package.json",
            language=Language.JSON,
            framework=Framework.EXPRESS.value,
            syntax_valid=True,
            line_count=1,
            character_count=0,
        ),
        ParsedDocument(
            path=package_lock,
            relative_path="package-lock.json",
            language=Language.JSON,
            framework=Framework.EXPRESS.value,
            syntax_valid=True,
            line_count=7,
            character_count=0,
        ),
    ]

    findings = run_detectors(documents)

    direct = [f for f in findings if f.metadata.get("dependency_scope") == "direct"]
    transitive = [f for f in findings if f.metadata.get("dependency_scope") == "transitive"]

    assert any(f.metadata.get("package") == "express" for f in direct)
    assert any(f.metadata.get("package") == "lodash" for f in transitive)
    assert all(f.metadata.get("vulnerability_backend") == "local-advisory" for f in findings if f.rule_id == "SCA-PACKAGE-001")


def test_local_advisory_backend_matches_known_packages() -> None:
    backend = LocalAdvisoryBackend()
    advisory = backend.lookup(
        DependencyRecord(
            package="express",
            version="4.18.2",
            source_file="package.json",
            scope=DependencyScope.DIRECT,
            line=1,
            ecosystem="javascript",
        )
    )

    assert advisory
    assert advisory[0].advisory_id == "ADV-JS-0001"
    assert advisory[0].severity.value == "high"


def test_detects_ssrf_path_traversal_and_open_redirect(tmp_path: Path) -> None:
    web_path = tmp_path / "views.py"
    web_path.write_text(
        "from flask import redirect\n"
        "requests.get(user_input)\n"
        "open('../' + filename)\n"
        "redirect(request.args.get('next'))\n",
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=web_path,
            relative_path="views.py",
            language=Language.PYTHON,
            framework=Framework.FLASK.value,
            syntax_valid=True,
            line_count=4,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)
    rule_ids = {finding.rule_id for finding in findings}

    assert "WEB-SSRF-001" in rule_ids
    assert "WEB-PATH-001" in rule_ids
    assert "WEB-REDIRECT-001" in rule_ids


def test_detects_assignment_propagation_in_web_flow(tmp_path: Path) -> None:
    web_path = tmp_path / "views.py"
    web_path.write_text(
        "from flask import redirect\n"
        "next_url = request.args.get('next')\n"
        "redirect_target = next_url\n"
        "redirect(redirect_target)\n",
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=web_path,
            relative_path="views.py",
            language=Language.PYTHON,
            framework=Framework.FLASK.value,
            syntax_valid=True,
            line_count=4,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)
    redirect = next(finding for finding in findings if finding.rule_id == "WEB-REDIRECT-001")

    assert redirect.metadata["source_kind"] == "query"
    assert redirect.metadata["taint_propagation"] == "assignment"
    assert redirect.metadata["taint_source_kind"] == "query"
    assert redirect.metadata["taint_origin_variable"] == "next_url"
    assert "redirect_target" in redirect.metadata["tainted_variables"]


def test_detects_function_call_propagation_in_web_flow(tmp_path: Path) -> None:
    web_path = tmp_path / "views.py"
    web_path.write_text(
        "from flask import redirect\n"
        "def forward(target):\n"
        "    return redirect(target)\n"
        "next_url = request.args.get('next')\n"
        "forward(next_url)\n",
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=web_path,
            relative_path="views.py",
            language=Language.PYTHON,
            framework=Framework.FLASK.value,
            syntax_valid=True,
            line_count=5,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)
    redirect = next(finding for finding in findings if finding.rule_id == "WEB-REDIRECT-001")

    assert redirect.location.start_line == 3
    assert redirect.metadata["source_kind"] == "query"
    assert redirect.metadata["taint_propagation"] == "function_call"
    assert redirect.metadata["taint_call"] == "forward"
    assert redirect.metadata["taint_source_kind"] == "query"
    assert "target" in redirect.metadata["tainted_variables"]


def test_detects_return_value_propagation_in_web_flow(tmp_path: Path) -> None:
    web_path = tmp_path / "views.py"
    web_path.write_text(
        "from flask import redirect\n"
        "def normalize(target):\n"
        "    alias = target\n"
        "    return alias\n"
        "next_url = request.args.get('next')\n"
        "redirect_target = normalize(next_url)\n"
        "redirect(redirect_target)\n",
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=web_path,
            relative_path="views.py",
            language=Language.PYTHON,
            framework=Framework.FLASK.value,
            syntax_valid=True,
            line_count=7,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)
    redirect = next(finding for finding in findings if finding.rule_id == "WEB-REDIRECT-001")

    assert redirect.location.start_line == 7
    assert redirect.metadata["source_kind"] == "query"
    assert redirect.metadata["taint_propagation"] == "return_value"
    assert redirect.metadata["taint_call"] == "normalize"
    assert redirect.metadata["taint_source_kind"] == "query"
    assert "redirect_target" in redirect.metadata["tainted_variables"]


def test_detects_container_propagation_in_web_flow(tmp_path: Path) -> None:
    web_path = tmp_path / "views.py"
    web_path.write_text(
        "from flask import redirect\n"
        "items = []\n"
        "next_url = request.args.get('next')\n"
        "items.append(next_url)\n"
        "redirect_target = items[0]\n"
        "redirect(redirect_target)\n",
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=web_path,
            relative_path="views.py",
            language=Language.PYTHON,
            framework=Framework.FLASK.value,
            syntax_valid=True,
            line_count=6,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)
    redirect = next(finding for finding in findings if finding.rule_id == "WEB-REDIRECT-001")

    assert redirect.location.start_line == 6
    assert redirect.metadata["source_kind"] == "query"
    assert redirect.metadata["taint_propagation"] == "container"
    assert redirect.metadata["taint_source_kind"] == "query"
    assert "redirect_target" in redirect.metadata["tainted_variables"]


def test_detects_field_propagation_in_web_flow(tmp_path: Path) -> None:
    web_path = tmp_path / "views.py"
    web_path.write_text(
        "from flask import redirect\n"
        "class Payload:\n"
        "    pass\n"
        "payload = Payload()\n"
        "next_url = request.args.get('next')\n"
        "payload.next = next_url\n"
        "redirect_target = payload.next\n"
        "redirect(redirect_target)\n",
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=web_path,
            relative_path="views.py",
            language=Language.PYTHON,
            framework=Framework.FLASK.value,
            syntax_valid=True,
            line_count=8,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)
    redirect = next(finding for finding in findings if finding.rule_id == "WEB-REDIRECT-001")

    assert redirect.location.start_line == 8
    assert redirect.metadata["source_kind"] == "query"
    assert redirect.metadata["taint_propagation"] == "field"
    assert redirect.metadata["taint_source_kind"] == "query"
    assert "redirect_target" in redirect.metadata["tainted_variables"]


def test_detects_branch_conservative_propagation_in_web_flow(tmp_path: Path) -> None:
    web_path = tmp_path / "views.py"
    web_path.write_text(
        "from flask import redirect\n"
        "if condition:\n"
        "    redirect_target = request.args.get('next')\n"
        "else:\n"
        "    redirect_target = safe_default\n"
        "redirect(redirect_target)\n",
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=web_path,
            relative_path="views.py",
            language=Language.PYTHON,
            framework=Framework.FLASK.value,
            syntax_valid=True,
            line_count=6,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)
    redirect = next(finding for finding in findings if finding.rule_id == "WEB-REDIRECT-001")

    assert redirect.location.start_line == 6
    assert redirect.metadata["source_kind"] == "query"
    assert redirect.metadata["taint_branch_context"] is True
    assert redirect.metadata["taint_branch_kind"] == "if"
    assert redirect.metadata["taint_branch_line"] == 3


def test_detects_unreachable_sink_metadata_in_false_branch(tmp_path: Path) -> None:
    web_path = tmp_path / "views.py"
    web_path.write_text(
        "from flask import redirect\n"
        "if False:\n"
        "    next_url = request.args.get('next')\n"
        "    redirect(next_url)\n",
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=web_path,
            relative_path="views.py",
            language=Language.PYTHON,
            framework=Framework.FLASK.value,
            syntax_valid=True,
            line_count=4,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)
    redirect = next(finding for finding in findings if finding.rule_id == "WEB-REDIRECT-001")

    assert redirect.metadata["taint_reachability"] == "unreachable"
    assert redirect.metadata["taint_sink_line"] == 4
    assert redirect.metadata["taint_exploitability_context"]["reachability"] == "unreachable"


def test_string_escape_sanitizer_suppresses_python_template_finding(tmp_path: Path) -> None:
    view_path = tmp_path / "views.py"
    view_path.write_text(
        "import html\n"
        "from flask import render_template\n"
        "safe_name = html.escape(request.args.get('name'))\n"
        "render_template('hello.html', name=safe_name)\n",
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=view_path,
            relative_path="views.py",
            language=Language.PYTHON,
            framework=Framework.FLASK.value,
            syntax_valid=True,
            line_count=4,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)

    assert not any(f.rule_id == "WEB-TEMPLATE-001" for f in findings)


def test_string_escape_sanitizer_suppresses_javascript_xss_finding(tmp_path: Path) -> None:
    component_path = tmp_path / "component.js"
    component_path.write_text(
        "const safeHtml = escapeHtml(req.body.html);\n"
        "document.getElementById('out').innerHTML = safeHtml;\n",
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=component_path,
            relative_path="component.js",
            language=Language.JAVASCRIPT,
            framework=Framework.EXPRESS.value,
            syntax_valid=True,
            line_count=2,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)

    assert not any(f.rule_id == "WEB-XSS-001" for f in findings)


def test_url_allowlist_guard_suppresses_python_redirect_finding(tmp_path: Path) -> None:
    view_path = tmp_path / "views.py"
    view_path.write_text(
        "from flask import redirect\n"
        "next_url = request.args.get('next')\n"
        "def go(url):\n"
        "    if is_allowed_url(next_url):\n"
        "        return redirect(next_url)\n",
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=view_path,
            relative_path="views.py",
            language=Language.PYTHON,
            framework=Framework.FLASK.value,
            syntax_valid=True,
            line_count=5,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)

    assert not any(f.rule_id == "WEB-REDIRECT-001" for f in findings)


def test_url_allowlist_guard_suppresses_javascript_ssrf_finding(tmp_path: Path) -> None:
    js_path = tmp_path / "server.js"
    js_path.write_text(
        "if (isAllowedUrl(req.query.url)) {\n"
        "  axios.get(req.query.url)\n"
        "}\n",
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=js_path,
            relative_path="server.js",
            language=Language.JAVASCRIPT,
            framework=Framework.EXPRESS.value,
            syntax_valid=True,
            line_count=3,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)

    assert not any(f.rule_id == "WEB-SSRF-001" for f in findings)


def test_express_source_sink_metadata_is_recorded(tmp_path: Path) -> None:
    js_path = tmp_path / "server.js"
    js_path.write_text(
        "const express = require('express')\n"
        "const app = express()\n"
        "app.get('/go', (req, res) => res.redirect(req.query.next))\n"
        "app.get('/fetch', (req, res) => axios.get(req.body.url))\n",
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=js_path,
            relative_path="server.js",
            language=Language.JAVASCRIPT,
            framework=Framework.EXPRESS.value,
            syntax_valid=True,
            line_count=4,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)
    redirect = next(f for f in findings if f.rule_id == "WEB-REDIRECT-001")
    ssrf = next(f for f in findings if f.rule_id == "WEB-SSRF-001")

    assert redirect.metadata["framework_model"] == "express"
    assert redirect.metadata["flow_model"] == "request_to_sink"
    assert redirect.metadata["source_kind"] == "query"
    assert redirect.metadata["sink_kind"] == "redirect"
    assert redirect.metadata["handler_kind"] == "route_handler"
    assert ssrf.metadata["framework_model"] == "express"
    assert ssrf.metadata["source_kind"] == "body"
    assert ssrf.metadata["sink_kind"] == "network_request"


def test_nextjs_request_flow_metadata_is_recorded(tmp_path: Path) -> None:
    route_path = tmp_path / "app" / "api" / "route.ts"
    route_path.parent.mkdir(parents=True, exist_ok=True)
    route_path.write_text(
        "import { NextResponse } from 'next/server'\n"
        "export async function GET(request) {\n"
        "  return NextResponse.redirect(new URL(request.nextUrl.searchParams.get('next'), request.url))\n"
        "}\n"
        "export async function POST(request) {\n"
        "  return fetch(request.nextUrl.searchParams.get('url'))\n"
        "}\n",
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=route_path,
            relative_path="app/api/route.ts",
            language=Language.TYPESCRIPT,
            framework=Framework.NEXTJS.value,
            syntax_valid=True,
            line_count=6,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)
    redirect = next(f for f in findings if f.rule_id == "WEB-REDIRECT-001")
    ssrf = next(f for f in findings if f.rule_id == "WEB-SSRF-001")

    assert redirect.metadata["framework_model"] == "nextjs"
    assert redirect.metadata["flow_model"] == "request_to_sink"
    assert redirect.metadata["source_kind"] == "search_params"
    assert redirect.metadata["sink_kind"] == "redirect"
    assert redirect.metadata["handler_kind"] == "route_handler"
    assert ssrf.metadata["framework_model"] == "nextjs"
    assert ssrf.metadata["source_kind"] == "search_params"
    assert ssrf.metadata["sink_kind"] == "network_request"


def test_react_dom_xss_flow_metadata_is_recorded(tmp_path: Path) -> None:
    component_path = tmp_path / "Component.tsx"
    component_path.write_text(
        "import React from 'react'\n"
        "export function Component({ userInput }) {\n"
        "  return <div dangerouslySetInnerHTML={{ __html: userInput }} />\n"
        "}\n",
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=component_path,
            relative_path="Component.tsx",
            language=Language.TYPESCRIPT,
            framework=Framework.REACT.value,
            syntax_valid=True,
            line_count=4,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)
    xss = next(f for f in findings if f.rule_id == "WEB-XSS-001")

    assert xss.metadata["framework_model"] == "react"
    assert xss.metadata["flow_model"] == "prop_to_dom_sink"
    assert xss.metadata["sink_kind"] == "dom_sink"
    assert xss.metadata["dom_sink"] == "innerhtml"
    assert xss.metadata["react_sink"] == "dangerouslySetInnerHTML"


def test_django_request_flow_metadata_is_recorded(tmp_path: Path) -> None:
    view_path = tmp_path / "views.py"
    view_path.write_text(
        "from django.shortcuts import redirect\n"
        "def go(request):\n"
        "    return redirect(request.GET.get('next'))\n"
        "def download(request):\n"
        "    return open(request.POST.get('path'))\n"
        "def proxy(request):\n"
        "    return requests.get(request.GET.get('url'))\n",
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=view_path,
            relative_path="views.py",
            language=Language.PYTHON,
            framework=Framework.DJANGO.value,
            syntax_valid=True,
            line_count=7,
            character_count=0,
        )
    ]

    findings = run_detectors(documents)
    redirect = next(f for f in findings if f.rule_id == "WEB-REDIRECT-001")
    traversal = next(f for f in findings if f.rule_id == "WEB-PATH-001")
    ssrf = next(f for f in findings if f.rule_id == "WEB-SSRF-001")

    assert redirect.metadata["framework_model"] == "django"
    assert redirect.metadata["flow_model"] == "request_to_sink"
    assert redirect.metadata["source_kind"] == "query"
    assert redirect.metadata["sink_kind"] == "redirect"
    assert traversal.metadata["framework_model"] == "django"
    assert traversal.metadata["source_kind"] == "body"
    assert traversal.metadata["sink_kind"] == "filesystem"
    assert ssrf.metadata["framework_model"] == "django"
    assert ssrf.metadata["source_kind"] == "query"
    assert ssrf.metadata["sink_kind"] == "network_request"


def test_detects_template_rendering_sinks_with_framework_metadata(tmp_path: Path) -> None:
    flask_path = tmp_path / "flask_views.py"
    flask_path.write_text(
        "from flask import render_template\n"
        "render_template(user_input)\n",
        encoding="utf-8",
    )
    django_path = tmp_path / "django_views.py"
    django_path.write_text(
        "from django.template.loader import render_to_string\n"
        "render_to_string('page.html', {'content': user_input})\n",
        encoding="utf-8",
    )

    findings = run_detectors(
        [
            ParsedDocument(
                path=flask_path,
                relative_path="flask_views.py",
                language=Language.PYTHON,
                framework=Framework.FLASK.value,
                syntax_valid=True,
                line_count=2,
                character_count=0,
            ),
            ParsedDocument(
                path=django_path,
                relative_path="django_views.py",
                language=Language.PYTHON,
                framework=Framework.DJANGO.value,
                syntax_valid=True,
                line_count=2,
                character_count=0,
            ),
        ]
    )

    template_findings = [finding for finding in findings if finding.rule_id == "WEB-TEMPLATE-001"]
    assert len(template_findings) == 2

    flask_finding = next(finding for finding in template_findings if finding.location.path == flask_path)
    django_finding = next(finding for finding in template_findings if finding.location.path == django_path)

    assert flask_finding.metadata["framework_model"] == "flask"
    assert flask_finding.metadata["template_model"] == "jinja2"
    assert flask_finding.metadata["flow_model"] == "context_to_template_sink"
    assert flask_finding.metadata["sink_kind"] == "template_render"
    assert flask_finding.metadata["template_sink"] == "render"

    assert django_finding.metadata["framework_model"] == "django"
    assert django_finding.metadata["template_model"] == "django"
    assert django_finding.metadata["flow_model"] == "context_to_template_sink"
    assert django_finding.metadata["sink_kind"] == "template_render"
    assert django_finding.metadata["template_sink"] == "render"


def test_detects_orm_query_sinks_with_framework_metadata(tmp_path: Path) -> None:
    django_path = tmp_path / "django_queries.py"
    django_path.write_text(
        "from django.db import connection\n"
        "def search(request):\n"
        "    return connection.cursor().execute(request.GET.get('query'))\n",
        encoding="utf-8",
    )
    sqlalchemy_path = tmp_path / "sqlalchemy_queries.py"
    sqlalchemy_path.write_text(
        "from sqlalchemy import text\n"
        "def search(user_input):\n"
        "    return session.execute(text(f'SELECT * FROM users WHERE id = {user_input}'))\n",
        encoding="utf-8",
    )

    findings = run_detectors(
        [
            ParsedDocument(
                path=django_path,
                relative_path="django_queries.py",
                language=Language.PYTHON,
                framework=Framework.DJANGO.value,
                syntax_valid=True,
                line_count=3,
                character_count=0,
            ),
            ParsedDocument(
                path=sqlalchemy_path,
                relative_path="sqlalchemy_queries.py",
                language=Language.PYTHON,
                framework=Framework.FLASK.value,
                syntax_valid=True,
                line_count=3,
                character_count=0,
            ),
        ]
    )

    orm_findings = [finding for finding in findings if finding.rule_id == "WEB-ORM-001"]
    assert len(orm_findings) == 2

    django_finding = next(finding for finding in orm_findings if finding.location.path == django_path)
    sqlalchemy_finding = next(finding for finding in orm_findings if finding.location.path == sqlalchemy_path)

    assert django_finding.metadata["framework_model"] == "django"
    assert django_finding.metadata["orm_model"] == "django_orm"
    assert django_finding.metadata["flow_model"] == "user_input_to_orm_query"
    assert django_finding.metadata["sink_kind"] == "orm_query"
    assert django_finding.metadata["source_kind"] == "request_input"
    assert django_finding.metadata["query_kind"] == "raw_sql"

    assert sqlalchemy_finding.metadata["framework_model"] == "flask"
    assert sqlalchemy_finding.metadata["orm_model"] == "sqlalchemy"
    assert sqlalchemy_finding.metadata["flow_model"] == "user_input_to_orm_query"
    assert sqlalchemy_finding.metadata["sink_kind"] == "orm_query"


def test_parameterized_python_query_does_not_raise_sqli_or_orm_finding(tmp_path: Path) -> None:
    django_path = tmp_path / "django_queries.py"
    django_path.write_text(
        "from django.db import connection\n"
        "def search(request):\n"
        "    return connection.cursor().execute(\"SELECT * FROM users WHERE id = %s\", [request.GET.get('id')])\n",
        encoding="utf-8",
    )

    findings = run_detectors(
        [
            ParsedDocument(
                path=django_path,
                relative_path="django_queries.py",
                language=Language.PYTHON,
                framework=Framework.DJANGO.value,
                syntax_valid=True,
                line_count=3,
                character_count=0,
            )
        ]
    )

    assert not any(f.rule_id == "WEB-SQLI-001" for f in findings)
    assert not any(f.rule_id == "WEB-ORM-001" for f in findings)
    assert sqlalchemy_finding.metadata["query_kind"] == "raw_sql"


def test_detects_file_access_sinks_with_framework_metadata(tmp_path: Path) -> None:
    flask_path = tmp_path / "download.py"
    flask_path.write_text(
        "from flask import send_file\n"
        "def download(request):\n"
        "    return open(request.args.get('path'))\n",
        encoding="utf-8",
    )
    django_path = tmp_path / "media.py"
    django_path.write_text(
        "from django.http import FileResponse\n"
        "def serve(request):\n"
        "    return FileResponse(request.GET.get('file'))\n",
        encoding="utf-8",
    )

    findings = run_detectors(
        [
            ParsedDocument(
                path=flask_path,
                relative_path="download.py",
                language=Language.PYTHON,
                framework=Framework.FLASK.value,
                syntax_valid=True,
                line_count=3,
                character_count=0,
            ),
            ParsedDocument(
                path=django_path,
                relative_path="media.py",
                language=Language.PYTHON,
                framework=Framework.DJANGO.value,
                syntax_valid=True,
                line_count=3,
                character_count=0,
            ),
        ]
    )

    file_findings = [finding for finding in findings if finding.rule_id == "WEB-FILE-001"]
    assert len(file_findings) == 2

    flask_finding = next(finding for finding in file_findings if finding.location.path == flask_path)
    django_finding = next(finding for finding in file_findings if finding.location.path == django_path)

    assert flask_finding.metadata["framework_model"] == "flask"
    assert flask_finding.metadata["flow_model"] == "request_input_to_file_sink"
    assert flask_finding.metadata["sink_kind"] == "file_access"
    assert flask_finding.metadata["file_operation"] == "open"
    assert flask_finding.metadata["source_kind"] == "request_input"

    assert django_finding.metadata["framework_model"] == "django"
    assert django_finding.metadata["flow_model"] == "request_input_to_file_sink"
    assert django_finding.metadata["sink_kind"] == "file_access"
    assert django_finding.metadata["file_operation"] == "open"
    assert django_finding.metadata["source_kind"] == "request_input"


def test_detects_spring_request_flow_metadata(tmp_path: Path) -> None:
    spring_path = tmp_path / "src" / "main" / "java" / "com" / "example" / "ProxyController.java"
    spring_path.parent.mkdir(parents=True, exist_ok=True)
    spring_path.write_text(
        "import org.springframework.web.bind.annotation.GetMapping;\n"
        "import org.springframework.web.bind.annotation.RequestParam;\n"
        "@RestController\n"
        "class ProxyController {\n"
        "    @GetMapping(\"/proxy\")\n"
        "    String proxy(@RequestParam(\"url\") String url) {\n"
        "        return restTemplate.getForObject(url, String.class);\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    findings = run_detectors(
        [
            ParsedDocument(
                path=spring_path,
                relative_path=str(spring_path.relative_to(tmp_path)),
                language=Language.JAVA,
                framework=Framework.SPRING.value,
                syntax_valid=True,
                line_count=9,
                character_count=0,
            )
        ]
    )

    ssrf = next(finding for finding in findings if finding.rule_id == "WEB-SSRF-001")
    assert ssrf.metadata["framework_model"] == "spring"
    assert ssrf.metadata["flow_model"] == "request_to_sink"
    assert ssrf.metadata["sink_kind"] == "network_request"
    assert ssrf.metadata["source_kind"] == "query"
    assert ssrf.metadata["handler_kind"] == "controller_method"
    assert ssrf.metadata["mapping_kind"] == "getmapping"
    assert ssrf.metadata["spring_parameter"] == "requestparam"
    assert ssrf.metadata["entry_kind"] == "controller"


def test_detects_spring_servlet_entry_metadata(tmp_path: Path) -> None:
    servlet_path = tmp_path / "src" / "main" / "java" / "com" / "example" / "ProxyServlet.java"
    servlet_path.parent.mkdir(parents=True, exist_ok=True)
    servlet_path.write_text(
        "import jakarta.servlet.annotation.WebServlet;\n"
        "import jakarta.servlet.http.HttpServlet;\n"
        "import jakarta.servlet.http.HttpServletRequest;\n"
        "import jakarta.servlet.http.HttpServletResponse;\n"
        "@WebServlet(\"/proxy\")\n"
        "public class ProxyServlet extends HttpServlet {\n"
        "    protected void doGet(HttpServletRequest request, HttpServletResponse response) {\n"
        "        restTemplate.getForObject(request.getParameter(\"url\"), String.class);\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    findings = run_detectors(
        [
            ParsedDocument(
                path=servlet_path,
                relative_path=str(servlet_path.relative_to(tmp_path)),
                language=Language.JAVA,
                framework=Framework.SPRING.value,
                syntax_valid=True,
                line_count=9,
                character_count=0,
            )
        ]
    )

    ssrf = next(finding for finding in findings if finding.rule_id == "WEB-SSRF-001")
    assert ssrf.metadata["framework_model"] == "spring"
    assert ssrf.metadata["flow_model"] == "request_to_sink"
    assert ssrf.metadata["sink_kind"] == "network_request"
    assert ssrf.metadata["source_kind"] == "query"
    assert ssrf.metadata["handler_kind"] == "servlet_method"
    assert ssrf.metadata["entry_kind"] == "servlet"
    assert ssrf.metadata["spring_parameter"] == "getparameter"


def test_detects_spring_sql_query_sinks(tmp_path: Path) -> None:
    spring_path = tmp_path / "src" / "main" / "java" / "com" / "example" / "UserRepository.java"
    spring_path.parent.mkdir(parents=True, exist_ok=True)
    spring_path.write_text(
        "import org.springframework.jdbc.core.JdbcTemplate;\n"
        "import jakarta.persistence.EntityManager;\n"
        "@Repository\n"
        "class UserRepository {\n"
        "    void run(JdbcTemplate jdbcTemplate, EntityManager entityManager, String userInput) {\n"
        "        jdbcTemplate.query(\"SELECT * FROM users WHERE name = '\" + userInput + \"'\", rowMapper);\n"
        "        entityManager.createNativeQuery(\"SELECT * FROM users WHERE id = \" + userInput);\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    findings = run_detectors(
        [
            ParsedDocument(
                path=spring_path,
                relative_path=str(spring_path.relative_to(tmp_path)),
                language=Language.JAVA,
                framework=Framework.SPRING.value,
                syntax_valid=True,
                line_count=9,
                character_count=0,
            )
        ]
    )

    sql_findings = [finding for finding in findings if finding.rule_id == "WEB-SQLI-001"]
    assert len(sql_findings) == 2
    for finding in sql_findings:
        assert finding.metadata["framework_model"] == "spring"
        assert finding.metadata["flow_model"] == "request_to_sink"
        assert finding.metadata["sink_kind"] == "sql_query"
        assert finding.metadata["entry_kind"] == "repository"
    assert any("jdbcTemplate.query" in finding.evidence.snippet for finding in sql_findings)
    assert any("entityManager.createNativeQuery" in finding.evidence.snippet for finding in sql_findings)


def test_parameterized_spring_query_does_not_raise_sqli_finding(tmp_path: Path) -> None:
    spring_path = tmp_path / "src" / "main" / "java" / "com" / "example" / "SafeRepository.java"
    spring_path.parent.mkdir(parents=True, exist_ok=True)
    spring_path.write_text(
        "import org.springframework.jdbc.core.JdbcTemplate;\n"
        "import java.sql.Connection;\n"
        "@Repository\n"
        "class SafeRepository {\n"
        "    void run(JdbcTemplate jdbcTemplate, Connection connection, String userInput, RowMapper rowMapper) throws Exception {\n"
        "        jdbcTemplate.query(\"SELECT * FROM users WHERE name = ?\", rowMapper, userInput);\n"
        "        connection.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    findings = run_detectors(
        [
            ParsedDocument(
                path=spring_path,
                relative_path=str(spring_path.relative_to(tmp_path)),
                language=Language.JAVA,
                framework=Framework.SPRING.value,
                syntax_valid=True,
                line_count=9,
                character_count=0,
            )
        ]
    )

    assert not any(f.rule_id == "WEB-SQLI-001" for f in findings)


def test_detects_spring_deserialization_sinks(tmp_path: Path) -> None:
    spring_path = tmp_path / "src" / "main" / "java" / "com" / "example" / "DeserializerController.java"
    spring_path.parent.mkdir(parents=True, exist_ok=True)
    spring_path.write_text(
        "import com.fasterxml.jackson.databind.ObjectMapper;\n"
        "import java.io.ObjectInputStream;\n"
        "import org.springframework.web.bind.annotation.PostMapping;\n"
        "import org.springframework.web.bind.annotation.RequestBody;\n"
        "@RestController\n"
        "class DeserializerController {\n"
        "    @PostMapping(\"/deserialize\")\n"
        "    String deserialize(@RequestBody String payload) throws Exception {\n"
        "        new ObjectMapper().readValue(payload, User.class);\n"
        "        new ObjectInputStream(inputStream).readObject();\n"
        "        return \"ok\";\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    findings = run_detectors(
        [
            ParsedDocument(
                path=spring_path,
                relative_path=str(spring_path.relative_to(tmp_path)),
                language=Language.JAVA,
                framework=Framework.SPRING.value,
                syntax_valid=True,
                line_count=12,
                character_count=0,
            )
        ]
    )

    deserialization_findings = [finding for finding in findings if finding.rule_id == "WEB-DESERIAL-001"]
    assert len(deserialization_findings) == 2
    for finding in deserialization_findings:
        assert finding.metadata["framework_model"] == "spring"
        assert finding.metadata["flow_model"] == "request_to_sink"
        assert finding.metadata["sink_kind"] == "deserialization"
        assert finding.metadata["entry_kind"] == "controller"
        assert finding.metadata["source_kind"] == "body"
    assert any(finding.metadata["deserialization_kind"] == "object_mapper" for finding in deserialization_findings)
    assert any(finding.metadata["deserialization_kind"] == "java_serialization" for finding in deserialization_findings)


def test_detects_laravel_request_flow_metadata(tmp_path: Path) -> None:
    php_path = tmp_path / "routes" / "web.php"
    php_path.parent.mkdir(parents=True, exist_ok=True)
    php_path.write_text(
        "<?php\n"
        "use Illuminate\\Http\\Request;\n"
        "use Illuminate\\Support\\Facades\\Http;\n"
        "use Illuminate\\Support\\Facades\\Route;\n"
        "Route::get('/proxy', function (Request $request) {\n"
        "    return Http::get($request->input('url'));\n"
        "});\n"
        "Route::get('/redirect', function (Request $request) {\n"
        "    return redirect($request->input('next'));\n"
        "});\n",
        encoding="utf-8",
    )

    findings = run_detectors(
        [
            ParsedDocument(
                path=php_path,
                relative_path=str(php_path.relative_to(tmp_path)),
                language=Language.PHP,
                framework=Framework.LARAVEL.value,
                syntax_valid=True,
                line_count=10,
                character_count=0,
            )
        ]
    )

    ssrf = next(finding for finding in findings if finding.rule_id == "WEB-SSRF-001")
    redirect = next(finding for finding in findings if finding.rule_id == "WEB-REDIRECT-001")
    assert ssrf.metadata["framework_model"] == "laravel"
    assert ssrf.metadata["flow_model"] == "request_to_sink"
    assert ssrf.metadata["sink_kind"] == "network_request"
    assert ssrf.metadata["source_kind"] == "request_input"
    assert ssrf.metadata["entry_kind"] == "route_definition"
    assert ssrf.metadata["route_kind"] == "get"
    assert redirect.metadata["framework_model"] == "laravel"
    assert redirect.metadata["flow_model"] == "request_to_sink"
    assert redirect.metadata["sink_kind"] == "redirect"
    assert redirect.metadata["source_kind"] == "request_input"
    assert redirect.metadata["entry_kind"] == "route_definition"
    assert redirect.metadata["route_kind"] == "get"


def test_detects_blade_template_sink_metadata(tmp_path: Path) -> None:
    php_path = tmp_path / "routes" / "web.php"
    php_path.parent.mkdir(parents=True, exist_ok=True)
    php_path.write_text(
        "<?php\n"
        "use Illuminate\\Http\\Request;\n"
        "use Illuminate\\Support\\Facades\\Blade;\n"
        "use Illuminate\\Support\\Facades\\Route;\n"
        "Route::get('/profile', function (Request $request) {\n"
        "    return view('profile', ['name' => $request->input('name')]);\n"
        "});\n"
        "Route::get('/preview', function (Request $request) {\n"
        "    return Blade::render($request->input('template'), ['name' => $request->input('name')]);\n"
        "});\n",
        encoding="utf-8",
    )

    findings = run_detectors(
        [
            ParsedDocument(
                path=php_path,
                relative_path=str(php_path.relative_to(tmp_path)),
                language=Language.PHP,
                framework=Framework.LARAVEL.value,
                syntax_valid=True,
                line_count=10,
                character_count=0,
            )
        ]
    )

    template_findings = [finding for finding in findings if finding.rule_id == "WEB-TEMPLATE-001"]
    assert len(template_findings) == 2
    assert all(finding.metadata["framework_model"] == "laravel" for finding in template_findings)
    assert all(finding.metadata["flow_model"] == "context_to_template_sink" for finding in template_findings)
    assert all(finding.metadata["sink_kind"] == "template_render" for finding in template_findings)
    assert all(finding.metadata["source_kind"] == "request_input" for finding in template_findings)
    assert all(finding.metadata["entry_kind"] == "route_definition" for finding in template_findings)
    assert all(finding.metadata["route_kind"] == "get" for finding in template_findings)
    assert any(finding.metadata["template_model"] == "blade" for finding in template_findings)
    assert any(finding.metadata["template_sink"] == "view" for finding in template_findings)
    assert any(finding.metadata["template_sink"] == "blade_render" for finding in template_findings)


def test_detects_laravel_process_sink_metadata(tmp_path: Path) -> None:
    php_path = tmp_path / "routes" / "web.php"
    php_path.parent.mkdir(parents=True, exist_ok=True)
    php_path.write_text(
        "<?php\n"
        "use Illuminate\\Http\\Request;\n"
        "use Illuminate\\Support\\Facades\\Route;\n"
        "Route::post('/run', function (Request $request) {\n"
        "    return shell_exec($request->input('cmd'));\n"
        "});\n"
        "Route::post('/spawn', function (Request $request) {\n"
        "    return proc_open($request->input('cmd'), [], $pipes);\n"
        "});\n",
        encoding="utf-8",
    )

    findings = run_detectors(
        [
            ParsedDocument(
                path=php_path,
                relative_path=str(php_path.relative_to(tmp_path)),
                language=Language.PHP,
                framework=Framework.LARAVEL.value,
                syntax_valid=True,
                line_count=9,
                character_count=0,
            )
        ]
    )

    process_findings = [finding for finding in findings if finding.rule_id == "WEB-PROC-001"]
    assert len(process_findings) == 2
    assert all(finding.metadata["framework_model"] == "laravel" for finding in process_findings)
    assert all(finding.metadata["flow_model"] == "request_to_sink" for finding in process_findings)
    assert all(finding.metadata["sink_kind"] == "process_execution" for finding in process_findings)
    assert all(finding.metadata["source_kind"] == "request_input" for finding in process_findings)
    assert all(finding.metadata["entry_kind"] == "route_definition" for finding in process_findings)
    assert all(finding.metadata["route_kind"] == "post" for finding in process_findings)
    assert any(finding.metadata["process_kind"] == "shell" for finding in process_findings)
    assert any(finding.metadata["process_kind"] == "spawn" for finding in process_findings)


def test_detects_cookie_source_metadata(tmp_path: Path) -> None:
    js_path = tmp_path / "cookie.js"
    js_path.write_text(
        "const express = require('express');\n"
        "app.get('/proxy', (req, res) => axios.get(req.cookies.url));\n"
        "app.get('/redirect', (req, res) => res.redirect(req.cookies.next));\n",
        encoding="utf-8",
    )

    findings = run_detectors(
        [
            ParsedDocument(
                path=js_path,
                relative_path="cookie.js",
                language=Language.JAVASCRIPT,
                framework=Framework.EXPRESS.value,
                syntax_valid=True,
                line_count=3,
                character_count=0,
            )
        ]
    )

    ssrf = next(finding for finding in findings if finding.rule_id == "WEB-SSRF-001")
    redirect = next(finding for finding in findings if finding.rule_id == "WEB-REDIRECT-001")
    assert ssrf.metadata["framework_model"] == "express"
    assert ssrf.metadata["flow_model"] == "request_to_sink"
    assert ssrf.metadata["sink_kind"] == "network_request"
    assert ssrf.metadata["source_kind"] == "cookies"
    assert redirect.metadata["framework_model"] == "express"
    assert redirect.metadata["flow_model"] == "request_to_sink"
    assert redirect.metadata["sink_kind"] == "redirect"
    assert redirect.metadata["source_kind"] == "cookies"


def test_detects_potential_missing_auth_check(tmp_path: Path) -> None:
    auth_path = tmp_path / "profile.py"
    auth_path.write_text(
        "from flask import request\n"
        "@app.route('/profile')\n"
        "def profile():\n"
        "    return request.args.get('user')\n",
        encoding="utf-8",
    )

    findings = run_detectors(
        [
            ParsedDocument(
                path=auth_path,
                relative_path="profile.py",
                language=Language.PYTHON,
                framework=Framework.FLASK.value,
                syntax_valid=True,
                line_count=4,
                character_count=0,
            )
        ]
    )

    assert any(f.rule_id == "WEB-AUTH-001" for f in findings)


def test_detects_middleware_based_auth_guard(tmp_path: Path) -> None:
    auth_path = tmp_path / "protected.js"
    auth_path.write_text(
        "const express = require('express')\n"
        "const app = express()\n"
        "app.use(requireAuth)\n"
        "app.get('/profile', (req, res) => res.json(req.query.user))\n",
        encoding="utf-8",
    )

    findings = run_detectors(
        [
            ParsedDocument(
                path=auth_path,
                relative_path="protected.js",
                language=Language.JAVASCRIPT,
                framework=Framework.EXPRESS.value,
                syntax_valid=True,
                line_count=4,
                character_count=0,
            )
        ]
    )

    auth_findings = [finding for finding in findings if finding.rule_id == "WEB-AUTH-001"]

    assert len(auth_findings) == 1
    assert auth_findings[0].severity.value == "info"
    assert auth_findings[0].metadata["auth_model"] == "middleware"
    assert auth_findings[0].metadata["middleware_kind"] == "auth"
    assert auth_findings[0].metadata["auth_guard"] is True


def test_detects_python_auth_decorator_guard(tmp_path: Path) -> None:
    auth_path = tmp_path / "profile.py"
    auth_path.write_text(
        "from flask import redirect\n"
        "@login_required\n"
        "@app.route('/profile')\n"
        "def profile():\n"
        "    return redirect(request.args.get('next'))\n",
        encoding="utf-8",
    )

    findings = run_detectors(
        [
            ParsedDocument(
                path=auth_path,
                relative_path="profile.py",
                language=Language.PYTHON,
                framework=Framework.FLASK.value,
                syntax_valid=True,
                line_count=5,
                character_count=0,
            )
        ]
    )

    auth_findings = [finding for finding in findings if finding.rule_id == "WEB-AUTH-001"]

    assert len(auth_findings) == 1
    assert auth_findings[0].severity.value == "info"
    assert auth_findings[0].metadata["auth_guard"] is True
    assert auth_findings[0].metadata["auth_guard_kind"] == "auth_check"
    assert auth_findings[0].metadata["auth_model"] == "decorator"


def test_detects_role_based_auth_guard(tmp_path: Path) -> None:
    auth_path = tmp_path / "admin.py"
    auth_path.write_text(
        "from flask import redirect\n"
        "@app.route('/admin')\n"
        "def admin():\n"
        "    if hasRole('ADMIN'):\n"
        "        return redirect(request.args.get('next'))\n",
        encoding="utf-8",
    )

    findings = run_detectors(
        [
            ParsedDocument(
                path=auth_path,
                relative_path="admin.py",
                language=Language.PYTHON,
                framework=Framework.FLASK.value,
                syntax_valid=True,
                line_count=5,
                character_count=0,
            )
        ]
    )

    auth_findings = [finding for finding in findings if finding.rule_id == "WEB-AUTH-001"]

    assert len(auth_findings) == 1
    assert auth_findings[0].severity.value == "info"
    assert auth_findings[0].metadata["auth_guard"] is True
    assert auth_findings[0].metadata["auth_guard_kind"] == "role_check"
    assert auth_findings[0].metadata["auth_model"] == "role_check"
    assert auth_findings[0].metadata["role_model"] == "rbac"


def test_detects_auth_context_metadata(tmp_path: Path) -> None:
    auth_path = tmp_path / "auth.py"
    auth_path.write_text(
        "from django.shortcuts import redirect\n"
        "@app.route('/me')\n"
        "def me():\n"
        "    return redirect(request.user)\n",
        encoding="utf-8",
    )

    findings = run_detectors(
        [
            ParsedDocument(
                path=auth_path,
                relative_path="auth.py",
                language=Language.PYTHON,
                framework=Framework.DJANGO.value,
                syntax_valid=True,
                line_count=4,
                character_count=0,
            )
        ]
    )

    auth_context_findings = [finding for finding in findings if finding.metadata.get("source_kind") == "auth_context"]
    assert auth_context_findings
    assert any(finding.rule_id == "WEB-REDIRECT-001" for finding in findings)


def test_detects_exported_android_activity(tmp_path: Path) -> None:
    manifest_path = tmp_path / "AndroidManifest.xml"
    manifest_path.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">\n'
        '  <application android:label="@string/app_name">\n'
        '    <activity android:name=".MainActivity" android:exported="true">\n'
        '      <intent-filter>\n'
        '        <action android:name="android.intent.action.MAIN" />\n'
        '      </intent-filter>\n'
        '    </activity>\n'
        '    <activity android:name=".PrivateActivity" android:exported="false" />\n'
        '  </application>\n'
        '</manifest>\n',
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=manifest_path,
            relative_path="AndroidManifest.xml",
            language=Language.XML,
            framework=Framework.ANDROID.value,
            syntax_valid=True,
            line_count=10,
            character_count=0,
            metadata={
                "parser": "xml",
                "android_manifest": {
                    "package": "com.example.app",
                    "shared_user_id": None,
                    "uses_permissions": [],
                    "uses_features": [],
                    "application": {
                        "label": "@string/app_name",
                        "debuggable": None,
                        "allow_backup": None,
                        "uses_cleartext_traffic": None,
                    },
                    "components": [
                        {
                            "kind": "activity",
                            "name": ".MainActivity",
                            "exported": True,
                            "permission": None,
                            "intent_filter_count": 1,
                        },
                        {
                            "kind": "activity",
                            "name": ".PrivateActivity",
                            "exported": False,
                            "permission": None,
                            "intent_filter_count": 0,
                        },
                    ],
                },
            },
        )
    ]

    findings = run_detectors(documents)
    android_findings = [finding for finding in findings if finding.rule_id == "MOBILE-ANDROID-001"]

    assert len(android_findings) == 1
    finding = android_findings[0]
    assert finding.category == "mobile"
    assert finding.metadata["framework_model"] == "android"
    assert finding.metadata["component_kind"] == "activity"
    assert finding.metadata["component_name"] == ".MainActivity"
    assert finding.metadata["component_exported"] is True
    assert finding.metadata["intent_filter_count"] == 1
    assert finding.metadata["android_package"] == "com.example.app"


def test_detects_exported_android_receiver(tmp_path: Path) -> None:
    manifest_path = tmp_path / "AndroidManifest.xml"
    manifest_path.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">\n'
        '  <application android:label="@string/app_name">\n'
        '    <receiver android:name=".BootReceiver" android:exported="true">\n'
        '      <intent-filter>\n'
        '        <action android:name="android.intent.action.BOOT_COMPLETED" />\n'
        '      </intent-filter>\n'
        '    </receiver>\n'
        '    <receiver android:name=".PrivateReceiver" android:exported="false" />\n'
        '  </application>\n'
        '</manifest>\n',
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=manifest_path,
            relative_path="AndroidManifest.xml",
            language=Language.XML,
            framework=Framework.ANDROID.value,
            syntax_valid=True,
            line_count=10,
            character_count=0,
            metadata={
                "parser": "xml",
                "android_manifest": {
                    "package": "com.example.app",
                    "shared_user_id": None,
                    "uses_permissions": [],
                    "uses_features": [],
                    "application": {
                        "label": "@string/app_name",
                        "debuggable": None,
                        "allow_backup": None,
                        "uses_cleartext_traffic": None,
                    },
                    "components": [
                        {
                            "kind": "receiver",
                            "name": ".BootReceiver",
                            "exported": True,
                            "permission": None,
                            "intent_filter_count": 1,
                        },
                        {
                            "kind": "receiver",
                            "name": ".PrivateReceiver",
                            "exported": False,
                            "permission": None,
                            "intent_filter_count": 0,
                        },
                    ],
                },
            },
        )
    ]

    findings = run_detectors(documents)
    receiver_findings = [finding for finding in findings if finding.rule_id == "MOBILE-ANDROID-002"]

    assert len(receiver_findings) == 1
    finding = receiver_findings[0]
    assert finding.category == "mobile"
    assert finding.metadata["framework_model"] == "android"
    assert finding.metadata["component_kind"] == "receiver"
    assert finding.metadata["component_name"] == ".BootReceiver"
    assert finding.metadata["component_exported"] is True
    assert finding.metadata["intent_filter_count"] == 1


def test_detects_dangerous_android_permissions(tmp_path: Path) -> None:
    manifest_path = tmp_path / "AndroidManifest.xml"
    manifest_path.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">\n'
        '  <uses-permission android:name="android.permission.CAMERA" />\n'
        '  <uses-permission android:name="android.permission.INTERNET" />\n'
        '</manifest>\n',
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=manifest_path,
            relative_path="AndroidManifest.xml",
            language=Language.XML,
            framework=Framework.ANDROID.value,
            syntax_valid=True,
            line_count=5,
            character_count=0,
            metadata={
                "parser": "xml",
                "android_manifest": {
                    "package": "com.example.app",
                    "shared_user_id": None,
                    "uses_permissions": [
                        "android.permission.CAMERA",
                        "android.permission.INTERNET",
                    ],
                    "uses_features": [],
                    "application": {
                        "label": None,
                        "debuggable": None,
                        "allow_backup": None,
                        "uses_cleartext_traffic": None,
                    },
                    "components": [],
                },
            },
        )
    ]

    findings = run_detectors(documents)
    permission_findings = [finding for finding in findings if finding.rule_id == "MOBILE-ANDROID-003"]

    assert len(permission_findings) == 1
    finding = permission_findings[0]
    assert finding.category == "mobile"
    assert finding.metadata["framework_model"] == "android"
    assert finding.metadata["manifest_kind"] == "permission"
    assert finding.metadata["permission_name"] == "android.permission.CAMERA"
    assert finding.metadata["permission_risk"] == "dangerous"
    assert finding.metadata["android_package"] == "com.example.app"


def test_detects_insecure_android_shared_preferences(tmp_path: Path) -> None:
    java_path = tmp_path / "SettingsStore.java"
    java_path.write_text(
        "import android.content.Context;\n"
        "import android.content.SharedPreferences;\n"
        "class SettingsStore {\n"
        "  void save(Context context, String token) {\n"
        "    SharedPreferences prefs = context.getSharedPreferences(\"prefs\", Context.MODE_WORLD_READABLE);\n"
        "    prefs.edit().putString(\"token\", token).apply();\n"
        "    prefs.edit().putString(\"username\", \"alice\").apply();\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    documents = [
        ParsedDocument(
            path=java_path,
            relative_path="SettingsStore.java",
            language=Language.JAVA,
            framework=Framework.ANDROID.value,
            syntax_valid=True,
            line_count=9,
            character_count=0,
            metadata={"parser": "text"},
        )
    ]

    findings = run_detectors(documents)
    storage_findings = [finding for finding in findings if finding.rule_id == "MOBILE-ANDROID-004"]

    assert len(storage_findings) == 2
    modes = {finding.metadata["storage_risk"] for finding in storage_findings}
    assert modes == {"world_accessible_mode", "sensitive_value_in_plaintext"}
    assert any(finding.metadata["shared_preferences_mode"] == "world_readable" for finding in storage_findings)
    assert any(finding.metadata["shared_preferences_key"] == "token" for finding in storage_findings)
