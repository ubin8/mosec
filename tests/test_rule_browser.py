from __future__ import annotations

import json

from mosec.rule_browser import (
    build_builtin_rule_packs,
    render_rule_browser_json,
    render_rule_browser_lines,
    render_rule_browser_sarif,
)


def test_builtin_rule_packs_include_detector_rules() -> None:
    packs = build_builtin_rule_packs()
    builtin = packs[0]

    assert builtin.name == "builtin-detectors"
    assert builtin.version == "0.1.0"
    assert len(builtin.rules) >= 10
    assert any(rule.id == "WEB-SQLI-001" for rule in builtin.rules)
    assert any(rule.id == "MOBILE-ANDROID-001" for rule in builtin.rules)


def test_rule_browser_lines_show_selected_pack_and_categories() -> None:
    packs = build_builtin_rule_packs()

    lines = render_rule_browser_lines(packs)

    assert "Rules browser" in lines[0]
    assert "Selected pack: builtin-detectors@0.1.0" in lines
    assert any("Selected rule" in line for line in lines)
    assert any("Categories" in line for line in lines)
    assert any("Injection" in line for line in lines)
    assert any("WEB-SQLI-001" in line for line in lines)


def test_rule_browser_json_and_sarif_include_builtin_rules() -> None:
    packs = build_builtin_rule_packs()

    payload = json.loads(render_rule_browser_json(packs))
    sarif = json.loads(render_rule_browser_sarif(packs))

    assert payload["pack_count"] == 1
    assert payload["rule_count"] >= 10
    assert payload["selected_pack"]["name"] == "builtin-detectors"
    assert any(rule["id"] == "WEB-SQLI-001" for rule in payload["selected_pack"]["rules"])
    assert sarif["runs"][0]["invocations"][0]["properties"]["view_id"] == "rules"
    assert sarif["runs"][0]["tool"]["driver"]["rules"]
