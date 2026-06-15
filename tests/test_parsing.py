from pathlib import Path

from mosec.detection import Framework, Language, FileClassification
from mosec.ingestion import DiscoveredFile
from mosec.parsing import ParseSeverity, ParserRegistry, parse_files


def test_python_parser_reports_syntax_errors(tmp_path: Path) -> None:
    file_path = tmp_path / "broken.py"
    file_path.write_text("def broken(:\n    pass\n", encoding="utf-8")
    file = DiscoveredFile(path=file_path, relative_path="broken.py", size=file_path.stat().st_size)
    classification = FileClassification(
        path=file_path,
        relative_path="broken.py",
        language=Language.PYTHON,
        framework=Framework.FLASK,
    )

    parsed = ParserRegistry().parse(file, classification)

    assert parsed.syntax_valid is False
    assert parsed.issues[0].severity == ParseSeverity.ERROR


def test_parse_files_returns_structured_documents(tmp_path: Path) -> None:
    file_path = tmp_path / "settings.py"
    file_path.write_text("from flask import Flask\napp = Flask(__name__)\n", encoding="utf-8")
    file = DiscoveredFile(path=file_path, relative_path="settings.py", size=file_path.stat().st_size)
    classification = FileClassification(
        path=file_path,
        relative_path="settings.py",
        language=Language.PYTHON,
        framework=Framework.FLASK,
    )

    parsed = parse_files([file], [classification])

    assert len(parsed) == 1
    assert parsed[0].framework == "flask"
    assert parsed[0].metadata["parser"] == "python"
    assert parsed[0].ir is not None
    assert any(node.kind == "call" for node in parsed[0].ir.nodes)


def test_python_ir_extracts_assignments_literals_and_member_access(tmp_path: Path) -> None:
    file_path = tmp_path / "app.py"
    file_path.write_text(
        "class Example:\n"
        "    def run(self, user_input):\n"
        "        query = db.client.execute(user_input)\n"
        "        token = 'abc123'\n",
        encoding="utf-8",
    )
    file = DiscoveredFile(path=file_path, relative_path="app.py", size=file_path.stat().st_size)
    classification = FileClassification(
        path=file_path,
        relative_path="app.py",
        language=Language.PYTHON,
        framework=Framework.UNKNOWN,
    )

    parsed = ParserRegistry().parse(file, classification)

    assert parsed.ir is not None
    kinds = [node.kind for node in parsed.ir.nodes]
    assert "assignment" in kinds
    assert "call" in kinds
    assert "literal" in kinds
    assert "member_access" in kinds


def test_parse_files_respects_parser_overrides(tmp_path: Path) -> None:
    file_path = tmp_path / "script.py"
    file_path.write_text("def broken(:\n    pass\n", encoding="utf-8")
    file = DiscoveredFile(path=file_path, relative_path="script.py", size=file_path.stat().st_size)
    classification = FileClassification(
        path=file_path,
        relative_path="script.py",
        language=Language.PYTHON,
        framework=Framework.FLASK,
    )

    parsed = parse_files([file], [classification], parser_overrides={"python": "text"})

    assert parsed[0].syntax_valid is True
    assert parsed[0].metadata["parser"] == "text"


def test_json_and_toml_parsing_populates_normalized_ir(tmp_path: Path) -> None:
    json_path = tmp_path / "package.json"
    json_path.write_text('{"dependencies": {"express": "4.18.2"}}', encoding="utf-8")
    toml_path = tmp_path / "mosec.toml"
    toml_path.write_text('root = "."\n[parsers]\npython = "text"\n', encoding="utf-8")

    json_file = DiscoveredFile(path=json_path, relative_path="package.json", size=json_path.stat().st_size)
    toml_file = DiscoveredFile(path=toml_path, relative_path="mosec.toml", size=toml_path.stat().st_size)
    json_classification = FileClassification(
        path=json_path,
        relative_path="package.json",
        language=Language.JSON,
        framework=Framework.EXPRESS,
    )
    toml_classification = FileClassification(
        path=toml_path,
        relative_path="mosec.toml",
        language=Language.TOML,
        framework=Framework.UNKNOWN,
    )

    parsed = parse_files([json_file, toml_file], [json_classification, toml_classification])

    assert parsed[0].ir is not None
    assert parsed[1].ir is not None
    assert any(node.kind == "assignment" for node in parsed[0].ir.nodes)
    assert any(node.kind == "literal" for node in parsed[0].ir.nodes)
    assert any(node.kind == "assignment" for node in parsed[1].ir.nodes)
    assert any(node.kind == "literal" for node in parsed[1].ir.nodes)


def test_android_manifest_parser_collects_structured_metadata(tmp_path: Path) -> None:
    manifest_path = tmp_path / "AndroidManifest.xml"
    manifest_path.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">\n'
        '  <uses-permission android:name="android.permission.INTERNET" />\n'
        '  <uses-permission-sdk-23 android:name="android.permission.CAMERA" />\n'
        '  <uses-feature android:name="android.hardware.camera" />\n'
        '  <application android:label="@string/app_name" android:debuggable="true" android:allowBackup="false" android:usesCleartextTraffic="false">\n'
        '    <activity android:name=".MainActivity" android:exported="true">\n'
        '      <intent-filter>\n'
        '        <action android:name="android.intent.action.MAIN" />\n'
        '      </intent-filter>\n'
        '    </activity>\n'
        '    <receiver android:name=".BootReceiver" android:exported="false" />\n'
        '  </application>\n'
        '</manifest>\n',
        encoding="utf-8",
    )
    file = DiscoveredFile(path=manifest_path, relative_path="AndroidManifest.xml", size=manifest_path.stat().st_size)
    classification = FileClassification(
        path=manifest_path,
        relative_path="AndroidManifest.xml",
        language=Language.XML,
        framework=Framework.ANDROID,
    )

    parsed = ParserRegistry().parse(file, classification)

    assert parsed.metadata["parser"] == "xml"
    assert "android_manifest" in parsed.metadata
    android_manifest = parsed.metadata["android_manifest"]
    assert android_manifest["package"] == "com.example.app"
    assert "android.permission.INTERNET" in android_manifest["uses_permissions"]
    assert "android.permission.CAMERA" in android_manifest["uses_permissions"]
    assert "android.hardware.camera" in android_manifest["uses_features"]
    assert android_manifest["application"]["debuggable"] is True
    assert android_manifest["application"]["allow_backup"] is False
    assert android_manifest["application"]["uses_cleartext_traffic"] is False
    assert any(component["kind"] == "activity" for component in android_manifest["components"])
    assert any(component["kind"] == "receiver" for component in android_manifest["components"])
    assert any(component["exported"] is True for component in android_manifest["components"])
