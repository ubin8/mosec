from pathlib import Path

from mosec.detection import Framework, Language, classify_file
from mosec.ingestion import DiscoveredFile


def test_detect_python_framework_from_content(tmp_path: Path) -> None:
    file_path = tmp_path / "app.py"
    file_path.write_text("from flask import Flask\n", encoding="utf-8")
    file = DiscoveredFile(path=file_path, relative_path="app.py", size=file_path.stat().st_size)

    classification = classify_file(file)

    assert classification.language == Language.PYTHON
    assert classification.framework == Framework.FLASK
    assert "python:flask" in classification.signals


def test_detect_package_json_framework(tmp_path: Path) -> None:
    file_path = tmp_path / "package.json"
    file_path.write_text(
        '{"dependencies": {"next": "14.0.0", "react": "18.2.0"}}',
        encoding="utf-8",
    )
    file = DiscoveredFile(path=file_path, relative_path="package.json", size=file_path.stat().st_size)

    classification = classify_file(file)

    assert classification.language == Language.JSON
    assert classification.framework == Framework.NEXTJS


def test_detect_java_and_kotlin_spring_framework(tmp_path: Path) -> None:
    java_path = tmp_path / "src" / "main" / "java" / "com" / "example" / "DemoController.java"
    java_path.parent.mkdir(parents=True, exist_ok=True)
    java_path.write_text(
        "import org.springframework.web.bind.annotation.GetMapping;\n"
        "import org.springframework.web.bind.annotation.RequestParam;\n"
        "@RestController\n"
        "class DemoController {}\n",
        encoding="utf-8",
    )
    kotlin_path = tmp_path / "src" / "main" / "kotlin" / "com" / "example" / "DemoController.kt"
    kotlin_path.parent.mkdir(parents=True, exist_ok=True)
    kotlin_path.write_text(
        "import org.springframework.web.bind.annotation.PostMapping\n"
        "import org.springframework.web.bind.annotation.RequestBody\n"
        "@RestController\n"
        "class DemoController\n",
        encoding="utf-8",
    )

    java = classify_file(DiscoveredFile(path=java_path, relative_path=str(java_path.relative_to(tmp_path)), size=java_path.stat().st_size))
    kotlin = classify_file(DiscoveredFile(path=kotlin_path, relative_path=str(kotlin_path.relative_to(tmp_path)), size=kotlin_path.stat().st_size))

    assert java.language == Language.JAVA
    assert java.framework == Framework.SPRING
    assert "java:spring-controller" in java.signals
    assert kotlin.language == Language.KOTLIN
    assert kotlin.framework == Framework.SPRING
    assert "java:spring-controller" in kotlin.signals


def test_detect_java_android_framework_from_shared_preferences_code(tmp_path: Path) -> None:
    java_path = tmp_path / "SettingsStore.java"
    java_path.write_text(
        "import android.content.Context;\n"
        "import android.content.SharedPreferences;\n"
        "class SettingsStore {\n"
        "  void save(Context context, String token) {\n"
        "    SharedPreferences prefs = context.getSharedPreferences(\"prefs\", Context.MODE_PRIVATE);\n"
        "    prefs.edit().putString(\"token\", token).apply();\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    classification = classify_file(DiscoveredFile(path=java_path, relative_path=str(java_path.relative_to(tmp_path)), size=java_path.stat().st_size))

    assert classification.language == Language.JAVA
    assert classification.framework == Framework.ANDROID
    assert "java:android" in classification.signals


def test_detect_php_laravel_framework(tmp_path: Path) -> None:
    php_path = tmp_path / "routes" / "web.php"
    php_path.parent.mkdir(parents=True, exist_ok=True)
    php_path.write_text(
        "<?php\n"
        "use Illuminate\\Support\\Facades\\Route;\n"
        "Route::get('/proxy', function () { return 'ok'; });\n",
        encoding="utf-8",
    )

    classification = classify_file(DiscoveredFile(path=php_path, relative_path=str(php_path.relative_to(tmp_path)), size=php_path.stat().st_size))

    assert classification.language == Language.PHP
    assert classification.framework == Framework.LARAVEL
    assert "php:laravel" in classification.signals


def test_detect_android_and_ios_metadata(tmp_path: Path) -> None:
    android_path = tmp_path / "AndroidManifest.xml"
    android_path.write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application /></manifest>',
        encoding="utf-8",
    )
    ios_path = tmp_path / "Info.plist"
    ios_path.write_text(
        "<?xml version='1.0'?><plist><dict><key>NSAppTransportSecurity</key></dict></plist>",
        encoding="utf-8",
    )

    android = classify_file(DiscoveredFile(path=android_path, relative_path="AndroidManifest.xml", size=android_path.stat().st_size))
    ios = classify_file(DiscoveredFile(path=ios_path, relative_path="Info.plist", size=ios_path.stat().st_size))

    assert android.framework == Framework.ANDROID
    assert ios.framework == Framework.IOS
