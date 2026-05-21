from __future__ import annotations

from pathlib import Path

import pytest

from mantis.inventory import MODE_TO_PACKS, packs_for, take_inventory


def test_empty_dir_defaults_to_fast(tmp_path):
    inv = take_inventory(tmp_path)
    assert inv.packs == ["fast"]


def test_ios_only_picks_mobile_ios(tmp_path):
    (tmp_path / "Podfile").write_text("source 'https://cdn.cocoapods.org/'\n")
    (tmp_path / "App.swift").write_text("import Foundation\n")
    inv = take_inventory(tmp_path)
    assert "mobile-ios" in inv.packs
    assert "ios" in inv.stack.detected


def test_android_only_picks_mobile_android(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text("<manifest/>\n")
    (tmp_path / "build.gradle").write_text("apply plugin: 'com.android.application'\n")
    inv = take_inventory(tmp_path)
    assert "mobile-android" in inv.packs


def test_gradle_without_manifest_is_jvm_not_android(tmp_path):
    """A Java server using Gradle must not be mistaken for an Android app."""
    (tmp_path / "build.gradle").write_text("apply plugin: 'java'\n")
    (tmp_path / "App.java").write_text("class App {}\n")
    inv = take_inventory(tmp_path)
    assert "android" not in inv.stack.detected
    assert "jvm" in inv.stack.detected
    assert "web" in inv.packs
    assert "mobile-android" not in inv.packs


def test_kotlin_backend_without_manifest_is_jvm(tmp_path):
    (tmp_path / "build.gradle.kts").write_text("plugins { kotlin(\"jvm\") }\n")
    (tmp_path / "Main.kt").write_text("fun main() {}\n")
    inv = take_inventory(tmp_path)
    assert "android" not in inv.stack.detected
    assert "jvm" in inv.stack.detected


def test_dual_mobile_picks_mobile(tmp_path):
    (tmp_path / "Podfile").write_text("a\n")
    (tmp_path / "AndroidManifest.xml").write_text("<manifest/>\n")
    inv = take_inventory(tmp_path)
    assert "mobile" in inv.packs


def test_python_with_llm_dep_picks_llm(tmp_path):
    (tmp_path / "requirements.txt").write_text("anthropic\nflask\n")
    inv = take_inventory(tmp_path)
    assert "web" in inv.packs
    assert "llm" in inv.packs


def test_python_no_llm_dep_no_llm_pack(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask\nsqlalchemy\n")
    inv = take_inventory(tmp_path)
    assert "llm" not in inv.packs


def test_react_native_picks_mobile(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react-native": "0.74.0"}}'
    )
    inv = take_inventory(tmp_path)
    assert "mobile" in inv.packs


def test_node_server_picks_web(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"express": "4.18.0"}}'
    )
    inv = take_inventory(tmp_path)
    assert "web" in inv.packs


def test_lockfile_adds_sca(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "1.0.0"}}')
    (tmp_path / "package-lock.json").write_text("{}")
    inv = take_inventory(tmp_path)
    assert "sca" in inv.packs
    assert any("lockfile" in r for r in inv.rationale)


def test_mode_override_wins(tmp_path):
    (tmp_path / "Podfile").write_text("a\n")
    inv = take_inventory(tmp_path)
    assert packs_for("bugbounty", inv) == MODE_TO_PACKS["bugbounty"]
    assert packs_for("deep", inv) == ["deep"]


def test_unknown_mode_raises(tmp_path):
    inv = take_inventory(tmp_path)
    with pytest.raises(ValueError):
        packs_for("turbo", inv)


def test_mode_none_returns_inventory_packs(tmp_path):
    (tmp_path / "Podfile").write_text("a\n")
    inv = take_inventory(tmp_path)
    assert packs_for(None, inv) == inv.packs
