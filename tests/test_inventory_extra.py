"""Tests for the tightened inventory detection (gaps #5 and #6)."""
from __future__ import annotations

from pathlib import Path

from mantis.inventory import take_inventory


def test_random_yaml_does_not_trigger_infra(tmp_path):
    (tmp_path / "config.yaml").write_text("foo: bar\n")
    (tmp_path / ".mantis.yaml").write_text("provider: google\n")
    inv = take_inventory(tmp_path)
    assert "infra" not in inv.stack.detected


def test_k8s_manifest_does_trigger_infra(tmp_path):
    (tmp_path / "deployment.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\n"
    )
    inv = take_inventory(tmp_path)
    assert "infra" in inv.stack.detected


def test_dockerfile_triggers_infra(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n")
    inv = take_inventory(tmp_path)
    assert "infra" in inv.stack.detected


def test_terraform_triggers_infra(tmp_path):
    (tmp_path / "main.tf").write_text("resource \"aws_s3_bucket\" \"x\" {}\n")
    inv = take_inventory(tmp_path)
    assert "infra" in inv.stack.detected


def test_substring_anthropic_does_not_trigger_llm(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# we used to depend on anthropic-mock-pkg\n"
        "not-anthropic==1.0\n"
        "flask==2.0\n"
    )
    inv = take_inventory(tmp_path)
    assert "llm" not in inv.packs


def test_real_anthropic_dep_triggers_llm(tmp_path):
    (tmp_path / "requirements.txt").write_text("anthropic>=0.40\nflask\n")
    inv = take_inventory(tmp_path)
    assert "llm" in inv.packs


def test_quoted_openai_in_pyproject_triggers_llm(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'x'\ndependencies = [\n  'openai>=1.0',\n  'flask',\n]\n"
    )
    inv = take_inventory(tmp_path)
    assert "llm" in inv.packs


def test_pyproject_url_mentioning_openai_does_not_trigger(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'x'\nurls = { homepage = 'https://openai-cookbook.dev/' }\n"
        "dependencies = [ 'flask' ]\n"
    )
    inv = take_inventory(tmp_path)
    assert "llm" not in inv.packs
