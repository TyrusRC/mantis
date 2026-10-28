"""Tests for the asset map (stage 0b) and threat model."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from mantis.assetmap import AssetMap, AssetNode, build_asset_map, _scan_file


# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------

def test_flask_route():
    code = textwrap.dedent("""\
        from flask import Flask
        app = Flask(__name__)

        @app.route('/api/users', methods=['GET'])
        def list_users():
            return jsonify(users)
    """)
    nodes = _scan_file(code, "python", "app.py")
    assert any(n.kind == "entrypoint" and "/api/users" in n.name for n in nodes)


def test_express_route():
    code = textwrap.dedent("""\
        const express = require('express');
        const app = express();

        app.get('/api/items', (req, res) => {
            res.json(items);
        });
    """)
    nodes = _scan_file(code, "javascript", "server.js")
    assert any(n.kind == "entrypoint" and "/api/items" in n.name for n in nodes)


def test_spring_mapping():
    code = textwrap.dedent("""\
        @RestController
        public class UserController {
            @GetMapping("/users")
            public List<User> getUsers() { return userService.findAll(); }
        }
    """)
    nodes = _scan_file(code, "java", "UserController.java")
    eps = [n for n in nodes if n.kind == "entrypoint"]
    assert len(eps) >= 2  # @RestController + @GetMapping


def test_go_handler():
    code = textwrap.dedent("""\
        package main
        import "net/http"
        func handleHealth(w http.ResponseWriter, r *http.Request) {
            w.Write([]byte("ok"))
        }
    """)
    nodes = _scan_file(code, "go", "main.go")
    assert any(n.kind == "entrypoint" and "handleHealth" in n.name for n in nodes)


def test_django_orm_datastore():
    code = textwrap.dedent("""\
        from myapp.models import User
        users = User.objects.filter(active=True)
    """)
    nodes = _scan_file(code, "python", "views.py")
    assert any(n.kind == "datastore" and "filter" in n.name for n in nodes)


def test_auth_middleware_python():
    code = textwrap.dedent("""\
        @login_required
        def dashboard(request):
            return render(request, 'dashboard.html')
    """)
    nodes = _scan_file(code, "python", "views.py")
    assert any(n.kind == "middleware" and "login_required" in n.name for n in nodes)


def test_sensitive_var():
    code = textwrap.dedent("""\
        password = input("Enter password: ")
        api_key = os.getenv("API_KEY")
    """)
    nodes = _scan_file(code, "python", "config.py")
    sensitive = [n for n in nodes if n.kind == "sensitive"]
    assert len(sensitive) >= 2


def test_external_call():
    code = textwrap.dedent("""\
        import requests
        resp = requests.post("https://api.example.com/notify", json=data)
    """)
    nodes = _scan_file(code, "python", "notify.py")
    assert any(n.kind == "external" and "post" in n.name for n in nodes)


# ---------------------------------------------------------------------------
# AssetMap queries
# ---------------------------------------------------------------------------

def test_context_for():
    amap = AssetMap(nodes=[
        AssetNode("entrypoint", "POST /api/login", "auth.py", 10, "flask", "python"),
        AssetNode("middleware", "login_required", "auth.py", 8, "py-auth-decorator", "python"),
        AssetNode("datastore", "execute", "auth.py", 15, "sql-execute", "python"),
    ])
    amap._index()

    ctx = amap.context_for("auth.py", 15)
    assert "ENTRY:" in ctx
    assert "POST /api/login" in ctx
    assert "AUTH:" in ctx
    assert "login_required" in ctx
    assert "DATA:" in ctx


def test_is_guarded():
    amap = AssetMap(nodes=[
        AssetNode("middleware", "login_required", "views.py", 5, "py-auth-decorator", "python"),
        AssetNode("entrypoint", "GET /dashboard", "views.py", 7, "flask", "python"),
    ])
    amap._index()
    guarded, name = amap.is_guarded("views.py", 7)
    assert guarded
    assert name == "login_required"

    guarded2, _ = amap.is_guarded("views.py", 3)
    assert not guarded2


def test_has_entry_point():
    amap = AssetMap(nodes=[
        AssetNode("entrypoint", "GET /", "app.py", 1, "flask", "python"),
    ])
    amap._index()
    assert amap.has_entry_point("app.py")
    assert not amap.has_entry_point("other.py")


# ---------------------------------------------------------------------------
# Threat model
# ---------------------------------------------------------------------------

def test_threat_model_output():
    amap = AssetMap(nodes=[
        AssetNode("entrypoint", "POST /api/register", "api.py", 10, "flask", "python"),
        AssetNode("datastore", "execute", "api.py", 20, "sql-execute", "python"),
    ])
    amap._index()

    tm = amap.threat_model()
    assert "Threat Model" in tm
    assert "STRIDE" in tm
    assert "Unguarded entry points" in tm
    assert "POST /api/register" in tm
    assert "High-risk paths" in tm


def test_threat_model_empty():
    amap = AssetMap()
    amap._index()
    assert amap.threat_model() == ""


# ---------------------------------------------------------------------------
# Integration: build_asset_map on a temp directory
# ---------------------------------------------------------------------------

def test_build_asset_map_integration(tmp_path):
    (tmp_path / "app.py").write_text(textwrap.dedent("""\
        from flask import Flask
        app = Flask(__name__)

        @app.route('/health')
        def health():
            return 'ok'

        @app.post('/api/data')
        def create_data():
            db.session.add(item)
            db.session.commit()
            return jsonify(item)
    """))
    (tmp_path / "utils.js").write_text(textwrap.dedent("""\
        const axios = require('axios');
        async function fetchData() {
            const resp = await axios.get('https://api.example.com/data');
            return resp.data;
        }
    """))

    amap = build_asset_map(tmp_path)

    assert amap.indexed_files == 2
    assert len(amap.entry_points) >= 2  # /health + /api/data
    assert len(amap.data_stores) >= 1   # db.session.add/commit
    assert len(amap.externals) >= 1     # axios.get

    summary = amap.summary()
    assert "entrypoint" in summary

    tm = amap.threat_model()
    assert "Threat Model" in tm
