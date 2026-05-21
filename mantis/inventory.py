"""Stage 0: inventory.

Detect stack, lockfiles, entrypoints — by file presence only, never by
reading source contents end-to-end. Suggests one or more packs based on
what's found, mirroring the cheat sheet in agents/sast-orchestrator.md.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Stack:
    detected: set[str] = field(default_factory=set)
    lockfiles: list[Path] = field(default_factory=list)
    has_llm_sdk: bool = False


@dataclass
class Inventory:
    target: Path
    stack: Stack
    packs: list[str]
    rationale: list[str]


_LOCKFILES = (
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Pipfile.lock", "poetry.lock", "uv.lock",
    "Cargo.lock", "go.sum", "Gemfile.lock",
    "composer.lock", "gradle.lockfile",
)


def _glob_any(root: Path, patterns: list[str], limit: int = 5) -> list[Path]:
    out: list[Path] = []
    for pat in patterns:
        for p in root.rglob(pat):
            if any(part.startswith(".") and part not in (".", "..") for part in p.relative_to(root).parts):
                continue
            if "node_modules" in p.parts or "vendor" in p.parts or "build" in p.parts:
                continue
            out.append(p)
            if len(out) >= limit:
                return out
    return out


def _scan_package_json(path: Path) -> tuple[bool, bool]:
    """Return (is_react_native, has_llm_sdk) without reading line-by-line."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return (False, False)
    deps = {}
    for k in ("dependencies", "devDependencies", "peerDependencies"):
        deps.update(data.get(k) or {})
    rn = "react-native" in deps
    llm = any(d in deps for d in (
        "openai", "@anthropic-ai/sdk", "anthropic", "@google/generative-ai",
        "langchain", "@langchain/core", "llamaindex", "@pinecone-database/pinecone",
        "chromadb", "@qdrant/js-client-rest",
    ))
    return (rn, llm)


_LLM_PY_DISTS = {
    "openai", "anthropic", "google-generativeai", "google-genai",
    "langchain", "langchain-core", "langchain-community",
    "llama-index", "llama-index-core",
    "pinecone-client", "chromadb", "qdrant-client", "weaviate-client",
    "cohere", "mistralai", "litellm",
}

_PY_DIST_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _scan_python_requirements(target: Path) -> bool:
    """Parse Python dep files line-by-line; match bare distribution names."""
    files = []
    for fname in ("requirements.txt", "requirements-dev.txt", "requirements_dev.txt",
                  "dev-requirements.txt", "Pipfile"):
        f = target / fname
        if f.is_file():
            files.append(f)

    for f in files:
        try:
            for raw in f.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                m = _PY_DIST_NAME.match(line)
                if not m:
                    continue
                name = m.group(1).lower()
                if name in _LLM_PY_DISTS:
                    return True
        except OSError:
            continue

    pyproject = target / "pyproject.toml"
    if pyproject.is_file():
        try:
            text = pyproject.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        # Cheap match: a quoted dep name on its own. Avoids substring hits
        # in URLs / comments / descriptions.
        if re.search(
            r'["\']\s*(' + "|".join(re.escape(n) for n in _LLM_PY_DISTS) + r')\s*[\[<=>~!,"\']',
            text, re.IGNORECASE,
        ):
            return True
    return False


_K8S_MARKERS = (
    re.compile(rb"^\s*apiVersion\s*:", re.MULTILINE),
    re.compile(rb"^\s*kind\s*:\s*(Deployment|Service|Pod|StatefulSet|DaemonSet|"
               rb"ConfigMap|Secret|Ingress|Job|CronJob)\s*$", re.MULTILINE),
)


def _has_infra_signals(target: Path) -> bool:
    """Distinguish real infra (Dockerfile / Terraform / k8s) from any .yaml."""
    if (target / "Dockerfile").is_file():
        return True
    if (target / "docker-compose.yml").is_file() or (target / "docker-compose.yaml").is_file():
        return True
    # Any *.tf file in the top three levels counts as Terraform.
    for p in target.glob("*.tf"):
        return True
    for p in target.glob("*/*.tf"):
        return True
    # k8s manifests need the apiVersion/kind markers — most .yaml in a repo
    # are not k8s (rule files, CI configs, mantis config).
    for yaml_path in list(target.glob("*.yaml")) + list(target.glob("k8s/*.yaml")) + \
                     list(target.glob("manifests/*.yaml")) + list(target.glob("deploy/*.yaml")):
        try:
            raw = yaml_path.read_bytes()[:4096]
        except OSError:
            continue
        if any(m.search(raw) for m in _K8S_MARKERS):
            return True
    return False


def take_inventory(target: Path) -> Inventory:
    target = target.resolve()
    stack = Stack()
    rationale: list[str] = []

    if _glob_any(target, ["*.swift", "Podfile", "*.xcodeproj"]):
        stack.detected.add("ios")
    # Android = AndroidManifest.xml (definitive). Kotlin + Gradle alone is
    # ambiguous (could be a JVM server) — mark `jvm` for those.
    has_manifest = bool(_glob_any(target, ["AndroidManifest.xml"]))
    has_gradle = bool(_glob_any(target, ["build.gradle", "build.gradle.kts", "settings.gradle"]))
    has_kt = bool(_glob_any(target, ["*.kt", "*.kts"]))
    has_java = bool(_glob_any(target, ["*.java"]))
    if has_manifest:
        stack.detected.add("android")
    elif (has_kt or has_java) and has_gradle:
        stack.detected.add("jvm")
    if (target / "pubspec.yaml").is_file():
        stack.detected.add("flutter")
    if (target / "package.json").is_file():
        rn, has_llm = _scan_package_json(target / "package.json")
        stack.detected.add("react-native" if rn else "js-web")
        if has_llm:
            stack.has_llm_sdk = True
    if _glob_any(target, ["requirements*.txt", "pyproject.toml", "Pipfile"]):
        stack.detected.add("python")
        if _scan_python_requirements(target):
            stack.has_llm_sdk = True
    if (target / "go.mod").is_file():
        stack.detected.add("go")
    if _has_infra_signals(target):
        stack.detected.add("infra")

    for name in _LOCKFILES:
        p = target / name
        if p.is_file():
            stack.lockfiles.append(p)

    packs: list[str] = []
    if "ios" in stack.detected and "android" not in stack.detected:
        packs.append("mobile-ios")
        rationale.append("ios-only stack -> mobile-ios pack")
    elif "android" in stack.detected and "ios" not in stack.detected:
        packs.append("mobile-android")
        rationale.append("android-only stack -> mobile-android pack")
    elif "ios" in stack.detected or "android" in stack.detected:
        packs.append("mobile")
        rationale.append("multi-platform mobile -> mobile pack")
    elif "react-native" in stack.detected or "flutter" in stack.detected:
        packs.append("mobile")
        rationale.append("cross-platform mobile -> mobile pack")

    if "js-web" in stack.detected or "python" in stack.detected or \
       "go" in stack.detected or "jvm" in stack.detected:
        packs.append("web")
        rationale.append("server-side stack -> web pack")

    if stack.has_llm_sdk:
        packs.append("llm")
        rationale.append("LLM SDK detected -> llm pack")

    if stack.lockfiles and "cve" not in packs:
        packs.append("sca")
        rationale.append(f"{len(stack.lockfiles)} lockfile(s) -> sca pack")

    if not packs:
        packs.append("fast")
        rationale.append("no stack detected -> fast pack (default)")

    seen = set()
    deduped: list[str] = []
    for p in packs:
        if p not in seen:
            seen.add(p)
            deduped.append(p)
    return Inventory(target=target, stack=stack, packs=deduped, rationale=rationale)


MODE_TO_PACKS: dict[str, list[str]] = {
    "quick": ["fast"],
    "deep":  ["deep"],
    "bugbounty": ["bugbounty"],
    "cve": ["cve", "sca"],
    "mobile": ["mobile"],
    "web": ["web"],
    "llm": ["llm"],
    "taint": ["taint"],
}


def packs_for(mode: str | None, inv: Inventory) -> list[str]:
    if mode:
        m = mode.lower()
        if m not in MODE_TO_PACKS:
            raise ValueError(f"unknown mode: {mode!r}")
        return MODE_TO_PACKS[m]
    return inv.packs
