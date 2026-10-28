"""STRIDE-based threat model generation from the asset map.

Auto-generates a threat model section for the audit report by mapping
discovered assets (entry points, data stores, external calls) to STRIDE
threat categories and flagging unguarded attack surfaces.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mantis.assetmap import AssetMap


@dataclass
class ThreatEntry:
    asset: str
    asset_file: str
    asset_line: int
    category: str       # STRIDE category
    threat: str
    guarded: bool
    guard_name: str


_STRIDE_MAP: dict[str, list[tuple[str, str]]] = {
    "entrypoint": [
        ("Spoofing", "Attacker impersonates a legitimate user at this endpoint"),
        ("Tampering", "Attacker sends crafted input to manipulate server state"),
        ("Repudiation", "Actions at this endpoint may not be auditable"),
        ("Denial of Service", "Endpoint may be abused for resource exhaustion"),
    ],
    "datastore": [
        ("Tampering", "Attacker modifies stored data via injection or direct access"),
        ("Information Disclosure", "Sensitive data may be leaked from this store"),
    ],
    "external": [
        ("Spoofing", "External service response may be forged (MITM)"),
        ("Information Disclosure", "Sensitive data sent to external service may leak"),
        ("Tampering", "SSRF via attacker-controlled URL to this call"),
    ],
    "sensitive": [
        ("Information Disclosure", "Sensitive value may be exposed in logs, errors, or responses"),
        ("Tampering", "Attacker may overwrite or inject this sensitive value"),
    ],
}


def build_threat_model(amap: "AssetMap") -> str:
    """Generate a compact STRIDE threat-model section from the asset map."""
    if not amap.nodes:
        return ""

    entries: list[ThreatEntry] = []
    for node in amap.nodes:
        stride_threats = _STRIDE_MAP.get(node.kind)
        if not stride_threats:
            continue
        guarded, guard_name = amap.is_guarded(node.file, node.line)
        for category, threat in stride_threats:
            entries.append(ThreatEntry(
                asset=node.name,
                asset_file=node.file,
                asset_line=node.line,
                category=category,
                threat=threat,
                guarded=guarded,
                guard_name=guard_name or "",
            ))

    if not entries:
        return ""

    lines: list[str] = [
        "## Threat Model (auto-generated)",
        "",
        "STRIDE-based threats inferred from the asset map. "
        "Unguarded assets (no detected auth middleware) are flagged.",
        "",
    ]

    ep_count = len(amap.entry_points)
    unguarded = sum(1 for ep in amap.entry_points
                    if not amap.is_guarded(ep.file, ep.line)[0])

    lines.append("### Attack surface summary")
    lines.append(f"- {ep_count} entry point(s), {unguarded} unguarded")
    lines.append(f"- {len(amap.trust_boundaries)} auth/middleware boundary(s)")
    lines.append(f"- {len(amap.data_stores)} data store operation(s)")
    lines.append(f"- {len(amap.externals)} external call(s)")
    lines.append("")

    if unguarded and amap.entry_points:
        lines.append("### Unguarded entry points")
        lines.append("")
        lines.append("| Endpoint | File | Line | Framework |")
        lines.append("|---|---|---|---|")
        for ep in amap.entry_points:
            if not amap.is_guarded(ep.file, ep.line)[0]:
                lines.append(f"| {ep.name} | `{ep.file}` | {ep.line} | {ep.detail} |")
        lines.append("")

    by_cat: dict[str, list[ThreatEntry]] = {}
    for e in entries:
        by_cat.setdefault(e.category, []).append(e)

    lines.append("### STRIDE threat matrix")
    lines.append("")
    lines.append("| Category | Threats | Unguarded | Assets |")
    lines.append("|---|---|---|---|")
    for cat in ("Spoofing", "Tampering", "Information Disclosure",
                "Repudiation", "Denial of Service", "Elevation of Privilege"):
        group = by_cat.get(cat, [])
        if not group:
            continue
        n_unguarded = sum(1 for e in group if not e.guarded)
        unique_assets = len({(e.asset_file, e.asset_line) for e in group})
        lines.append(f"| {cat} | {len(group)} | {n_unguarded} | {unique_assets} |")
    lines.append("")

    high_risk: list[str] = []
    for ep in amap.entry_points:
        if amap.is_guarded(ep.file, ep.line)[0]:
            continue
        file_nodes = amap._by_file.get(ep.file, [])
        has_data = any(n.kind == "datastore" for n in file_nodes)
        has_ext = any(n.kind == "external" for n in file_nodes)
        if has_data or has_ext:
            targets = []
            if has_data:
                targets.append("data store")
            if has_ext:
                targets.append("external call")
            high_risk.append(
                f"- `{ep.file}:{ep.line}` **{ep.name}** -- unguarded, "
                f"touches {' + '.join(targets)}"
            )
    if high_risk:
        lines.append("### High-risk paths (unguarded + data/external access)")
        lines.append("")
        lines.extend(high_risk[:20])
        lines.append("")

    return "\n".join(lines)
