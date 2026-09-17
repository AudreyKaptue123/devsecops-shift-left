#!/usr/bin/env python3
"""
security_gate.py

Point de decision centralise du pipeline DevSecOps.

Ce script remplace la logique de blocage auparavant eparpillee et
incoherente entre les jobs (un `bandit -ll` qui bloque, un job SCA et
un job IaC purement informatifs, cf. memoire section 4.8). Il lit les
rapports produits par les trois outils d'analyse (Bandit, pip-audit,
Hadolint), les normalise vers un modele de "finding" unique, calcule
une decision de blocage explicite selon une politique de severite
configurable par categorie, et produit :

  1. Un rapport SARIF fusionne (security-report.sarif), au format
     standard OASIS, exploitable par l'onglet "Security" de GitHub
     ou par tout autre outil compatible SARIF 2.1.0.
  2. Un rapport lisible (gate-report.md) destine au step summary
     GitHub Actions.
  3. Un code de sortie (0 = promotion autorisee, 1 = promotion
     refusee) qui pilote le job "gate" du pipeline.

Contrairement a la version precedente du pipeline (cf. memoire 4.9.2),
ce job est concu pour s'executer systematiquement, meme si un job
d'analyse amont a echoue (if: always() cote workflow), afin de
toujours produire un verdict explicite et trace plutot qu'une absence
d'execution.
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Modele normalise
# ---------------------------------------------------------------------------

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Finding:
    tool: str
    rule_id: str
    severity: str          # normalise sur LOW / MEDIUM / HIGH / CRITICAL
    message: str
    file_path: str = ""
    line: int = 0

    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)


@dataclass
class ToolResult:
    tool: str
    findings: list = field(default_factory=list)
    ran: bool = True
    error: str = ""


# ---------------------------------------------------------------------------
# Normalisation : Bandit (JSON natif) -> Finding
# ---------------------------------------------------------------------------

def load_bandit(path: Path) -> ToolResult:
    if not path.exists():
        return ToolResult(tool="bandit", ran=False, error=f"rapport introuvable : {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for item in data.get("results", []):
        findings.append(Finding(
            tool="bandit",
            rule_id=item.get("test_id", "B000"),
            severity=item.get("issue_severity", "LOW").upper(),
            message=item.get("issue_text", "").strip(),
            file_path=item.get("filename", ""),
            line=item.get("line_number", 0),
        ))
    return ToolResult(tool="bandit", findings=findings)


# ---------------------------------------------------------------------------
# Normalisation : pip-audit (JSON natif) -> Finding
# ---------------------------------------------------------------------------

def load_pip_audit(path: Path) -> ToolResult:
    if not path.exists():
        return ToolResult(tool="pip-audit", ran=False, error=f"rapport introuvable : {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    # pip-audit emet soit {"dependencies": [...]}, soit une liste directe
    # selon la version ; les deux formes sont gerees ici.
    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    for dep in deps:
        name = dep.get("name", "?")
        version = dep.get("version", "?")
        for vuln in dep.get("vulns", []):
            vuln_id = vuln.get("id", "PYSEC-UNKNOWN")
            fix_versions = ", ".join(vuln.get("fix_versions", []) or []) or "aucun correctif connu"
            # pip-audit ne fournit pas de severite normalisee : toute
            # vulnerabilite publiee (CVE/PYSEC) est traitee par defaut
            # comme HIGH, politique volontairement prudente documentee
            # au chapitre 4 du memoire.
            findings.append(Finding(
                tool="pip-audit",
                rule_id=vuln_id,
                severity="HIGH",
                message=f"{name} {version} : {vuln_id} (correctif : {fix_versions})",
                file_path="requirements.txt",
            ))
    return ToolResult(tool="pip-audit", findings=findings)


# ---------------------------------------------------------------------------
# Normalisation : Hadolint (SARIF natif) -> Finding
# ---------------------------------------------------------------------------

HADOLINT_LEVEL_TO_SEVERITY = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "LOW",
}


def load_hadolint_sarif(path: Path) -> ToolResult:
    if not path.exists():
        return ToolResult(tool="hadolint", ran=False, error=f"rapport introuvable : {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for run in data.get("runs", []):
        rules_index = {
            r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "DL0000")
            level = result.get("level", "warning")
            severity = HADOLINT_LEVEL_TO_SEVERITY.get(level, "MEDIUM")
            message = result.get("message", {}).get("text", "")
            location = result.get("locations", [{}])[0]
            phys = location.get("physicalLocation", {})
            file_path = phys.get("artifactLocation", {}).get("uri", "Dockerfile")
            line = phys.get("region", {}).get("startLine", 0)
            findings.append(Finding(
                tool="hadolint", rule_id=rule_id, severity=severity,
                message=message, file_path=file_path, line=line,
            ))
    return ToolResult(tool="hadolint", findings=findings)


# ---------------------------------------------------------------------------
# Politique de blocage (configurable par categorie)
# ---------------------------------------------------------------------------

DEFAULT_POLICY = {
    # categorie : severite minimale bloquante
    "bandit": "HIGH",
    "pip-audit": "HIGH",
    "hadolint": "HIGH",
}


def evaluate_gate(results: list, policy: dict) -> tuple:
    """Retourne (autorise: bool, raisons_de_blocage: list[str])."""
    blocking = []
    for result in results:
        threshold = SEVERITY_RANK[policy.get(result.tool, "HIGH")]
        for f in result.findings:
            if f.rank() >= threshold:
                blocking.append(f"[{f.tool}] {f.rule_id} ({f.severity}) : {f.message[:100]}")
    return (len(blocking) == 0, blocking)


# ---------------------------------------------------------------------------
# Emission SARIF fusionnee (format standard, exploitable par GitHub)
# ---------------------------------------------------------------------------

def to_sarif(results: list) -> dict:
    runs = []
    for result in results:
        rules = {}
        sarif_results = []
        for f in result.findings:
            rules.setdefault(f.rule_id, {
                "id": f.rule_id,
                "shortDescription": {"text": f.rule_id},
            })
            sarif_results.append({
                "ruleId": f.rule_id,
                "level": {"LOW": "note", "MEDIUM": "warning", "HIGH": "error", "CRITICAL": "error"}[f.severity],
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path or "unknown"},
                        "region": {"startLine": max(f.line, 1)},
                    }
                }],
            })
        runs.append({
            "tool": {"driver": {"name": result.tool, "rules": list(rules.values())}},
            "results": sarif_results,
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }


# ---------------------------------------------------------------------------
# Rapport Markdown (destine au step summary GitHub Actions)
# ---------------------------------------------------------------------------

def to_markdown(results: list, allowed: bool, blocking: list, policy: dict) -> str:
    lines = ["# Rapport du Security Gate", ""]
    lines.append(f"Genere le {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    lines.append("")
    lines.append("| Outil | Findings | Seuil de blocage | Statut |")
    lines.append("|---|---|---|---|")
    for r in results:
        status = "N/A (non execute)" if not r.ran else ("OK" if not any(
            f.rank() >= SEVERITY_RANK[policy.get(r.tool, "HIGH")] for f in r.findings
        ) else "BLOQUANT")
        lines.append(f"| {r.tool} | {len(r.findings)} | >= {policy.get(r.tool, 'HIGH')} | {status} |")
    lines.append("")
    lines.append(f"## Decision : {'PROMOTION AUTORISEE' if allowed else 'PROMOTION REFUSEE'}")
    lines.append("")
    if blocking:
        lines.append("### Findings bloquants")
        for b in blocking:
            lines.append(f"- {b}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Point d'entree
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bandit", type=Path, default=Path("bandit-report.json"))
    parser.add_argument("--pip-audit", type=Path, default=Path("sca-report.json"))
    parser.add_argument("--hadolint", type=Path, default=Path("hadolint-report.sarif"))
    parser.add_argument("--sarif-out", type=Path, default=Path("security-report.sarif"))
    parser.add_argument("--markdown-out", type=Path, default=Path("gate-report.md"))
    args = parser.parse_args()

    results = [
        load_bandit(args.bandit),
        load_pip_audit(args.pip_audit),
        load_hadolint_sarif(args.hadolint),
    ]

    for r in results:
        if not r.ran:
            print(f"[avertissement] {r.tool} : {r.error}", file=sys.stderr)

    allowed, blocking = evaluate_gate(results, DEFAULT_POLICY)

    args.sarif_out.write_text(json.dumps(to_sarif(results), indent=2), encoding="utf-8")
    report_md = to_markdown(results, allowed, blocking, DEFAULT_POLICY)
    args.markdown_out.write_text(report_md, encoding="utf-8")

    print(report_md)

    sys.exit(0 if allowed else 1)


if __name__ == "__main__":
    main()
