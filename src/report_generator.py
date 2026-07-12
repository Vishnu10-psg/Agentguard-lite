"""
report_generator.py - Ranked risk report + CSV export for AgentGuard-lite (PB-10)

Built against the OFFICIAL dataset schema. Combines dependency-level and
application-level scores into a ranked report with remediation suggestions,
and exports to CSV for audit/judge review.
"""
import csv
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parent))
from data_loader import load_all
from risk_scorer import score_all_dependencies, score_applications

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "data" / "outputs"

# Remediation map: library -> (safer alternative / fix, reason)
# Distinguishes "version upgrade is the real fix" from genuine library swaps.
REMEDIATION_MAP = {
    "log4j-core": ("Upgrade to log4j-core >= 2.17.1", "Patched version closes the JNDI lookup RCE (Log4Shell)."),
    "snakeyaml": ("Upgrade to the fixed_version listed in the CVE record", "Open redirect / unsafe loading issues are patched in later releases."),
    "jackson-databind": ("Upgrade to the latest patched Jackson release", "Multiple deserialization CVEs fixed across recent versions."),
    "commons-io": ("Upgrade to the latest Apache Commons IO release", "Multiple CVEs patched across releases; no alternative library needed."),
    "guava": ("Upgrade Guava to the latest version", "Google actively maintains Guava; version upgrade is the standard fix."),
    "requests": ("Upgrade to Requests >= 2.31.0, or migrate to httpx", "Proxy-Authorization header leak on redirect; fixed in later versions."),
}
DEFAULT_REMEDIATION = ("Upgrade to the fixed_version noted in the vulnerability record",
                       "Check the library's changelog/advisory for the specific fixing release.")


def get_remediation(library_name):
    return REMEDIATION_MAP.get(library_name, DEFAULT_REMEDIATION)


def build_findings(scored_deps, top_n=10):
    """Top N riskiest dependencies across the whole portfolio."""
    risky = [d for d in scored_deps if d["final_score"] > 0]
    risky.sort(key=lambda d: d["final_score"], reverse=True)

    findings = []
    for d in risky[:top_n]:
        alt, reason = get_remediation(d["library"])
        cve_list = ", ".join(h["cve_id"] for h in d["cve_hits"]) if d["cve_hits"] else "None"
        findings.append({
            "application_id": d["application_id"],
            "library": f"{d['library']}@{d['version']}",
            "risk_score": d["final_score"],
            "cves": cve_list,
            "license_issue": "Yes" if d["license_penalty"] > 0 else "No",
            "unmaintained": "Yes" if d["is_unmaintained"] else "No",
            "remediation": alt,
            "reason": reason,
        })
    return findings


def export_app_ranking_csv(app_scores, filename="app_risk_ranking.csv"):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / filename
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(app_scores[0].keys()))
        writer.writeheader()
        writer.writerows(app_scores)
    return path


def export_findings_csv(findings, filename="top_findings.csv"):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / filename
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(findings[0].keys()))
        writer.writeheader()
        writer.writerows(findings)
    return path


def export_all_dependencies_csv(scored_deps, filename="all_dependency_scores.csv"):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / filename
    rows = []
    for d in scored_deps:
        rows.append({
            "dep_id": d["dep_id"],
            "application_id": d["application_id"],
            "library": d["library"],
            "version": d["version"],
            "license_type": d["license_type"],
            "final_score": d["final_score"],
            "cve_count": len(d["cve_hits"]),
            "cve_ids": ", ".join(h["cve_id"] for h in d["cve_hits"]),
            "license_penalty": d["license_penalty"],
            "is_unmaintained": d["is_unmaintained"],
            "age_years": d["age_years"],
        })
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return path


def generate_report():
    data = load_all()
    scored_deps = score_all_dependencies(
        data["sbom_dependencies"], data["vulnerability_db"], data["license_rules"]
    )
    app_scores = score_applications(scored_deps)
    findings = build_findings(scored_deps, top_n=10)

    app_path = export_app_ranking_csv(app_scores)
    findings_path = export_findings_csv(findings)
    all_deps_path = export_all_dependencies_csv(scored_deps)

    return {
        "app_scores": app_scores,
        "findings": findings,
        "scored_deps": scored_deps,
        "exported_files": [app_path, findings_path, all_deps_path],
    }


if __name__ == "__main__":
    result = generate_report()

    print(f"=== AgentGuard-Lite Risk Report - generated {datetime.now():%Y-%m-%d %H:%M} ===")
    print("Vulnerability matching: by library name (see risk_scorer.py docstring for why)")
    print()
    print("Top 10 riskiest dependencies portfolio-wide:")
    print("-" * 100)
    for f in result["findings"]:
        print(f"[{f['application_id']}] {f['library']:<30} score={f['risk_score']:<7} "
              f"cves={f['cves']:<20} license_issue={f['license_issue']} unmaintained={f['unmaintained']}")
        print(f"    -> Remediation: {f['remediation']} ({f['reason']})")
    print()
    print("Files exported to data/outputs/:")
    for path in result["exported_files"]:
        print(f"  - {path.name}")