"""
data_loader.py - Ingestion layer for AgentGuard-lite (PB-10 SBOM Analyzer)

Loads and validates the 6 OFFICIAL sample_data files (Societe Generale
Neo Hire Hackathon dataset). Fails loudly if a file is missing or malformed.
"""
import json
import csv
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "sample_data"

REQUIRED_APP_KEYS = {"app_id", "name", "language", "criticality",
                      "license_model", "business_owner", "department", "deployment"}
REQUIRED_SBOM_COLS = {"dep_id", "application_id", "application_name", "library", "version",
                       "license", "dependency_type", "last_updated", "transitive_deps"}
REQUIRED_VULN_KEYS = {"cve_id", "library", "affected_versions", "fixed_version",
                       "cvss_score", "severity", "exploitability", "description",
                       "patch_available", "published_date"}
REQUIRED_LICENSE_KEYS = {"license", "spdx", "risk_level", "compatible_with_proprietary",
                          "viral", "notes"}
REQUIRED_LABEL_COLS = {"dep_id", "application_id", "library", "version",
                        "is_risky", "risk_type", "severity", "explanation"}
REQUIRED_TRANSITIVE_KEYS = {"parent_library", "parent_version", "child_library",
                             "child_version", "application_id"}


def _require_file(path: Path) -> Path:
    if not path.exists():
        raise FileNotFoundError(
            f"Required data file not found: {path}\n"
            f"Make sure the official sample_data files are in {DATA_DIR}"
        )
    return path


def _read_csv_rows(path: Path) -> list[dict]:
    """Read a CSV file, trying UTF-8 first and falling back to Windows-1252
    (cp1252) if the file contains non-UTF-8 bytes - common in files exported
    from Excel on Windows (e.g. em-dashes, curly quotes)."""
    last_error = None
    for encoding in ("utf-8-sig", "utf-8", "cp1252"):
        try:
            with open(path, encoding=encoding, newline="") as f:
                reader = csv.DictReader(f)
                return list(reader)
        except UnicodeDecodeError as e:
            last_error = e
            continue
    raise UnicodeDecodeError(
        "unknown", b"", 0, 1,
        f"Could not decode {path} with utf-8-sig, utf-8, or cp1252: {last_error}"
    )


def load_applications() -> list[dict]:
    path = _require_file(DATA_DIR / "applications.json")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list) or not data:
        raise ValueError("applications.json must contain a non-empty list")
    missing = REQUIRED_APP_KEYS - set(data[0].keys())
    if missing:
        raise ValueError(f"applications.json entries missing required keys: {missing}")
    return data


def load_sbom_dependencies() -> list[dict]:
    path = _require_file(DATA_DIR / "sbom_dependencies.csv")
    rows = _read_csv_rows(path)
    if not rows:
        raise ValueError("sbom_dependencies.csv is empty")
    missing = REQUIRED_SBOM_COLS - set(rows[0].keys())
    if missing:
        raise ValueError(f"sbom_dependencies.csv missing required columns: {missing}")
    return rows


def load_vulnerability_db() -> list[dict]:
    path = _require_file(DATA_DIR / "vulnerability_db.json")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list) or not data:
        raise ValueError("vulnerability_db.json must contain a non-empty list")
    missing = REQUIRED_VULN_KEYS - set(data[0].keys())
    if missing:
        raise ValueError(f"vulnerability_db.json entries missing required keys: {missing}")
    return data


def load_license_rules() -> list[dict]:
    path = _require_file(DATA_DIR / "license_rules.json")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list) or not data:
        raise ValueError("license_rules.json must contain a non-empty list")
    missing = REQUIRED_LICENSE_KEYS - set(data[0].keys())
    if missing:
        raise ValueError(f"license_rules.json entries missing required keys: {missing}")
    return data


def load_dependency_labels() -> list[dict]:
    path = _require_file(DATA_DIR / "dependency_labels.csv")
    rows = _read_csv_rows(path)
    if not rows:
        raise ValueError("dependency_labels.csv is empty")
    missing = REQUIRED_LABEL_COLS - set(rows[0].keys())
    if missing:
        raise ValueError(f"dependency_labels.csv missing required columns: {missing}")
    return rows


def load_transitive_dependencies() -> list[dict]:
    """Explicit parent->child dependency edges provided by the official dataset."""
    path = _require_file(DATA_DIR / "transitive_dependencies.json")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list) or not data:
        raise ValueError("transitive_dependencies.json must contain a non-empty list")
    missing = REQUIRED_TRANSITIVE_KEYS - set(data[0].keys())
    if missing:
        raise ValueError(f"transitive_dependencies.json entries missing required keys: {missing}")
    return data


def load_all() -> dict:
    """Load and validate everything in one call. Fails loudly on any problem."""
    return {
        "applications": load_applications(),
        "sbom_dependencies": load_sbom_dependencies(),
        "vulnerability_db": load_vulnerability_db(),
        "license_rules": load_license_rules(),
        "dependency_labels": load_dependency_labels(),
        "transitive_dependencies": load_transitive_dependencies(),
    }


if __name__ == "__main__":
    data = load_all()
    print("=== Official data loaded successfully ===")
    print(f"Applications            : {len(data['applications'])}")
    print(f"SBOM dependencies        : {len(data['sbom_dependencies'])}")
    print(f"Vulnerabilities          : {len(data['vulnerability_db'])}")
    print(f"License rules            : {len(data['license_rules'])}")
    print(f"Dependency labels        : {len(data['dependency_labels'])}")
    print(f"Transitive dependencies  : {len(data['transitive_dependencies'])}")
    print()
    print("Sample application  :", data['applications'][0])
    print("Sample SBOM row     :", data['sbom_dependencies'][0])
    print("Sample transitive   :", data['transitive_dependencies'][0])