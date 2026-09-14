#!/usr/bin/env python3
"""
ESP32 Firmware SBOM Generator & Vulnerability Watcher
------------------------------------------------------
Generates a CycloneDX-format Software Bill of Materials (SBOM) for an
embedded/firmware project and cross-checks each component against known
vulnerability databases.

Why CycloneDX?
  It's one of the two SBOM formats explicitly referenced under the EU
  Cyber Resilience Act (CRA) (the other being SPDX). Producing SBOMs in
  a standard, machine-readable format -- rather than a plain text list --
  is the actual practice this project demonstrates.

Why two vulnerability sources?
  Most embedded/Arduino libraries are NOT tracked in package-manager
  ecosystems (npm, PyPI, crates.io, etc.), so OSV.dev's exact-match batch
  API can't see them. For components tagged with a real ecosystem (e.g.
  Python backend deps), we use OSV for precise, version-aware matches.
  For everything else (ESP32/Arduino libraries), we fall back to a
  keyword search against the NVD (National Vulnerability Database),
  which covers free-text product mentions even outside package registries.
  This mirrors a real-world constraint you'd run into doing this for an
  actual embedded product, and it's worth being able to explain that
  limitation out loud in an interview.

Usage:
  python sbom_generator.py --input components.json --project-name "Pause" \
      --project-version "1.0.0" --output-dir sbom_output

  python sbom_generator.py --input platformio.ini --project-name "MyFirmware"

Author: Ahsan Hamid (project scaffold)
"""

import argparse
import configparser
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    print("Missing dependency. Install it with:\n  pip install requests --break-system-packages")
    sys.exit(1)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CYCLONEDX_SPEC_VERSION = "1.5"


# ---------------------------------------------------------------------------
# 1. INPUT PARSING
# ---------------------------------------------------------------------------

def load_components_json(path: Path) -> list[dict]:
    """Load a manually maintained component list.

    Expected format:
    [
      {"name": "ArduinoJson", "version": "6.21.3", "type": "library"},
      {"name": "Flask", "version": "3.0.0", "type": "library", "ecosystem": "PyPI"}
    ]

    The optional "ecosystem" field (e.g. "PyPI", "npm", "crates.io") lets
    us do a precise OSV lookup for components that live in a real package
    registry. Leave it out (or null) for ESP32/Arduino libraries -- those
    will be checked via NVD keyword search instead.
    """
    with open(path) as f:
        data = json.load(f)
    for c in data:
        c.setdefault("type", "library")
        c.setdefault("ecosystem", None)
    return data


def parse_platformio_ini(path: Path) -> list[dict]:
    """Best-effort parse of a platformio.ini's lib_deps entries.

    Handles common PlatformIO dependency formats:
      lib_deps =
          bblanchon/ArduinoJson @ ^6.21.3
          knolleary/PubSubClient@2.8
          adafruit/Adafruit SSD1306
    """
    config = configparser.ConfigParser()
    config.read(path)
    components = []

    for section in config.sections():
        if "lib_deps" not in config[section]:
            continue
        raw = config[section]["lib_deps"]
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            # Split "owner/name @ version" or "owner/name@version"
            if "@" in line:
                name_part, version_part = line.split("@", 1)
                version = version_part.strip().lstrip("^~=")
            else:
                name_part, version = line, "unspecified"
            # Strip owner/ prefix for a cleaner display name
            name = name_part.strip().split("/")[-1]
            components.append({
                "name": name,
                "version": version.strip(),
                "type": "library",
                "ecosystem": None,
            })
    return components


def load_input(path_str: str) -> list[dict]:
    path = Path(path_str)
    if not path.exists():
        print(f"Input file not found: {path}")
        sys.exit(1)
    if path.suffix == ".json":
        return load_components_json(path)
    elif path.name.endswith(".ini"):
        return parse_platformio_ini(path)
    else:
        print("Unsupported input type. Use a .json component list or platformio.ini")
        sys.exit(1)


# ---------------------------------------------------------------------------
# 2. SBOM GENERATION (CycloneDX JSON)
# ---------------------------------------------------------------------------

def build_cyclonedx_sbom(components: list[dict], project_name: str, project_version: str) -> dict:
    """Construct a CycloneDX 1.5 JSON SBOM document."""
    timestamp = datetime.now(timezone.utc).isoformat()

    sbom_components = []
    for c in components:
        bom_ref = f"{c['name']}@{c['version']}"
        entry = {
            "type": c.get("type", "library"),
            "bom-ref": bom_ref,
            "name": c["name"],
            "version": c["version"],
        }
        if c.get("ecosystem"):
            entry["properties"] = [
                {"name": "ecosystem", "value": c["ecosystem"]}
            ]
        sbom_components.append(entry)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": {
                "type": "firmware",
                "name": project_name,
                "version": project_version,
            },
            "tools": [
                {"vendor": "self-built", "name": "esp32-sbom-generator", "version": "0.1.0"}
            ],
        },
        "components": sbom_components,
    }
    return sbom


# ---------------------------------------------------------------------------
# 3. VULNERABILITY CHECKING
# ---------------------------------------------------------------------------

def query_osv_batch(components: list[dict]) -> dict:
    """Query OSV.dev for components that declare a known ecosystem.

    Returns: {component_key: [vuln_id, ...]}
    """
    results = {}
    queries = []
    keys = []

    for c in components:
        if not c.get("ecosystem"):
            continue
        queries.append({
            "package": {"name": c["name"], "ecosystem": c["ecosystem"]},
            "version": c["version"],
        })
        keys.append(f"{c['name']}@{c['version']}")

    if not queries:
        return results

    try:
        resp = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=15)
        resp.raise_for_status()
        batch_results = resp.json().get("results", [])
        for key, result in zip(keys, batch_results):
            vuln_ids = [v["id"] for v in result.get("vulns", [])]
            if vuln_ids:
                results[key] = vuln_ids
    except requests.RequestException as e:
        print(f"  [!] OSV batch query failed: {e}")

    return results


def query_nvd_keyword(name: str, version: str, max_results: int = 3) -> list[dict]:
    """Fallback keyword search against NVD for components not in a package
    ecosystem (typical for Arduino/ESP32 libraries).

    NOTE: keyword search is fuzzy -- it matches free-text mentions of the
    name in CVE descriptions, so false positives/negatives are expected.
    This is exactly the kind of caveat worth calling out explicitly in a
    real vulnerability report, rather than pretending the match is exact.
    """
    params = {"keywordSearch": name, "resultsPerPage": max_results}
    try:
        resp = requests.get(NVD_CVE_URL, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        findings = []
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            cve_id = cve["id"]
            description = ""
            for d in cve.get("descriptions", []):
                if d["lang"] == "en":
                    description = d["value"]
                    break
            findings.append({"id": cve_id, "description": description[:200]})
        return findings
    except requests.RequestException as e:
        print(f"  [!] NVD lookup failed for '{name}': {e}")
        return []
    finally:
        # Be polite to the public NVD API (unauthenticated rate limit is low)
        time.sleep(2)


def run_vulnerability_scan(components: list[dict]) -> dict:
    """Runs both checks and returns a merged report keyed by component."""
    print("Checking components with a known ecosystem against OSV.dev...")
    osv_results = query_osv_batch(components)

    report = {}
    for c in components:
        key = f"{c['name']}@{c['version']}"
        if c.get("ecosystem"):
            report[key] = {
                "source": "osv.dev",
                "ecosystem": c["ecosystem"],
                "vulnerabilities": osv_results.get(key, []),
            }
        else:
            print(f"Keyword-checking '{c['name']}' against NVD (no known ecosystem)...")
            findings = query_nvd_keyword(c["name"], c["version"])
            report[key] = {
                "source": "nvd-keyword-search (fuzzy, review manually)",
                "ecosystem": None,
                "vulnerabilities": findings,
            }
    return report


# ---------------------------------------------------------------------------
# 4. MAIN
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Generate and check an SBOM for a firmware project.")
    parser.add_argument("--input", required=True, help="components.json or platformio.ini")
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--project-version", default="0.1.0")
    parser.add_argument("--output-dir", default="sbom_output")
    parser.add_argument("--skip-vuln-check", action="store_true",
                         help="Only generate the SBOM, skip network vulnerability lookups")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading components from {args.input} ...")
    components = load_input(args.input)
    print(f"Found {len(components)} component(s).\n")

    sbom = build_cyclonedx_sbom(components, args.project_name, args.project_version)
    sbom_path = out_dir / "sbom.cyclonedx.json"
    with open(sbom_path, "w") as f:
        json.dump(sbom, f, indent=2)
    print(f"SBOM written to {sbom_path}\n")

    if args.skip_vuln_check:
        print("Skipping vulnerability scan (--skip-vuln-check set).")
        return

    report = run_vulnerability_scan(components)
    report_path = out_dir / "vulnerability_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nVulnerability report written to {report_path}\n")
    print("Summary:")
    for key, result in report.items():
        count = len(result["vulnerabilities"])
        flag = "⚠️ " if count else "✅ "
        print(f"  {flag}{key} — {count} potential finding(s) via {result['source']}")


if __name__ == "__main__":
    main()
