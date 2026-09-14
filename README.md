# ESP32 Firmware SBOM Generator & Vulnerability Watcher

A tool that generates a standards-compliant Software Bill of Materials
(SBOM) for an embedded/firmware project and continuously checks its
dependencies for known vulnerabilities.

## Why this project exists

Modern cybersecurity regulation (notably the EU **Cyber Resilience Act**)
requires manufacturers of connected products to know exactly what
software components are inside their firmware, and to keep that
inventory current as new vulnerabilities are disclosed. This is called
**SBOM maintenance** — not a one-time document, but a living record.

This project builds a small pipeline that does exactly that for one of
my own ESP32 projects ([Pause](https://builtbyahsan.tech), a voice-journaling
device), producing:

1. A machine-readable SBOM in **CycloneDX** format (one of the two formats
   referenced under the CRA, alongside SPDX)
2. A vulnerability report cross-referencing every component's version
   against public vulnerability databases
3. An automated weekly re-check via GitHub Actions, so the report stays
   current without manual re-running

## How it works

```
components.json / platformio.ini
            │
            ▼
   sbom_generator.py
            │
   ┌────────┴─────────┐
   ▼                   ▼
sbom.cyclonedx.json   vulnerability_report.json
(the SBOM itself)     (per-component CVE findings)
```

**Step 1 — Inventory.** The script reads a component list either from a
manually maintained `components.json` or parsed directly from a
PlatformIO project's `lib_deps`.

**Step 2 — SBOM generation.** Each component becomes a CycloneDX entry
with name, version, and (where known) its package ecosystem.

**Step 3 — Vulnerability checking, using two sources on purpose:**
- Components tagged with a real package ecosystem (e.g. the project's
  Python backend dependencies — `Flask`, `requests`, `openai-whisper` —
  which live on PyPI) are checked via **OSV.dev**'s batch API for exact,
  version-aware matches.
- Firmware/Arduino libraries (e.g. `ArduinoJson`, `Adafruit SSD1306`)
  generally aren't tracked in any package-manager ecosystem, so OSV can't
  match them precisely. These are instead checked via a **keyword search
  against the NVD** (National Vulnerability Database). This is fuzzier —
  it matches free-text mentions in CVE descriptions — so findings from
  this path are flagged as needing manual review rather than treated as
  confirmed matches.

This two-path design isn't a shortcut — it reflects a real constraint in
embedded/OT vulnerability management: a lot of firmware-level software
simply isn't covered by the same tooling that works cleanly for
web/app dependencies. Knowing *which* check applies to *which* kind of
component, and being explicit about the confidence level of each, is
itself part of the job.

**Step 4 — Maintenance, not a one-off.** A GitHub Actions workflow
re-runs the whole pipeline weekly (and on every push), uploading the
updated SBOM and report as build artifacts, and fails the run if a new
vulnerability shows up — the same idea as continuous dependency
monitoring in an industrial security program.

## Usage

```bash
pip install -r requirements.txt

# From a manually maintained component list:
python sbom_generator.py \
  --input components.example.json \
  --project-name "Pause" \
  --project-version "1.0.0" \
  --output-dir sbom_output

# Or auto-extract dependencies from a PlatformIO project:
python sbom_generator.py \
  --input platformio.ini \
  --project-name "MyFirmware"
```

Outputs land in `sbom_output/`:
- `sbom.cyclonedx.json` — the SBOM
- `vulnerability_report.json` — per-component findings + source/confidence

## Possible extensions

- **Fleet visibility dashboard:** track firmware versions across several
  physical ESP32 devices reporting in, and flag which ones are running
  outdated/vulnerable builds — mirrors asset-inventory practice under
  **IEC 62443**.
- **SPDX output** alongside CycloneDX, since some customers/regulators
  prefer one format over the other.
- **Diffing SBOMs over time** to show exactly what changed between
  firmware releases.

## Limitations (worth stating honestly)

- NVD keyword search is not authoritative — it can surface irrelevant
  CVEs (name collisions) or miss real ones (inconsistent naming). Treat
  it as a triage signal, not a definitive scan result.
- The tool does not yet inspect compiled binaries or ESP-IDF's own
  internal component versions — it works from declared dependencies only.
