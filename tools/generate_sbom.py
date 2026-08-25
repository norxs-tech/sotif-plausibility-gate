#!/usr/bin/env python3
"""
@copyright (c) 2026 norxs Technology LLC. All rights reserved.

Generates an SPDX 2.3 SBOM covering every source, header, test, and
documentation file in this repository (excluding vendor/ — those files are
covered by autosar-soa-gateway's and zonal-zero-trust-auth's own SBOMs, not
this repository's).

Usage: python3 tools/generate_sbom.py <version>
"""
import hashlib
import json
import sys
import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXCLUDE_DIR_PARTS = {"vendor", ".git", "sbom", "__pycache__"}


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def collect_files():
    files = []
    for p in sorted(REPO_ROOT.rglob("*")):
        if not p.is_file():
            continue
        rel_parts = set(p.relative_to(REPO_ROOT).parts)
        if rel_parts & EXCLUDE_DIR_PARTS:
            continue
        files.append(p)
    return files


def build_sbom(version: str) -> dict:
    files = collect_files()
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    file_entries = []
    for f in files:
        rel = str(f.relative_to(REPO_ROOT))
        file_entries.append({
            "fileName": f"./{rel}",
            "SPDXID": "SPDXRef-File-" + rel.replace("/", "-").replace(".", "-"),
            "checksums": [
                {"algorithm": "SHA256", "checksumValue": sha256_of(f)}
            ],
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"sotif-plausibility-gate-{version}",
        "documentNamespace": f"https://norxs.com/spdx/sotif-plausibility-gate-{version}",
        "creationInfo": {
            "created": now,
            "creators": ["Organization: norxs Technology LLC", "Tool: generate_sbom.py"],
        },
        "packages": [
            {
                "name": "sotif-plausibility-gate",
                "SPDXID": "SPDXRef-Package-sotif-plausibility-gate",
                "versionInfo": version,
                "downloadLocation": "https://github.com/norxs-tech/sotif-plausibility-gate",
                "licenseConcluded": "LicenseRef-norxs-RI-1.0",
                "licenseDeclared": "LicenseRef-norxs-RI-1.0",
                "copyrightText": "(c) 2026 norxs Technology LLC. All rights reserved.",
                "hasFiles": [e["SPDXID"] for e in file_entries],
            }
        ],
        "files": file_entries,
        # Explicit, honest note this SBOM tool does not compute: this
        # repository has zero third-party runtime dependencies of its own,
        # but DEPENDS AT BUILD TIME on headers/sources vendored from
        # autosar-soa-gateway and zonal-zero-trust-auth (see vendor/ and
        # vendor-autosar-soa-gateway/ — excluded from this SBOM's file list
        # since those repositories own and SBOM those files themselves).
        "comment": (
            "Zero third-party runtime dependencies. Build-time dependency on "
            "autosar-soa-gateway (sotif-gate/) and zonal-zero-trust-auth "
            "(pqc-kem-extension/) public headers, vendored read-only and "
            "excluded from this file list by design."
        ),
    }


def main():
    if len(sys.argv) != 2:
        print("usage: generate_sbom.py <version>", file=sys.stderr)
        sys.exit(1)

    version = sys.argv[1]
    sbom = build_sbom(version)

    out_dir = REPO_ROOT / "sbom"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "sotif-plausibility-gate.spdx.json"
    out_path.write_text(json.dumps(sbom, indent=2) + "\n")

    print(f"Wrote {out_path} covering {len(sbom['files'])} files.")


if __name__ == "__main__":
    main()
