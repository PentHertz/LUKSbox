#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)
"""Check the C libraries bundled into the static FIDO2 + TPM luksbox build
for known vulnerabilities (GitHub #34).

Usage: check_static_deps.py <components.tsv> [<reviewed.txt>]

components.tsv is written by scripts/static_fido2_tpm_alpine.sh into the
tarball's licenses/ directory: one `name<TAB>version<TAB>source` line per
library, where source is `alpine:<branch>` or `github:<owner>/<repo>`.

Fails (exit 1) when:
  - OSV lists a vulnerability for an Alpine package at that exact version
    (OpenSSL, zlib, musl; OSV tracks Alpine's own security fixes);
  - NVD lists a CVE whose affected range for a pinned library includes the
    pinned version, or a CVE naming the library that NVD has not analysed
    yet and that is not listed in reviewed.txt (default:
    scripts/static_deps_reviewed.txt);
  - an upstream release newer than the pinned one announces security fixes
    (advisories, or memory-safety / race fixes in its notes). Advisories are
    often published weeks after the fixed release (tpm2-tss 4.1.4 fixed ten
    still-private GHSAs), so a database lookup alone misses them.
A newer upstream release without security notes only prints a warning.
Network errors fail too: the build is optional, so one that could not be
checked is simply not published.

Standard library only. GITHUB_TOKEN or GH_TOKEN raises the GitHub API rate
limit; NVD_API_KEY is optional (without it NVD allows 5 requests / 30 s).
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# NVD keyword searches and CPE product names per pinned library.
NVD = {
    "libfido2": (["libfido2"], ["libfido2"]),
    "libcbor": (["libcbor"], ["libcbor"]),
    "libudev-zero": (["libudev-zero"], ["libudev-zero", "libudev_zero"]),
    "tpm2-tss": (
        ["tpm2-tss", "TPM2 Software Stack"],
        ["tpm2-tss", "tpm2_tss", "tpm2_software_stack"],
    ),
}
# Release-note wording that counts as a security fix: advisories, and the
# memory-safety / race fixes that parsers like libcbor ship without one.
SECURITY_NOTES = re.compile(
    r"\bsecurity\b|\bvulnerab|CVE-\d{4}-\d+|GHSA-[0-9a-z]{4}-|YSA-\d{4}"
    r"|overflow|underflow|out[- ]of[- ]bounds|bounds check|use[- ]after[- ]free"
    r"|double[- ]free|TOCTOU",
    re.I,
)


def vkey(version):
    return tuple(int(x) for x in re.findall(r"\d+", version))


def fetch(url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if attempt == 3 or e.code not in (403, 429, 500, 502, 503, 504):
                raise
        except urllib.error.URLError:
            if attempt == 3:
                raise
        time.sleep(10 * (attempt + 1))
    raise AssertionError("unreachable")


def github(path):
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return fetch(f"https://api.github.com{path}", headers=headers)


def check_alpine(name, version, branch, problems):
    query = {"package": {"name": name, "ecosystem": f"Alpine:{branch}"}, "version": version}
    result = fetch(
        "https://api.osv.dev/v1/query",
        data=json.dumps(query).encode(),
        headers={"Content-Type": "application/json"},
    )
    vulns = [v["id"] for v in (result or {}).get("vulns", [])]
    if vulns:
        problems.append(f"{name} {version} (Alpine {branch}): {', '.join(vulns)}")
    print(f"  OSV Alpine:{branch} {name} {version}: {len(vulns)} known")


def affects(match, version):
    """Does one NVD cpeMatch entry cover `version`?"""
    cpe_version = match["criteria"].split(":")[5]
    if cpe_version not in ("*", "-"):
        return vkey(cpe_version) == vkey(version)
    v = vkey(version)
    checks = (
        ("versionStartIncluding", lambda b: v >= b),
        ("versionStartExcluding", lambda b: v > b),
        ("versionEndIncluding", lambda b: v <= b),
        ("versionEndExcluding", lambda b: v < b),
    )
    return all(ok(vkey(match[k])) for k, ok in checks if k in match)


def check_nvd(name, version, reviewed, problems):
    keywords, products = NVD[name]
    headers = {}
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    seen = set()
    for keyword in keywords:
        query = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": 2000})
        result = fetch(f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}", headers=headers)
        if not headers:
            time.sleep(7)  # stay under the anonymous 5 requests / 30 s
        for item in (result or {}).get("vulnerabilities", []):
            cve = item["cve"]
            if cve["id"] in seen:
                continue
            seen.add(cve["id"])
            ours = [
                m
                for cfg in cve.get("configurations", [])
                for node in cfg["nodes"]
                for m in node["cpeMatch"]
                if m.get("vulnerable") and any(p in m["criteria"].split(":")[4] for p in products)
            ]
            if ours:
                if any(affects(m, version) for m in ours):
                    problems.append(f"{name} {version}: {cve['id']}")
            elif not cve.get("configurations") and cve["id"] not in reviewed:
                desc = cve["descriptions"][0]["value"][:160]
                problems.append(
                    f"{name} {version}: {cve['id']} is not analysed by NVD yet; review it and, "
                    f"if it does not apply, add it to the reviewed list ({desc})"
                )
    print(f"  NVD {name} {version}: {len(seen)} CVE(s) mention it")


def check_upstream(name, version, repo, problems, warnings):
    releases = github(f"/repos/{repo}/releases?per_page=50") or []
    newer = [
        r for r in releases
        if not r.get("prerelease") and not r.get("draft") and vkey(r["tag_name"]) > vkey(version)
    ]
    if releases:
        for r in sorted(newer, key=lambda r: vkey(r["tag_name"])):
            note = f"{name}: upstream {r['tag_name']} is newer than the pinned {version}"
            if SECURITY_NOTES.search(r.get("body") or ""):
                problems.append(f"{note} and its release notes announce security fixes")
            else:
                warnings.append(note)
    else:
        # No GitHub releases (libfido2 ships tarballs): compare tags only.
        tags = [t["name"] for t in (github(f"/repos/{repo}/tags?per_page=100") or [])]
        latest = max(tags, key=vkey, default=version)
        if vkey(latest) > vkey(version):
            warnings.append(f"{name}: upstream tag {latest} is newer than the pinned {version}")
    print(f"  upstream {repo}: {len(newer) if releases else 'tags only'} newer release(s)")


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    components = Path(sys.argv[1])
    reviewed_path = Path(sys.argv[2]) if len(sys.argv) == 3 else (
        Path(__file__).with_name("static_deps_reviewed.txt")
    )
    reviewed = set()
    if reviewed_path.exists():
        for line in reviewed_path.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                reviewed.add(line.split()[0])

    problems, warnings = [], []
    for line in components.read_text().splitlines():
        if not line.strip():
            continue
        name, version, source = line.split("\t")
        print(f"{name} {version} ({source})")
        kind, _, where = source.partition(":")
        if kind == "alpine":
            check_alpine(name, version, where, problems)
        elif kind == "github":
            check_nvd(name, version, reviewed, problems)
            check_upstream(name, version, where, problems, warnings)
        else:
            problems.append(f"{name}: unknown source {source!r}")

    for w in warnings:
        print(f"warning: {w}")
    for p in problems:
        print(f"error: {p}")
    if problems:
        sys.exit(1)
    print("no known vulnerabilities in the bundled libraries")


if __name__ == "__main__":
    main()
