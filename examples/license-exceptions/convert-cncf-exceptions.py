#!/usr/bin/env python3
"""Prepare the CNCF foundation license-exceptions file for BOMHort.

Source: https://github.com/cncf/foundation/blob/main/license-exceptions/exceptions.json

BOMHort loads the upstream file as-is: "allowlisted" counts as approved, the
"issueUrl"/"packageUrl" provenance fields are accepted, and "All CNCF
Projects" is a wildcard scope. This script is therefore optional. It exists
to make the review step before deploying to a public instance easier:

  1. It drops entries whose status is not an approval ("apache-2.0",
     "denied", "not-eligible", "pending"). They are inactive either way, but
     a smaller file is easier to audit and diff between refreshes.
  2. It reports prose package names ("Crossplane Upjet MPL dependencies")
     that cannot match a package identifier. They are kept, since only a
     human can replace them with the real module path or purl.
  3. It normalises project wildcards to "*" so the effective scope is
     explicit in the deployed file.

Usage:
    python3 convert-cncf-exceptions.py [source.json] [-o out.json]
    curl -sSL <raw-url> | python3 convert-cncf-exceptions.py - -o cncf-exceptions.json
    helm upgrade ... --set-file licenseExceptions.custom=./cncf-exceptions.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

# Fields BOMHort's license.Exception struct accepts.
ALLOWED_FIELDS = {
    "id",
    "package",
    "license",
    "project",
    "status",
    "approvedDate",
    "scope",
    "results",
    "comment",
    "issueUrl",
    "packageUrl",
}

# Upstream statuses that represent a real approval in BOMHort's sense.
# "apache-2.0" is excluded on purpose: Apache-2.0 is permissive and never
# raises a violation, so those entries would only be dead weight.
APPROVED_STATUSES = {"approved", "allowlisted"}

# Wildcards upstream uses; BOMHort understands them, "*" is just explicit.
WILDCARD_PROJECTS = {"all cncf projects", "all projects", "any", "all"}


def convert(src: dict) -> tuple[dict, dict]:
    stats: Counter = Counter()
    out_exceptions = []

    for entry in src.get("exceptions", []):
        stats["total"] += 1
        status = (entry.get("status") or "").lower()
        stats[f"status:{status or '(empty)'}"] += 1

        if status not in APPROVED_STATUSES:
            stats["dropped"] += 1
            continue

        converted = {k: v for k, v in entry.items() if k in ALLOWED_FIELDS}
        dropped_keys = set(entry) - ALLOWED_FIELDS
        if dropped_keys:
            stats["entries_with_unknown_fields"] += 1
            # Keep the information rather than losing it: fold unknown keys
            # into the comment, which BOMHort surfaces as the reason.
            extra = " ".join(f"{k}: {entry[k]}" for k in sorted(dropped_keys))
            converted["comment"] = (converted.get("comment", "") + " " + extra).strip()

        # Normalise the project wildcard.
        project = (converted.get("project") or "").strip()
        if project.lower() in WILDCARD_PROJECTS:
            converted["project"] = "*"
            stats["project_wildcarded"] += 1

        pkg = converted.get("package", "")
        if " " in pkg or "`" in pkg:
            stats["prose_package_names"] += 1
            print(f"REVIEW prose package name: {entry.get('id')!r} -> {pkg!r}", file=sys.stderr)

        out_exceptions.append(converted)

    blanket = []
    for entry in src.get("blanketExceptions", []):
        blanket.append({k: v for k, v in entry.items() if k in ALLOWED_FIELDS})

    out = {
        "version": src.get("version", ""),
        "lastUpdated": src.get("lastUpdated", ""),
        "description": "Converted from cncf/foundation license-exceptions/exceptions.json",
        "blanketExceptions": blanket,
        "exceptions": out_exceptions,
    }
    stats["kept"] = len(out_exceptions)
    return out, stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source", nargs="?", default="-", help="source JSON file, or - for stdin")
    ap.add_argument("-o", "--output", default="-", help="output file, or - for stdout")
    args = ap.parse_args()

    raw = sys.stdin.read() if args.source == "-" else open(args.source, encoding="utf-8").read()
    out, stats = convert(json.loads(raw))
    text = json.dumps(out, indent=2, ensure_ascii=False) + "\n"

    if args.output == "-":
        sys.stdout.write(text)
    else:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)

    for key in sorted(stats):
        print(f"{key:32} {stats[key]}", file=sys.stderr)
    print(f"{'output bytes':32} {len(text)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

