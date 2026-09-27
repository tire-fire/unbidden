#!/usr/bin/env python3
"""Regenerates the technique columns of ci/attack-coverage.tsv from ATT&CK's
STIX bundle, so a new release's techniques show up as rows without an
answer. Usage: attack-list.py enterprise-attack.json > new.tsv, then diff.
The bundle is at github.com/mitre-attack/attack-stix-data."""
import json, sys
d = json.load(open(sys.argv[1]))
objs = d["objects"]
coll = [o for o in objs if o.get("type") == "x-mitre-collection"]
print("# ATT&CK", coll[0].get("x_mitre_version") if coll else "?")
rows = []
for t in objs:
    if t.get("type") != "attack-pattern" or t.get("revoked") or t.get("x_mitre_deprecated"):
        continue
    plats = set(t.get("x_mitre_platforms", []))
    if not (plats & {"Linux", "Containers"}):
        continue
    tactics = {p["phase_name"] for p in t.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"}
    tid = next((r["external_id"] for r in t.get("external_references", []) if r.get("source_name") == "mitre-attack"), "?")
    if not (tactics & {"persistence", "privilege-escalation"} or tid.startswith("T1574")):
        continue
    rows.append((tid, t["name"], ",".join(sorted(tactics)), ",".join(sorted(plats & {"Linux", "Containers"}))))
for r in sorted(rows):
    print("\t".join(r))
