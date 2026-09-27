"""Packs harness cases into test vectors, one file per case.

pack.py KIND SRC DEST: every file a case's out/ tree holds that the
generator reads or writes, as `=== <path> <length>` then exactly that many
bytes and a newline, so trailing newlines and their absence survive.
"""
import os
import sys

kind, src, dest = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(dest, exist_ok=True)

WANT = {
    "pam-auth-update": ["usr/share/pam/", "usr/share/pam-configs/", "var/lib/pam/", "etc/pam.d/"],
    "authselect": ["etc/authselect/", "usr/share/authselect/"],
}[kind]

n = 0
for case in sorted(os.listdir(src)):
    out = os.path.join(src, case, "out")
    if kind == "pam-auth-update" and not os.path.exists(os.path.join(out, "etc/pam.d/common-auth")):
        continue
    if kind == "authselect" and not os.path.exists(os.path.join(out, "etc/authselect/authselect.conf")):
        continue
    files = []
    for dirpath, _, names in os.walk(out):
        for name in names:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, out)
            if not any(rel.startswith(w) for w in WANT) or rel.endswith(".md5sums") or rel == "var/lib/pam/seen":
                continue
            files.append((rel, open(full, "rb").read()))
    files.sort()
    with open(os.path.join(dest, f"{n:03d}.case"), "wb") as f:
        for rel, body in files:
            f.write(f"=== {rel} {len(body)}\n".encode())
            f.write(body)
            f.write(b"\n")
    n += 1
print(kind, n, "cases")
