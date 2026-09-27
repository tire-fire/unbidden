"""Random pam-auth-update inputs: profiles and original templates.

gen.py OUT SEED N writes N case directories, each with profile files
(prof*), the profiles to enable (ENABLE), and templates/common-*.
"""
import os
import random
import shutil
import sys

out, seed, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
random.seed(seed)
shutil.rmtree(out, ignore_errors=True)

MODS = ["pam_a.so", "pam_b.so", "pam_c.so", "pam_d.so", "pam_e.so"]
CTRL = [
    "required", "requisite", "sufficient", "optional",
    "[success=end default=ignore]", "[success=1 default=ignore]", "[default=die]",
    "[success=ok new_authtok_reqd=ok ignore=ignore user_unknown=bad default=die]",
    "[success=end new_authtok_reqd=done default=ignore]",
]
ARGS = ["", " try_first_pass", " use_authtok nullok", " quiet"]
TYPES = ["auth", "account", "password", "session", "session-noninteractive"]


def lines():
    return "\n".join(
        f"\t{random.choice(CTRL)}\t{random.choice(MODS)}{random.choice(ARGS)}"
        for _ in range(random.randint(1, 3))
    )


for c in range(n):
    d = f"{out}/{c:04d}"
    os.makedirs(d)
    names = [f"prof{i}" for i in range(random.randint(1, 4))]
    enable = []
    for nm in names:
        f = [
            f"Name: {nm} profile",
            f"Default: {random.choice(['yes', 'no'])}",
            f"Priority: {random.choice([0, 64, 128, 192, 256, 257, 512, 1024])}",
        ]
        for ty in ["Auth", "Account", "Password", "Session"]:
            if random.random() < 0.6:
                f.append(f"{ty}-Type: {random.choice(['Primary', 'Additional'])}")
                f.append(f"{ty}:\n" + lines())
                if random.random() < 0.3:
                    f.append(f"{ty}-Initial:\n" + lines())
        if random.random() < 0.2:
            f.append("Session-Interactive-Only: yes")
        open(f"{d}/{nm}", "w").write("\n".join(f) + "\n")
        if random.random() < 0.6:
            enable.append(nm)
    open(f"{d}/ENABLE", "w").write(" ".join(enable) + "\n")

    # Original templates, carrying the four marker comments pam-auth-update
    # requires, with or without fixed lines between the blocks and local
    # lines around them.
    os.makedirs(f"{d}/templates")
    variant = random.randint(0, 2)
    for ty in TYPES:
        key = ty.replace("-", "_")
        word = ty.split("-")[0]
        body = [f"# test template for common-{ty}, variant {variant}"]
        if variant == 1:
            body.append(f"{word}\toptional\tpam_local_before.so")
        body.append('# here are the per-package modules (the "Primary" block)')
        body.append(f"${key}_primary")
        body.append("# here's the fallback if no module succeeds")
        if variant != 2:
            body.append(f"{word}\trequisite\t\t\tpam_deny.so")
            body.append(f"{word}\trequired\t\t\tpam_permit.so")
        body.append('# and here are more per-package modules (the "Additional" block)')
        body.append(f"${key}_additional")
        body.append("# end of pam-auth-update config")
        if variant == 1:
            body.append(f"{word}\toptional\tpam_local_after.so")
        open(f"{d}/templates/common-{ty}", "w").write("\n".join(body) + "\n")
