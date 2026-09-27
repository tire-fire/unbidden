"""Random authselect profiles, written from authselect-profiles(5).

gen.py OUT SEED N writes N case directories, each holding a profile
(profile/*) and the features to select (FEATURES).
"""
import os
import random
import shutil
import sys

out, seed, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
random.seed(seed)
shutil.rmtree(out, ignore_errors=True)

FEATURES = ["with-a", "with-b", "with-c", "with-d"]
PAM_FILES = ["system-auth", "password-auth", "fingerprint-auth", "smartcard-auth", "postlogin"]
TEXT = [
    "auth        required      pam_env.so",
    "auth        sufficient    pam_unix.so nullok",
    "account     required      pam_unix.so",
    "password    requisite     pam_pwquality.so",
    "session     optional      pam_keyinit.so revoke",
    "session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid",
    "# a comment line",
    "",
    "   ",
]


def feat():
    return f'"{random.choice(FEATURES)}"'


def expr(depth=0):
    r = random.random()
    if depth > 2 or r < 0.45:
        return feat()
    if r < 0.6:
        return "not " + expr(depth + 1)
    if r < 0.75:
        return f"({expr(depth + 1)})"
    return f"{expr(depth + 1)} {random.choice(['and', 'or'])} {expr(depth + 1)}"


def op():
    r = random.random()
    e = expr()
    if r < 0.15:
        return f"{{continue if {e}}}"
    if r < 0.25:
        return f"{{stop if {e}}}"
    if r < 0.45:
        return f"{{include if {e}}}"
    if r < 0.6:
        return f"{{exclude if {e}}}"
    if r < 0.7:
        return f"{{imply {feat()} if {e}}}"
    if r < 0.85:
        return f"{{if {e}:yes_text|no_text}}"
    if r < 0.95:
        return f"{{if {e}:only_yes}}"
    # Malformed, to see what authselect leaves alone.
    return random.choice(["{if :x}", "{include if}", "{bogus \"with-a\"}", "{if \"with-a\"", "{if (\"with-a\":x}", "{}"])


def line():
    t = random.choice(TEXT)
    r = random.random()
    if r < 0.35:
        return t
    if r < 0.55:
        return op()
    if r < 0.85:
        return f"{t} {op()}"
    return f"{t} {op()} tail {op()}"


for c in range(n):
    d = f"{out}/{c:04d}/profile"
    os.makedirs(d)
    open(f"{d}/README", "w").write("Test profile.\n")
    for f in PAM_FILES + ["nsswitch.conf"]:
        if random.random() < 0.85:
            body = "\n".join(line() for _ in range(random.randint(1, 10)))
            if random.random() < 0.8:
                body += "\n"
            open(f"{d}/{f}", "w").write(body)
    chosen = [f for f in FEATURES if random.random() < 0.5]
    open(f"{out}/{c:04d}/FEATURES", "w").write(" ".join(chosen) + "\n")
