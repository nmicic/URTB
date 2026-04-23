# Bake the short git SHA into the firmware image so the OLED boot screen
# can show which build is running. Falls back to "unknown" when not in a
# git checkout (e.g. tarball builds).
import os
import subprocess

Import("env")  # noqa: F821 — provided by PlatformIO

try:
    sha = subprocess.check_output(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=os.path.dirname(env["PROJECT_DIR"]),  # noqa: F821
        stderr=subprocess.DEVNULL,
    ).decode().strip()
except Exception:
    sha = "unknown"

env.Append(CPPDEFINES=[("URTB_GIT_SHA", '\\"' + sha + '\\"')])  # noqa: F821
