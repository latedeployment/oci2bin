"""
Entry point for the PyPI-installed oci2bin.

Locates the bash script bundled inside the package, sets OCI2BIN_HOME to
the package directory (which contains scripts/ and src/), then execs bash.
The exec replaces this process — no subprocess overhead.
"""

import os
import sys
from pathlib import Path


def main() -> None:
    pkg_dir = Path(__file__).parent.resolve()
    bash_script = pkg_dir / "oci2bin.bash"
    if not bash_script.exists():
        print(f"oci2bin: bundled script not found: {bash_script}", file=sys.stderr)
        sys.exit(1)

    env = os.environ.copy()
    env["OCI2BIN_HOME"] = str(pkg_dir)

    os.execve("/bin/bash", ["/bin/bash", str(bash_script)] + sys.argv[1:], env)
