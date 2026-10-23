#!/usr/bin/env python3
"""pyIPATool (iOS): check the packages needed to build and run Unicorn from
source on a jailbroken device, and say where to get the missing ones.

    python3 vendor/unicorn/ios/check_deps.py

setup.py runs the same check before building on iOS (skip it with
UNICORN_SKIP_DEP_CHECK=1). Exit status: 0 = all present, 1 = something missing.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from typing import Dict, List, Optional, Sequence, Tuple

PROCURSUS = ("Procursus", "https://apt.procurs.us/", "the default repository on rootless jailbreaks")
CYPWN = ("CyPwn", "https://repo.cypwn.xyz/", "")

# (package to install, repository, how an installed package is recognised,
#  what it is for). "prefix:" matches any version (clang-15, clang-17...).
PACKAGES: Sequence[Tuple[str, Tuple[str, str, str], str, str]] = (
    ("clang-16", PROCURSUS, "prefix:clang-", "C compiler"),
    ("clangd-16", PROCURSUS, "prefix:clangd-", "clang tooling"),
    ("cmake", PROCURSUS, "cmake", "build system"),
    ("cmake-data", PROCURSUS, "cmake-data", "cmake modules"),
    ("make", PROCURSUS, "make", "build tool"),
    ("build-essential", PROCURSUS, "build-essential", "headers and basic build tools"),
    ("libffi8", PROCURSUS, "libffi8", "ctypes runtime (Python loads the library through it)"),
    ("libffi-dev", PROCURSUS, "libffi-dev", "ctypes headers"),
    ("dash", PROCURSUS, "dash", "shell used by the build"),
    ("ldid", PROCURSUS, "ldid", "signs the built library"),
    ("odcctools", PROCURSUS, "odcctools", "linker tools (ld, lipo, otool)"),
    ("python3.12", CYPWN, "prefix:python3.", "Python 3.9 or newer"),
)

# Without dpkg we can at least look for the programs themselves.
COMMANDS: Sequence[Tuple[str, str]] = (
    ("clang", "clang-16"),
    ("cmake", "cmake"),
    ("make", "make"),
    ("ldid", "ldid"),
)


def installed_packages() -> Optional[Dict[str, str]]:
    """{package: version} from dpkg, or None if dpkg isn't usable here."""
    query = shutil.which("dpkg-query")
    if not query:
        return None
    try:
        output = subprocess.run(
            [query, "-W", "-f=${Package}\t${Version}\t${Status}\n"],
            capture_output=True, text=True, timeout=60,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    packages: Dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[2].endswith(" installed"):
            packages[parts[0]] = parts[1]
    return packages


def _matches(rule: str, packages: Dict[str, str]) -> bool:
    if rule.startswith("prefix:"):
        prefix = rule[len("prefix:"):]
        return any(name.startswith(prefix) for name in packages)
    return rule in packages


def missing_packages(packages: Optional[Dict[str, str]] = None) -> List[Tuple[str, Tuple[str, str, str], str]]:
    """[(package, repository, purpose)] that aren't installed."""
    if packages is None:
        packages = installed_packages()
    missing = []
    if packages is None:
        for command, package in COMMANDS:
            if not shutil.which(command):
                entry = next(p for p in PACKAGES if p[0] == package)
                missing.append((entry[0], entry[1], entry[3]))
        return missing
    for package, repository, rule, purpose in PACKAGES:
        if package.startswith("python3."):
            continue  # judged by the running interpreter below
        if not _matches(rule, packages):
            missing.append((package, repository, purpose))
    return missing


def report(missing, python_ok: bool = True) -> str:
    """Human-readable list grouped by repository, with the install command."""
    if not missing and python_ok:
        return "All packages needed to build Unicorn are installed."
    lines = ["Missing packages for building Unicorn on iOS:"]
    by_repo: Dict[Tuple[str, str, str], List[Tuple[str, str]]] = {}
    for package, repository, purpose in missing:
        by_repo.setdefault(repository, []).append((package, purpose))
    if not python_ok:
        by_repo.setdefault(CYPWN, []).append(("python3.12", "Python 3.9 or newer (this one is %d.%d)" % sys.version_info[:2]))
    for (name, url, note), items in by_repo.items():
        lines.append("")
        lines.append("  %s - %s%s" % (name, url, " (%s)" % note if note else ""))
        for package, purpose in items:
            lines.append("    %-16s %s" % (package, purpose))
    names = [package for items in by_repo.values() for package, _ in items]
    lines.append("")
    lines.append("Add the repositories in Sileo/Zebra if needed, then install the packages there or with:")
    lines.append("    sudo apt install " + " ".join(names))
    return "\n".join(lines)


def check() -> Tuple[bool, str]:
    missing = missing_packages()
    python_ok = sys.version_info >= (3, 9)
    return (not missing and python_ok), report(missing, python_ok)


if __name__ == "__main__":
    ok, text = check()
    print(text)
    sys.exit(0 if ok else 1)
