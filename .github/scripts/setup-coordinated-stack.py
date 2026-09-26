#!/usr/bin/env python3
"""Test unpublished sibling commits on an ephemeral GitHub Actions runner.

This is CI-only. It never changes a production manifest or publishes a crate.
Remove the stack pins after compatible releases and lockfiles are available.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib


def run(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True)


def main():
    root = Path(__file__).resolve().parents[2]
    manifest = json.loads((root / ".github/coordinated-stack.json").read_text())
    allowed = {"riptering", "ritsp-ltv", "ribergshamra"}
    for name, entry in manifest.items():
        if name not in allowed or not re.fullmatch(r"[0-9a-f]{40}", entry["revision"]):
            raise ValueError("Stack pins must name known repositories and full commit SHAs")
        for package, relative in entry["packages"].items():
            if not re.fullmatch(r"[a-z0-9-]+", package):
                raise ValueError("Invalid crate name")
            if Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise ValueError("Crate paths must stay within their pinned repository")
    if sys.argv[1:] == ["--check"]:
        print("Coordinated stack manifest is valid")
        return
    if sys.argv[1:] or os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("This setup only runs on ephemeral GitHub Actions runners")

    stack = Path(os.environ["RUNNER_TEMP"]) / "coordinated-stack"
    stack.mkdir(exist_ok=True)
    patches = {}
    for name, entry in manifest.items():
        directory = stack / name
        if directory.exists():
            raise ValueError("Refusing to reuse an existing stack checkout")
        directory.mkdir()
        run("git", "init", "--quiet", str(directory))
        run("git", "-C", str(directory), "fetch", "--quiet", "--depth=1",
            f"https://github.com/Rhein-Industries/{name}.git", entry["revision"])
        run("git", "-C", str(directory), "checkout", "--quiet", "--detach", "FETCH_HEAD")
        actual = subprocess.check_output(
            ["git", "-C", str(directory), "rev-parse", "HEAD"], text=True).strip()
        if actual != entry["revision"]:
            raise ValueError("Fetched revision does not match the immutable pin")
        print(f"Testing {name} at {actual}", flush=True)
        for package, relative in entry["packages"].items():
            path = (directory / relative).resolve()
            if not path.is_relative_to(directory.resolve()) or not (path / "Cargo.toml").is_file():
                raise ValueError("Missing or escaped crate manifest")
            if package in patches:
                raise ValueError("Duplicate package patch")
            patches[package] = path

    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
    cargo_home.mkdir(exist_ok=True)
    config = cargo_home / "config.toml"
    previous = config.read_text() if config.exists() else ""
    if (cargo_home / "config").exists() or "[patch." in previous:
        raise ValueError("Refusing to overwrite pre-existing Cargo patch configuration")
    lines = [previous.rstrip(), "", "# Ephemeral coordinated security-review stack.", "[patch.crates-io]"]
    for package, path in sorted(patches.items()):
        lines.append(f"{package} = {{ path = {json.dumps(path.as_posix())} }}")
    config.write_text("\n".join(lines) + "\n")

    original = tomllib.loads((root / "Cargo.lock").read_text())
    # A lockfile can retain an older registry version and leave a newer path
    # patch unused. Select each pinned package explicitly before verification.
    for package, path in patches.items():
        package_manifest = tomllib.loads((path / "Cargo.toml").read_text())
        version = package_manifest["package"]["version"]
        if isinstance(version, dict) and version.get("workspace") is True:
            for parent in path.parents:
                manifest_path = parent / "Cargo.toml"
                if manifest_path.is_file():
                    workspace = tomllib.loads(manifest_path.read_text()).get("workspace", {})
                    if "version" in workspace.get("package", {}):
                        version = workspace["package"]["version"]
                        break
        if not isinstance(version, str):
            raise ValueError(f"Cannot read pinned version for {package}")
        run("cargo", "update", "--package", package, "--precise", version, cwd=root)
    # Resolve only the source/feature changes in this disposable checkout.
    # Every later build/test command remains --locked.
    data = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version=1"], cwd=root, text=True))
    resolved = tomllib.loads((root / "Cargo.lock").read_text())
    def versions(lock):
        result = {}
        for package in lock["package"]:
            if package["name"] not in patches:
                result.setdefault(package["name"], set()).add(package["version"])
        return result
    before, after = versions(original), versions(resolved)
    for name in before.keys() & after.keys():
        if not after[name].issubset(before[name]):
            raise ValueError(f"Unexpected dependency version change: {name}")
    for package, path in patches.items():
        matches = [item for item in data["packages"] if item["name"] == package]
        if len(matches) != 1 or matches[0]["source"] is not None:
            raise ValueError(f"Expected exactly one local {package}")
        if Path(matches[0]["manifest_path"]).resolve() != path / "Cargo.toml":
            raise ValueError(f"Resolved unexpected {package} manifest")
    subprocess.run(["cargo", "metadata", "--locked", "--format-version=1", "--no-deps"],
                   cwd=root, check=True, stdout=subprocess.DEVNULL)
    print("Pinned sibling sources resolved; existing dependency versions preserved", flush=True)


if __name__ == "__main__":
    main()
