#!/usr/bin/env python3
"""Compile NexHunt's premium backend modules as Stable-ABI C extensions."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from Cython.Build import cythonize
from setuptools import Extension, setup


PREMIUM_MODULES = [
    # License providers, storage, fingerprinting, manager, and feature gates.
    "nexhunt.licensing.fingerprint",
    "nexhunt.licensing.guard",
    "nexhunt.licensing.gumroad",
    "nexhunt.licensing.keygen",
    "nexhunt.licensing.lemonsqueezy",
    "nexhunt.licensing.manager",
    "nexhunt.licensing.provider",
    "nexhunt.licensing.store",
    # Premium APIs and mixed API modules containing guarded routes.
    "nexhunt.api.license",
    "nexhunt.api.copilot",
    "nexhunt.api.api_scanner",
    "nexhunt.api.jwt_attacks",
    "nexhunt.api.bizlogic",
    "nexhunt.api.wordpress",
    "nexhunt.api.exposure_intel",
    "nexhunt.api.repository_intelligence",
    "nexhunt.api.pipeline",
    "nexhunt.api.proxy",
    "nexhunt.api.recon",
    "nexhunt.api.scanner",
    "nexhunt.api.security_tools",
    # Premium implementations called by the guarded API layer.
    "nexhunt.adapters.api_scanner",
    "nexhunt.adapters.cloud_buckets",
    "nexhunt.adapters.graphql_audit",
    "nexhunt.adapters.js_api_mapper",
    "nexhunt.adapters.wpscan",
    "nexhunt.services.copilot_service",
    "nexhunt.services.ngrok_manager",
    "nexhunt.services.repository_intelligence",
]


def module_source(backend: Path, module: str) -> Path:
    return backend / (module.replace(".", "/") + ".py")


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: build-premium-cython.py BACKEND_DIR BUILD_DIR", file=sys.stderr)
        return 2

    backend = Path(sys.argv[1]).resolve()
    build_dir = Path(sys.argv[2]).resolve()
    generated = build_dir / "generated"
    objects = build_dir / "objects"
    output = build_dir / "output"

    if build_dir.exists():
        shutil.rmtree(build_dir)
    generated.mkdir(parents=True)
    objects.mkdir(parents=True)
    output.mkdir(parents=True)

    extensions: list[Extension] = []
    for module in PREMIUM_MODULES:
        source = module_source(backend, module)
        if not source.is_file():
            raise FileNotFoundError(f"Premium module not found: {source}")
        extensions.append(
            Extension(
                module,
                [str(source)],
                define_macros=[
                    ("Py_LIMITED_API", "0x030A0000"),
                    ("CYTHON_LIMITED_API", "1"),
                ],
                py_limited_api=True,
            )
        )

    compiled = cythonize(
        extensions,
        build_dir=str(generated),
        compiler_directives={
            "language_level": 3,
            # FastAPI inspects endpoint signatures and annotations.
            "binding": True,
            "embedsignature": True,
            # Treat annotations as Python metadata, not Cython type declarations.
            # FastAPI commonly uses e.g. `limit: int = Query(...)`.
            "annotation_typing": False,
        },
        compile_time_env={"NEXHUNT_PREMIUM_BUILD": True},
    )

    setup(
        name="nexhunt-premium",
        version="1",
        ext_modules=compiled,
        script_args=[
            "--quiet",
            "build_ext",
            "--build-lib",
            str(output),
            "--build-temp",
            str(objects),
        ],
    )

    strip = shutil.which("strip")
    for module in PREMIUM_MODULES:
        relative = Path(*module.split("."))
        built = output / relative.parent / f"{relative.name}.abi3.so"
        source = module_source(backend, module)
        if not built.is_file():
            raise FileNotFoundError(f"Compiled extension not produced: {built}")
        destination = source.with_name(built.name)
        shutil.copy2(built, destination)
        if strip:
            subprocess.run([strip, "--strip-unneeded", str(destination)], check=True)
        source.unlink()
        print(f"  [compiled] {module} -> {destination.name}")

    remaining = [str(module_source(backend, name)) for name in PREMIUM_MODULES if module_source(backend, name).exists()]
    if remaining:
        raise RuntimeError(f"Premium sources still present: {remaining}")

    print(f"  [ok] {len(PREMIUM_MODULES)} premium modules compiled with CPython Stable ABI 3.10+")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
