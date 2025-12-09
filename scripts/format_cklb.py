#!/usr/bin/env python3
"""
Pretty-print CKLB files (JSON) so they are readable instead of a single line.

Usage examples:
  python scripts/format_cklb.py tmp/IONC_Oracle8_V2R5_20251208-033602.cklb
  python scripts/format_cklb.py tmp --recursive --output-dir formatted_cklbs
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Iterable, Iterator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Format CKLB JSON files with indentation for readability."
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="File(s) or directory(ies) containing .cklb files to format.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Optional directory to write formatted files. Defaults to formatting in place.",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="When a directory is provided, search recursively for .cklb files.",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="Indentation level for formatted JSON (default: 2).",
    )
    return parser.parse_args()


def find_cklb_files(paths: Iterable[str], recursive: bool) -> Iterator[Path]:
    """Yield unique .cklb files from the given paths."""
    seen: set[Path] = set()
    for raw in paths:
        path = Path(raw).expanduser()
        if path.is_dir():
            pattern = "**/*.cklb" if recursive else "*.cklb"
            for file_path in sorted(path.glob(pattern)):
                if file_path.is_file() and file_path.suffix.lower() == ".cklb":
                    if file_path not in seen:
                        seen.add(file_path)
                        yield file_path
        elif path.is_file() and path.suffix.lower() == ".cklb":
            if path not in seen:
                seen.add(path)
                yield path
        else:
            print(f"[skip] {path} is not a .cklb file or directory", file=sys.stderr)


def format_cklb_file(path: Path, output_dir: Path | None, indent: int) -> Path:
    """Load a CKLB JSON file and write a formatted version."""
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON ({exc})") from exc

    target = path if output_dir is None else Path(output_dir) / path.name
    target.parent.mkdir(parents=True, exist_ok=True)

    with target.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent)
        f.write("\n")

    return target


def main() -> int:
    args = parse_args()

    files = list(find_cklb_files(args.paths, args.recursive))
    if not files:
        print("No .cklb files found to format.", file=sys.stderr)
        return 1

    failures: list[str] = []
    for file_path in files:
        try:
            target = format_cklb_file(file_path, args.output_dir, args.indent)
            print(f"[formatted] {file_path} -> {target}")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{file_path}: {exc}")

    if failures:
        print("Some files could not be formatted:", file=sys.stderr)
        for msg in failures:
            print(f"  - {msg}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
