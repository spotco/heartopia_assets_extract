from __future__ import annotations

import argparse
import csv
import os
from collections import Counter
from pathlib import Path

from heartopia_wwise import (
    DEFAULT_GAME_ROOT,
    classify_bank,
    decode_bank_if_needed,
    default_bank_root,
    didx_entries,
    relative_posix,
)


DEFAULT_OUT = Path("reports")


def classify_header(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            data = handle.read(32)
    except OSError as exc:
        return f"read_error:{exc.__class__.__name__}"

    if data.startswith(b"RIFF"):
        return "riff"
    if data.startswith(b"BKHD"):
        return "wwise_bank"
    return "unknown"


def iter_files(root: Path):
    for current, _, filenames in os.walk(root):
        current_path = Path(current)
        for filename in filenames:
            yield current_path / filename


def main() -> int:
    parser = argparse.ArgumentParser(description="Inventory Heartopia Wwise audio files.")
    parser.add_argument("--game-root", type=Path, default=DEFAULT_GAME_ROOT)
    parser.add_argument("--audio-root", type=Path, help="Override the Wwise bank directory.")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--header-limit", type=int, default=10000, help="Max files to header-classify.")
    args = parser.parse_args()

    game_root = args.game_root.resolve()
    audio_root = (args.audio_root or default_bank_root(game_root)).resolve()
    if not audio_root.is_dir():
        raise SystemExit(f"Missing audio directory: {audio_root}")

    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, str | int]] = []
    ext_counts: Counter[str] = Counter()
    ext_bytes: Counter[str] = Counter()
    header_counts: Counter[str] = Counter()
    bank_category_counts: Counter[str] = Counter()

    total_embedded_wems = 0
    scanned_files = 0
    missing_files = 0
    for index, path in enumerate(iter_files(audio_root)):
        try:
            stat = path.stat()
        except FileNotFoundError:
            missing_files += 1
            continue
        scanned_files += 1
        rel = relative_posix(path, audio_root)
        ext = path.suffix.lower() or "<none>"
        header = classify_header(path) if index < args.header_limit else "not_scanned"
        bank_category = ""
        embedded_wem_count = 0
        if ext == ".bnk":
            bank_category = classify_bank(path.name)
            try:
                embedded_wem_count = len(didx_entries(decode_bank_if_needed(path.read_bytes())))
            except OSError:
                embedded_wem_count = 0
            total_embedded_wems += embedded_wem_count
            bank_category_counts[bank_category] += 1

        ext_counts[ext] += 1
        ext_bytes[ext] += stat.st_size
        header_counts[header] += 1
        rows.append(
            {
                "relative_path": rel,
                "size": stat.st_size,
                "extension": ext,
                "header": header,
                "mtime": int(stat.st_mtime),
                "bank_category": bank_category,
                "embedded_wem_count": embedded_wem_count,
            }
        )

    manifest_path = out / "asset_manifest.csv"
    with manifest_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["relative_path", "size", "extension", "header", "mtime", "bank_category", "embedded_wem_count"],
        )
        writer.writeheader()
        writer.writerows(rows)

    summary_path = out / "summary.txt"
    with summary_path.open("w", encoding="utf-8") as handle:
        handle.write(f"Game root: {game_root}\n")
        handle.write(f"Audio root: {audio_root}\n")
        handle.write(f"Files: {scanned_files}\n")
        handle.write(f"Skipped missing during scan: {missing_files}\n")
        handle.write(f"Bytes: {sum(ext_bytes.values())}\n")
        handle.write(f"Loose WEM files: {ext_counts['.wem']}\n")
        handle.write(f"Bank files: {ext_counts['.bnk']}\n")
        handle.write(f"Embedded DIDX WEM entries across banks: {total_embedded_wems}\n\n")
        handle.write("Extensions:\n")
        for ext, count in ext_counts.most_common():
            handle.write(f"  {ext}: {count} files, {ext_bytes[ext]} bytes\n")
        handle.write("\nHeaders:\n")
        for header, count in header_counts.most_common():
            handle.write(f"  {header}: {count}\n")
        handle.write("\nMusic-related bank categories:\n")
        for category, count in bank_category_counts.most_common():
            handle.write(f"  {category}: {count}\n")

    print(f"Scanned files: {scanned_files}")
    print(f"Wrote {manifest_path}")
    print(f"Wrote {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
