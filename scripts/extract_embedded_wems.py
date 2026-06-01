from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path

from heartopia_wwise import (
    DEFAULT_GAME_ROOT,
    classify_bank,
    data_chunk,
    decode_bank_if_needed,
    default_bank_root,
    didx_entries,
    is_music_bank,
    relative_posix,
    sanitize,
)


DEFAULT_OUT = Path("extracted/embedded_wems")
DEFAULT_MANIFEST = Path("reports/embedded_wem_manifest.csv")
DEFAULT_SUMMARY = Path("reports/embedded_wem_summary.txt")


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract embedded WEM files from Heartopia Wwise banks.")
    parser.add_argument("--game-root", type=Path, default=DEFAULT_GAME_ROOT)
    parser.add_argument("--bank-root", type=Path, help="Override the Wwise bank directory.")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--all-banks", action="store_true", help="Extract from every bank instead of only music-related banks.")
    args = parser.parse_args()

    bank_root = (args.bank_root or default_bank_root(args.game_root)).resolve()
    if not bank_root.is_dir():
        raise SystemExit(f"Missing bank directory: {bank_root}")

    out_root = args.out.resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.summary.parent.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, str | int]] = []
    bank_counts: Counter[str] = Counter()
    extracted_files = 0
    skipped_non_music = 0

    for bank_path in sorted(bank_root.glob("*.bnk")):
        bank_category = classify_bank(bank_path.name)
        if not args.all_banks and not is_music_bank(bank_path.name):
            skipped_non_music += 1
            continue

        bank = decode_bank_if_needed(bank_path.read_bytes())
        entries = didx_entries(bank)
        payload = data_chunk(bank)
        if not entries or not payload:
            continue

        safe_bank = sanitize(bank_path.stem)
        dest_dir = out_root / safe_bank
        dest_dir.mkdir(parents=True, exist_ok=True)

        for index, (media_id, offset, size) in enumerate(entries, start=1):
            chunk = payload[offset : offset + size]
            if len(chunk) != size:
                continue
            filename = f"{safe_bank}__{media_id}.wem"
            dest_path = dest_dir / filename
            dest_path.write_bytes(chunk)
            rows.append(
                {
                    "bank_name": bank_path.name,
                    "bank_relative_path": relative_posix(bank_path, bank_root),
                    "bank_category": bank_category,
                    "media_id": media_id,
                    "embedded_index": index,
                    "size": size,
                    "output_relative_path": relative_posix(dest_path, Path.cwd()),
                    "output_path": str(dest_path),
                }
            )
            extracted_files += 1
            bank_counts[bank_category] += 1

    with args.manifest.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "bank_name",
                "bank_relative_path",
                "bank_category",
                "media_id",
                "embedded_index",
                "size",
                "output_relative_path",
                "output_path",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    with args.summary.open("w", encoding="utf-8") as handle:
        handle.write(f"Bank root: {bank_root}\n")
        handle.write(f"Output root: {out_root}\n")
        handle.write(f"Extracted embedded WEMs: {extracted_files}\n")
        handle.write(f"Skipped non-music banks: {skipped_non_music}\n\n")
        handle.write("Extracted rows by bank category:\n")
        for category, count in bank_counts.most_common():
            handle.write(f"  {category}: {count}\n")

    print(f"Extracted embedded WEMs: {extracted_files}")
    print(f"Wrote {args.manifest}")
    print(f"Wrote {args.summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
