from __future__ import annotations

import argparse
import csv
import re
from collections import Counter, defaultdict
from pathlib import Path

from heartopia_wwise import (
    DEFAULT_GAME_ROOT,
    build_music_label,
    choose_title,
    classify_bank,
    decode_bank_if_needed,
    default_bank_root,
    didx_media_ids,
    hirc_media_ids,
    is_music_bank,
    relative_posix,
)


DEFAULT_OUT = Path("reports/heartopia_music_name_candidates.csv")
DEFAULT_SUMMARY = Path("reports/heartopia_music_name_strategy_notes.txt")
DEFAULT_EMBEDDED_ROOT = Path("extracted/embedded_wems")


def media_id_from_name(name: str) -> int | None:
    stem = Path(name).stem
    if stem.isdecimal():
        return int(stem)
    match = re.search(r"__(\d+)$", stem)
    return int(match.group(1)) if match else None


def pick_source_path(extracted: list[str], loose: list[str]) -> str:
    if extracted:
        return extracted[0]
    if loose:
        return loose[0]
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description="Build first-pass human-readable Heartopia music names from Wwise bank filenames.")
    parser.add_argument("--game-root", type=Path, default=DEFAULT_GAME_ROOT)
    parser.add_argument("--bank-root", type=Path, help="Override the Wwise bank directory.")
    parser.add_argument("--embedded-root", type=Path, default=DEFAULT_EMBEDDED_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    args = parser.parse_args()

    bank_root = (args.bank_root or default_bank_root(args.game_root)).resolve()
    if not bank_root.is_dir():
        raise SystemExit(f"Missing bank directory: {bank_root}")
    embedded_root = args.embedded_root.resolve()

    loose_paths: dict[int, list[str]] = defaultdict(list)
    loose_absolute_paths: dict[int, list[str]] = defaultdict(list)
    for wem_path in sorted(bank_root.glob("*.wem")):
        media_id = media_id_from_name(wem_path.name)
        if media_id is None:
            continue
        loose_paths[media_id].append(relative_posix(wem_path, bank_root))
        loose_absolute_paths[media_id].append(str(wem_path))

    extracted_paths: dict[int, list[str]] = defaultdict(list)
    extracted_absolute_paths: dict[int, list[str]] = defaultdict(list)
    if embedded_root.is_dir():
        for wem_path in sorted(embedded_root.rglob("*.wem")):
            media_id = media_id_from_name(wem_path.name)
            if media_id is None:
                continue
            extracted_paths[media_id].append(relative_posix(wem_path, Path.cwd()))
            extracted_absolute_paths[media_id].append(str(wem_path))

    known_media_ids = set(loose_paths) | set(extracted_paths)
    media_to_banks: dict[int, set[str]] = defaultdict(set)
    bank_type_by_media: dict[int, set[str]] = defaultdict(set)
    parsed_banks = 0
    skipped_banks = 0

    for bank_path in sorted(bank_root.glob("*.bnk")):
        if not is_music_bank(bank_path.name):
            skipped_banks += 1
            continue
        bank = decode_bank_if_needed(bank_path.read_bytes())
        matched_ids = didx_media_ids(bank)
        if known_media_ids:
            matched_ids |= hirc_media_ids(bank, known_media_ids)
        if not matched_ids:
            continue
        rel = relative_posix(bank_path, bank_root)
        bank_kind = classify_bank(bank_path.name)
        for media_id in matched_ids:
            media_to_banks[media_id].add(rel)
            bank_type_by_media[media_id].add(bank_kind)
        parsed_banks += 1

    rows = []
    confidence_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    type_counts: Counter[str] = Counter()
    for media_id in sorted(media_to_banks):
        bank_names = sorted(media_to_banks[media_id])
        bank_types = sorted(bank_type_by_media[media_id])
        raw_title = choose_title(bank_names)
        title, label_strategy = build_music_label(raw_title, bank_types, media_id)
        loose = sorted(loose_paths.get(media_id, []))
        extracted = sorted(extracted_paths.get(media_id, []))
        absolute_extracted = sorted(extracted_absolute_paths.get(media_id, []))
        absolute_loose = sorted(loose_absolute_paths.get(media_id, []))
        if extracted and loose:
            source_kind = "embedded_and_loose"
        elif extracted:
            source_kind = "embedded"
        elif loose:
            source_kind = "loose"
        else:
            source_kind = "bank_reference_only"
        high_signal = {"instrument_theme_music", "bridge_music", "map_music", "ui_music", "timeline_music", "music_named_bank"}
        if title and any(kind in high_signal for kind in bank_types):
            confidence = "high" if source_kind != "bank_reference_only" else "medium"
        elif title and "general_ambience" in bank_types:
            confidence = "medium" if source_kind != "bank_reference_only" else "low"
        else:
            confidence = "low"

        source_path = pick_source_path(absolute_extracted, absolute_loose)
        rows.append(
            {
                "media_id": media_id,
                "source_kind": source_kind,
                "source_path": source_path,
                "loose_relative_paths": "|".join(loose),
                "embedded_relative_paths": "|".join(extracted),
                "bank_names": "|".join(bank_names),
                "bank_types": "|".join(bank_types),
                "raw_title": raw_title,
                "label_strategy": label_strategy,
                "suggested_title": title,
                "suggested_filename": f"{title}__{media_id}.wem" if title else "",
                "confidence": confidence,
            }
        )
        confidence_counts[confidence] += 1
        source_counts[source_kind] += 1
        for bank_type in bank_types:
            type_counts[bank_type] += 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "media_id",
                "source_kind",
                "source_path",
                "confidence",
                "raw_title",
                "label_strategy",
                "suggested_title",
                "suggested_filename",
                "bank_types",
                "bank_names",
                "loose_relative_paths",
                "embedded_relative_paths",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    with args.summary.open("w", encoding="utf-8") as handle:
        handle.write(f"Bank root: {bank_root}\n")
        handle.write(f"Embedded root: {embedded_root}\n")
        handle.write(f"Music candidate rows: {len(rows)}\n")
        handle.write(f"Parsed music-related banks: {parsed_banks}\n")
        handle.write(f"Skipped non-music banks: {skipped_banks}\n\n")
        handle.write("Confidence counts:\n")
        for key, count in confidence_counts.most_common():
            handle.write(f"  {key}: {count}\n")
        handle.write("\nSource counts:\n")
        for key, count in source_counts.most_common():
            handle.write(f"  {key}: {count}\n")
        handle.write("\nBank type hits:\n")
        for key, count in type_counts.most_common():
            handle.write(f"  {key}: {count}\n")
        handle.write("\nNotes:\n")
        handle.write("1. Heartopia ships plain BKHD banks and plain RIFF WEM files, so Sword's XOR-decoding path is preserved but usually unused.\n")
        handle.write("2. No SoundBanksInfo/XML or exported event-name manifest was found in the install, so labels come from bank filenames when possible and fall back to stable bank-type-plus-media-id labels for generic banks.\n")
        handle.write("3. Most clearly named music appears to be embedded in DIDX/DATA chunks inside music-related banks, so extraction is required before conversion.\n")
        handle.write("4. HIRC scanning is only used here to catch loose WEM ids referenced by music banks without direct DIDX entries.\n")

    print(f"Wrote {args.out}")
    print(f"Wrote {args.summary}")
    print(f"Music candidate rows: {len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
