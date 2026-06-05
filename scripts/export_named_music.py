from __future__ import annotations

import argparse
import csv
import re
import shutil
import subprocess
from pathlib import Path

from heartopia_wwise import decode_wem_bytes


DEFAULT_NAMES = Path("reports/heartopia_music_name_candidates.csv")
DEFAULT_OUT = Path("extracted/music_mp3")
DEFAULT_VGMSTREAM = Path("tools/vgmstream/vgmstream-cli.exe")


def require_tool(path_or_name: str | Path) -> str:
    text = str(path_or_name)
    if Path(text).exists():
        return text
    found = shutil.which(text)
    if found:
        return found
    raise SystemExit(f"Missing required tool: {text}")


def safe_filename(text: str, max_len: int = 180) -> str:
    text = re.sub(r"[<>:\"/\\|?*\x00-\x1f]+", "_", text)
    text = re.sub(r"_+", "_", text).strip(" ._")
    return (text or "unnamed")[:max_len].rstrip(" ._")


def decode_wem_to_file(source: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(decode_wem_bytes(source))


def convert_to_mp3(vgmstream: str, ffmpeg: str, decoded_wem: Path, wav: Path, mp3: Path, bitrate: str) -> None:
    subprocess.run([vgmstream, "-o", str(wav), str(decoded_wem)], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    subprocess.run(
        [
            ffmpeg,
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            str(wav),
            "-codec:a",
            "libmp3lame",
            "-b:a",
            bitrate,
            str(mp3),
        ],
        check=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Export Heartopia named music/ambience WEMs to MP3.")
    parser.add_argument("--names", type=Path, default=DEFAULT_NAMES)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--vgmstream", type=Path, default=DEFAULT_VGMSTREAM)
    parser.add_argument("--ffmpeg", default="ffmpeg")
    parser.add_argument("--bitrate", default="192k")
    parser.add_argument("--include-low-confidence", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    vgmstream = require_tool(args.vgmstream)
    ffmpeg = require_tool(args.ffmpeg)
    out = args.out.resolve()
    tmp = out / "_tmp"
    out.mkdir(parents=True, exist_ok=True)
    tmp.mkdir(parents=True, exist_ok=True)

    with args.names.open("r", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    selected = []
    skipped = []
    for row in rows:
        title = row.get("suggested_title", "")
        confidence = row.get("confidence", "")
        source_value = row.get("source_path", "")
        if not source_value:
            row["export_status"] = "skipped_missing_source"
            skipped.append(row)
            continue
        if confidence == "low" and not args.include_low_confidence:
            row["export_status"] = "skipped_low_confidence"
            skipped.append(row)
            continue
        if not title:
            title = f"unnamed_{row['media_id']}"
        selected.append(row | {"effective_title": title})

    if args.limit:
        selected = selected[: args.limit]

    exported = []
    errors = []
    try:
        for index, row in enumerate(selected, start=1):
            media_id = row["media_id"]
            title = safe_filename(row["effective_title"])
            source = Path(row["source_path"])
            filename = safe_filename(f"{title}__{media_id}.mp3")
            dest_mp3 = out / filename
            decoded = tmp / f"{media_id}.wem"
            wav = tmp / f"{media_id}.wav"

            if dest_mp3.exists() and not args.overwrite:
                row["export_status"] = "exists"
                row["output_path"] = str(dest_mp3)
                exported.append(row)
                print(f"[{index}/{len(selected)}] exists {filename}")
                continue

            try:
                decode_wem_to_file(source, decoded)
                convert_to_mp3(vgmstream, ffmpeg, decoded, wav, dest_mp3, args.bitrate)
                row["export_status"] = "exported"
                row["output_path"] = str(dest_mp3)
                exported.append(row)
                print(f"[{index}/{len(selected)}] exported {filename}")
            except Exception as exc:
                row["export_status"] = f"error:{exc.__class__.__name__}"
                row["error"] = str(exc)
                errors.append(row)
                print(f"[{index}/{len(selected)}] ERROR {source}: {exc}")
            finally:
                decoded.unlink(missing_ok=True)
                wav.unlink(missing_ok=True)
    finally:
        try:
            tmp.rmdir()
        except OSError:
            pass

    manifest = out / "music_export_manifest.csv"
    fieldnames = [
        "media_id",
        "source_kind",
        "source_path",
        "confidence",
        "raw_title",
        "label_strategy",
        "suggested_title",
        "suggested_filename",
        "bank_names",
        "export_status",
        "output_path",
        "error",
    ]
    with manifest.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(exported)
        writer.writerows(skipped)
        writer.writerows(errors)

    print(f"Exported/exists: {len(exported)}")
    print(f"Skipped: {len(skipped)}")
    print(f"Errors: {len(errors)}")
    print(f"Manifest: {manifest}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
