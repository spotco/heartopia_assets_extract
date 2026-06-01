from __future__ import annotations

import argparse
import csv
import re
import subprocess
import tempfile
from pathlib import Path

from heartopia_wwise import decode_wem_bytes


DEFAULT_MANIFEST = Path("reports/heartopia_music_name_candidates.csv")
DEFAULT_OUT = Path("reports/heartopia_music_analysis.csv")
DEFAULT_SUMMARY = Path("reports/heartopia_music_analysis_summary.txt")
DEFAULT_VGMSTREAM = Path("tools/vgmstream/vgmstream-cli.exe")


def decoded_sample(path: Path, sample_size: int = 64) -> bytes:
    return decode_wem_bytes(path)[:sample_size]


def source_state(path: Path) -> str:
    sample = decoded_sample(path)
    if sample.startswith(b"RIFF") and sample[8:12] == b"WAVE":
        return "wwise_riff"
    return "unknown"


def vgmstream_info(vgmstream: Path, path: Path) -> dict[str, str]:
    decoded = decode_wem_bytes(path)
    with tempfile.NamedTemporaryFile(suffix=".wem", delete=False) as handle:
        temp_path = Path(handle.name)
        handle.write(decoded)
    proc = subprocess.run(
        [str(vgmstream), "-m", str(temp_path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    temp_path.unlink(missing_ok=True)
    text = proc.stdout
    info: dict[str, str] = {"vgmstream_ok": str(proc.returncode == 0), "vgmstream_output": text.replace("\r", "")}
    patterns = {
        "sample_rate": r"sample rate:\s*([^\n]+)",
        "channels": r"channels:\s*([^\n]+)",
        "duration": r"stream total samples:.*?\(([^)]+)\)",
        "encoding": r"encoding:\s*([^\n]+)",
        "layout": r"layout:\s*([^\n]+)",
        "bitrate": r"bitrate:\s*([^\n]+)",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        info[key] = match.group(1).strip() if match else ""
    info["duration_seconds"] = str(duration_to_seconds(info.get("duration", "")))
    return info


def duration_to_seconds(text: str) -> float:
    if not text:
        return 0.0
    text = text.strip().removesuffix(" seconds").strip()
    parts = text.strip().split(":")
    try:
        if len(parts) == 3:
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])
        if len(parts) == 2:
            return int(parts[0]) * 60 + float(parts[1])
        return float(parts[0])
    except ValueError:
        return 0.0


def classify(row: dict[str, str]) -> tuple[str, str]:
    seconds = float(row.get("duration_seconds") or 0)
    channels = row.get("channels", "")
    bank_types = row.get("bank_types", "")
    if seconds >= 45 and "2" in channels:
        return "likely_music_or_ambience", "stereo and at least 45 seconds"
    if seconds >= 20 and "2" in channels:
        return "possibly_music_ambience_or_long_sfx", "stereo and at least 20 seconds"
    if "general_ambience" in bank_types and seconds >= 10:
        return "likely_ambience_loop", "ambience bank and non-trivial duration"
    if 0 < seconds < 10:
        return "likely_sfx_or_stinger", "short duration"
    return "unknown", "insufficient metadata"


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze Heartopia music candidate WEM files with vgmstream.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--path-field", default="source_path")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--vgmstream", type=Path, default=DEFAULT_VGMSTREAM)
    args = parser.parse_args()

    with args.manifest.open("r", newline="", encoding="utf-8") as handle:
        inputs = list(csv.DictReader(handle))

    rows = []
    for index, item in enumerate(inputs, start=1):
        source_value = item.get(args.path_field, "")
        if not source_value:
            continue
        path = Path(source_value)
        row = {
            "media_id": item.get("media_id", ""),
            "source_kind": item.get("source_kind", ""),
            "source_path": source_value,
            "suggested_title": item.get("suggested_title", ""),
            "bank_types": item.get("bank_types", ""),
            "bank_names": item.get("bank_names", ""),
            "size": str(path.stat().st_size if path.exists() else 0),
            "source_state": source_state(path) if path.exists() else "missing_file",
        }
        if path.exists() and args.vgmstream.exists():
            row.update(vgmstream_info(args.vgmstream, path))
        category, reason = classify(row)
        row["category"] = category
        row["reason"] = reason
        rows.append(row)
        if index % 100 == 0:
            print(f"Analyzed {index}/{len(inputs)}")

    fieldnames = [
        "media_id",
        "source_kind",
        "source_path",
        "suggested_title",
        "category",
        "reason",
        "duration_seconds",
        "duration",
        "channels",
        "sample_rate",
        "encoding",
        "bitrate",
        "bank_types",
        "bank_names",
        "size",
        "source_state",
        "vgmstream_ok",
    ]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    counts: dict[str, int] = {}
    duration_totals: dict[str, float] = {}
    for row in rows:
        counts[row["category"]] = counts.get(row["category"], 0) + 1
        duration_totals[row["category"]] = duration_totals.get(row["category"], 0.0) + float(row.get("duration_seconds") or 0)

    with args.summary.open("w", encoding="utf-8") as handle:
        handle.write(f"Heartopia candidate WEM files analyzed: {len(rows)}\n\n")
        for category, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
            handle.write(f"{category}: {count} files, total duration {duration_totals[category]:.1f}s\n")
        handle.write("\nLongest likely music/ambience candidates:\n")
        for row in sorted(rows, key=lambda item: float(item.get("duration_seconds") or 0), reverse=True):
            if row["category"] in {"likely_music_or_ambience", "possibly_music_ambience_or_long_sfx", "likely_ambience_loop"}:
                handle.write(
                    f"{row['media_id']}\t{row.get('suggested_title','')}\t{row['category']}\t"
                    f"{float(row.get('duration_seconds') or 0):.1f}s\t{row.get('channels','')}ch\t{row.get('bank_types','')}\n"
                )

    print(f"Wrote {args.out}")
    print(f"Wrote {args.summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
