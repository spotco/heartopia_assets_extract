from __future__ import annotations

import argparse
import csv
import json
import struct
from collections import Counter
from pathlib import Path
from typing import Any, Callable

from heartopia_wwise import DEFAULT_GAME_ROOT


DEFAULT_ASSEMBLY_DIR = Path(r"xdt_Data\StreamingAssets\DotnetAssemblies")
DEFAULT_JSON_OUT = Path("reports/wrapped_assembly_inspection.json")
DEFAULT_TEXT_OUT = Path("reports/wrapped_assembly_inspection.txt")
DEFAULT_CSV_OUT = Path("reports/wrapped_assembly_manifest.csv")
XDENCODE_MAGIC = b"XDENCODE0001"
XDENCODE_HEADER_SIZE = 298
HEADER_U32_COUNT = 10
MZ_SCAN_LIMIT = 32


def find_mz_offsets(data: bytes, limit: int = MZ_SCAN_LIMIT) -> list[int]:
    offsets: list[int] = []
    start = 0
    while len(offsets) < limit:
        offset = data.find(b"MZ", start)
        if offset < 0:
            break
        offsets.append(offset)
        start = offset + 1
    return offsets


def parse_pe_at(data: bytes, mz_offset: int) -> dict[str, int] | None:
    if mz_offset < 0 or mz_offset + 0x40 > len(data):
        return None
    if data[mz_offset : mz_offset + 2] != b"MZ":
        return None
    pe_relative_offset = int.from_bytes(data[mz_offset + 0x3C : mz_offset + 0x40], "little")
    pe_offset = mz_offset + pe_relative_offset
    if pe_relative_offset < 0x40 or pe_offset + 4 > len(data):
        return None
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return None
    return {
        "mz_offset": mz_offset,
        "pe_relative_offset": pe_relative_offset,
        "pe_offset": pe_offset,
    }


def first_valid_pe(data: bytes) -> dict[str, int] | None:
    for mz_offset in find_mz_offsets(data):
        details = parse_pe_at(data, mz_offset)
        if details:
            return details
    return None


def nibble_swap(data: bytes) -> bytes:
    return bytes(((value & 0x0F) << 4) | (value >> 4) for value in data)


def rotate_left(data: bytes, bits: int) -> bytes:
    return bytes((((value << bits) & 0xFF) | (value >> (8 - bits))) for value in data)


def rotate_right(data: bytes, bits: int) -> bytes:
    return bytes(((value >> bits) | ((value << (8 - bits)) & 0xFF)) for value in data)


def transform_xor(data: bytes, value: int) -> bytes:
    return bytes(byte ^ value for byte in data)


def transform_add(data: bytes, value: int) -> bytes:
    return bytes((byte + value) & 0xFF for byte in data)


def transform_sub(data: bytes, value: int) -> bytes:
    return bytes((byte - value) & 0xFF for byte in data)


def repeating_xor(data: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def candidate_payload_transforms(payload: bytes) -> tuple[list[str], list[str]]:
    if len(payload) < 2:
        return [], []

    prefix_hits: list[tuple[str, Callable[[bytes], bytes]]] = []
    if payload.startswith(b"MZ"):
        prefix_hits.append(("identity", lambda data: data))

    for value in range(256):
        if bytes((payload[0] ^ value, payload[1] ^ value)) == b"MZ":
            prefix_hits.append((f"xor:{value}", lambda data, key=value: transform_xor(data, key)))
        if bytes((((payload[0] + value) & 0xFF), ((payload[1] + value) & 0xFF))) == b"MZ":
            prefix_hits.append((f"add:{value}", lambda data, key=value: transform_add(data, key)))
        if bytes((((payload[0] - value) & 0xFF), ((payload[1] - value) & 0xFF))) == b"MZ":
            prefix_hits.append((f"sub:{value}", lambda data, key=value: transform_sub(data, key)))

    if nibble_swap(payload[:2]) == b"MZ":
        prefix_hits.append(("nibble_swap", nibble_swap))

    for bits in range(1, 8):
        if rotate_left(payload[:2], bits) == b"MZ":
            prefix_hits.append((f"rol:{bits}", lambda data, count=bits: rotate_left(data, count)))
        if rotate_right(payload[:2], bits) == b"MZ":
            prefix_hits.append((f"ror:{bits}", lambda data, count=bits: rotate_right(data, count)))

    unique_prefix_hits: list[str] = []
    valid_pe_hits: list[str] = []
    seen_names: set[str] = set()
    for name, transform in prefix_hits:
        if name in seen_names:
            continue
        seen_names.add(name)
        unique_prefix_hits.append(name)
        if first_valid_pe(transform(payload)):
            valid_pe_hits.append(name)
    return unique_prefix_hits, valid_pe_hits


def header_field_xor_candidates(payload: bytes, header_values: list[int]) -> tuple[list[str], list[str]]:
    if len(payload) < 2 or len(header_values) < 3:
        return [], []

    candidates = [
        ("xor_field1_le", struct.pack("<I", header_values[1])),
        ("xor_field1_be", struct.pack(">I", header_values[1])),
        ("xor_field2_le", struct.pack("<I", header_values[2])),
        ("xor_field2_be", struct.pack(">I", header_values[2])),
    ]

    prefix_hits: list[str] = []
    valid_pe_hits: list[str] = []
    for name, key in candidates:
        transformed = repeating_xor(payload, key)
        if transformed.startswith(b"MZ"):
            prefix_hits.append(f"{name}:{key.hex()}")
        pe_details = first_valid_pe(transformed)
        if pe_details:
            valid_pe_hits.append(f"{name}:{key.hex()}@{pe_details['pe_offset']}")
    return prefix_hits, valid_pe_hits


def header_u32_values(data: bytes, count: int = HEADER_U32_COUNT) -> list[int]:
    start = len(XDENCODE_MAGIC)
    available = max(0, min(count, (len(data) - start) // 4))
    if not available:
        return []
    return list(struct.unpack_from(f"<{available}I", data, start))


def inspect_plain_pe(path: Path, data: bytes) -> dict[str, Any]:
    return {
        "name": path.name,
        "kind": "plain_pe",
        "size": len(data),
        "raw_mz_offsets": [0],
        "raw_valid_pe": parse_pe_at(data, 0),
    }


def inspect_xdencode(path: Path, data: bytes) -> dict[str, Any]:
    payload_size_field = struct.unpack_from("<I", data, len(XDENCODE_MAGIC))[0] if len(data) >= 16 else 0
    payload = data[XDENCODE_HEADER_SIZE:] if len(data) >= XDENCODE_HEADER_SIZE else b""
    raw_valid_pe = first_valid_pe(data)
    prefix_hits, valid_pe_hits = candidate_payload_transforms(payload)
    header_values = header_u32_values(data)
    header_field_prefix_hits, header_field_valid_pe_hits = header_field_xor_candidates(payload, header_values)
    return {
        "name": path.name,
        "kind": "xdencode",
        "size": len(data),
        "header_size": XDENCODE_HEADER_SIZE,
        "payload_size_field": payload_size_field,
        "payload_size_from_file": max(0, len(data) - XDENCODE_HEADER_SIZE),
        "payload_size_matches_file": payload_size_field == max(0, len(data) - XDENCODE_HEADER_SIZE),
        "header_u32_values": header_values,
        "header_u32_deltas": [value - payload_size_field for value in header_values],
        "raw_mz_offsets": find_mz_offsets(data),
        "raw_valid_pe": raw_valid_pe,
        "payload_prefix_mz_hits": prefix_hits,
        "payload_valid_pe_hits": valid_pe_hits,
        "header_field_xor_mz_hits": header_field_prefix_hits,
        "header_field_xor_valid_pe_hits": header_field_valid_pe_hits,
    }


def inspect_other(path: Path, data: bytes) -> dict[str, Any]:
    return {
        "name": path.name,
        "kind": "other",
        "size": len(data),
        "head_hex": data[:32].hex(),
        "raw_mz_offsets": find_mz_offsets(data),
        "raw_valid_pe": first_valid_pe(data),
    }


def inspect_assembly(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if data.startswith(b"MZ"):
        return inspect_plain_pe(path, data)
    if data.startswith(XDENCODE_MAGIC):
        return inspect_xdencode(path, data)
    return inspect_other(path, data)


def iter_assemblies(root: Path, names: list[str] | None) -> list[Path]:
    files = sorted(root.glob("*.dll.bytes"))
    if not names:
        return files
    allowed = {name.lower() for name in names}
    return [path for path in files if path.name.lower() in allowed]


def render_text_report(assemblies_root: Path, records: list[dict[str, Any]]) -> str:
    kind_counts = Counter(record["kind"] for record in records)
    wrapped = [record for record in records if record["kind"] == "xdencode"]

    lines = [f"Assemblies root: {assemblies_root}", ""]
    lines.append(f"Total assemblies: {len(records)}")
    for kind, count in sorted(kind_counts.items()):
        lines.append(f"  {kind}: {count}")
    lines.append("")

    if wrapped:
        lines.append("Wrapped assembly summary:")
        lines.append(f"  payload-size field matches file minus {XDENCODE_HEADER_SIZE}: {sum(1 for record in wrapped if record['payload_size_matches_file'])}/{len(wrapped)}")
        lines.append(f"  wrapped files with raw MZ offsets present: {sum(1 for record in wrapped if record['raw_mz_offsets'])}/{len(wrapped)}")
        lines.append(f"  wrapped files with raw valid PE found: {sum(1 for record in wrapped if record['raw_valid_pe'])}/{len(wrapped)}")
        lines.append(
            "  wrapped files with simple payload-start MZ hits: "
            f"{sum(1 for record in wrapped if record['payload_prefix_mz_hits'])}/{len(wrapped)}"
        )
        lines.append(
            "  wrapped files with header-field XOR payload-start MZ hits: "
            f"{sum(1 for record in wrapped if record['header_field_xor_mz_hits'])}/{len(wrapped)}"
        )
        lines.append(
            "  wrapped files with header-field XOR valid PEs: "
            f"{sum(1 for record in wrapped if record['header_field_xor_valid_pe_hits'])}/{len(wrapped)}"
        )
        lines.append("")

        delta_counter: dict[int, Counter[int]] = {}
        for index in range(HEADER_U32_COUNT):
            delta_counter[index] = Counter(
                record["header_u32_deltas"][index]
                for record in wrapped
                if len(record["header_u32_deltas"]) > index
            )
        lines.append("Common wrapped header deltas (field - payload_size_field):")
        for index in range(HEADER_U32_COUNT):
            common = delta_counter[index].most_common(3)
            if not common:
                continue
            formatted = ", ".join(f"{value} ({count})" for value, count in common)
            lines.append(f"  [{index}] {formatted}")
        lines.append("")

        lines.append("Wrapped assemblies:")
        for record in wrapped:
            lines.append(
                f"  {record['name']}: payload={record['payload_size_field']}, "
                f"raw_mz={record['raw_mz_offsets'][:3]}, "
                f"raw_valid_pe={bool(record['raw_valid_pe'])}, "
                f"prefix_hits={', '.join(record['payload_prefix_mz_hits']) or '-'}, "
                f"valid_pe_hits={', '.join(record['payload_valid_pe_hits']) or '-'}, "
                f"header_xor_hits={', '.join(record['header_field_xor_mz_hits']) or '-'}, "
                f"header_xor_valid={', '.join(record['header_field_xor_valid_pe_hits']) or '-'}"
            )
        lines.append("")

    plain = [record for record in records if record["kind"] == "plain_pe"]
    if plain:
        lines.append("Plain PE assemblies:")
        for record in plain[:10]:
            lines.append(f"  {record['name']}")
        if len(plain) > 10:
            lines.append(f"  ... and {len(plain) - 10} more")
        lines.append("")

    other = [record for record in records if record["kind"] == "other"]
    if other:
        lines.append("Other/unrecognized assemblies:")
        for record in other:
            lines.append(f"  {record['name']} head={record['head_hex']}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_csv(path: Path, records: list[dict[str, Any]]) -> None:
    fieldnames = [
        "name",
        "kind",
        "size",
        "header_size",
        "payload_size_field",
        "payload_size_from_file",
        "payload_size_matches_file",
        "raw_mz_offsets",
        "raw_valid_pe_offset",
        "raw_valid_pe_relative_offset",
        "payload_prefix_mz_hits",
        "payload_valid_pe_hits",
        "header_field_xor_mz_hits",
        "header_field_xor_valid_pe_hits",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            raw_valid_pe = record.get("raw_valid_pe") or {}
            writer.writerow(
                {
                    "name": record.get("name", ""),
                    "kind": record.get("kind", ""),
                    "size": record.get("size", 0),
                    "header_size": record.get("header_size", ""),
                    "payload_size_field": record.get("payload_size_field", ""),
                    "payload_size_from_file": record.get("payload_size_from_file", ""),
                    "payload_size_matches_file": record.get("payload_size_matches_file", ""),
                    "raw_mz_offsets": ",".join(str(value) for value in record.get("raw_mz_offsets", [])),
                    "raw_valid_pe_offset": raw_valid_pe.get("pe_offset", ""),
                    "raw_valid_pe_relative_offset": raw_valid_pe.get("pe_relative_offset", ""),
                    "payload_prefix_mz_hits": ",".join(record.get("payload_prefix_mz_hits", [])),
                    "payload_valid_pe_hits": ",".join(record.get("payload_valid_pe_hits", [])),
                    "header_field_xor_mz_hits": ",".join(record.get("header_field_xor_mz_hits", [])),
                    "header_field_xor_valid_pe_hits": ",".join(record.get("header_field_xor_valid_pe_hits", [])),
                }
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect Heartopia DotnetAssemblies .dll.bytes files, including XDENCODE0001-wrapped managed assemblies."
    )
    parser.add_argument("--game-root", type=Path, default=DEFAULT_GAME_ROOT)
    parser.add_argument("--assemblies-root", type=Path, help="Override the DotnetAssemblies directory.")
    parser.add_argument("--name", action="append", dest="names", help="Inspect only specific file names.")
    parser.add_argument("--json-out", type=Path, default=DEFAULT_JSON_OUT)
    parser.add_argument("--text-out", type=Path, default=DEFAULT_TEXT_OUT)
    parser.add_argument("--csv-out", type=Path, default=DEFAULT_CSV_OUT)
    args = parser.parse_args()

    assemblies_root = (args.assemblies_root or (args.game_root / DEFAULT_ASSEMBLY_DIR)).resolve()
    if not assemblies_root.is_dir():
        raise SystemExit(f"Missing DotnetAssemblies directory: {assemblies_root}")

    assembly_paths = iter_assemblies(assemblies_root, args.names)
    records = [inspect_assembly(path) for path in assembly_paths]
    payload = {
        "assemblies_root": str(assemblies_root),
        "xdencode_magic": XDENCODE_MAGIC.decode("ascii"),
        "xdencode_header_size": XDENCODE_HEADER_SIZE,
        "records": records,
    }

    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.text_out.parent.mkdir(parents=True, exist_ok=True)
    args.csv_out.parent.mkdir(parents=True, exist_ok=True)

    args.json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    args.text_out.write_text(render_text_report(assemblies_root, records), encoding="utf-8")
    write_csv(args.csv_out, records)

    kind_counts = Counter(record["kind"] for record in records)
    print(f"Scanned {len(records)} assemblies from {assemblies_root}")
    for kind, count in sorted(kind_counts.items()):
        print(f"  {kind}: {count}")
    print(f"Wrote {args.json_out}")
    print(f"Wrote {args.text_out}")
    print(f"Wrote {args.csv_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
