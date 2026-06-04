from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import UnityPy
from UnityPy.files.BundleFile import ArchiveFlags, ArchiveFlagsOld
from UnityPy.helpers import ArchiveStorageManager as asm
from UnityPy.helpers.CompressionHelper import DECOMPRESSION_MAP
from UnityPy.streams import EndianBinaryReader

from heartopia_wwise import DEFAULT_GAME_ROOT


DEFAULT_METADATA = Path(r"xdt_Data\il2cpp_data\Metadata\global-metadata.dat")
DEFAULT_BUNDLE_DIR = Path(r"xdt_Data\StreamingAssets\AssetBundle")
DEFAULT_BUNDLES = (
    "5d0746fd3d7d_prefab.ab",
    "27041feea928_mainlevelconfig_1.ab",
)
DEFAULT_JSON_OUT = Path("reports/map_music_bundle_inspection.json")
DEFAULT_TEXT_OUT = Path("reports/map_music_bundle_inspection.txt")


def parse_version_tuple(text: str) -> tuple[int, ...]:
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", text)
    if not match:
        return ()
    return tuple(int(part) for part in match.groups())


def archive_flag_enum(revision: str) -> type[ArchiveFlags] | type[ArchiveFlagsOld]:
    version = parse_version_tuple(revision)
    if (
        version < (2020,)
        or (version[:1] == (2020,) and version < (2020, 3, 34))
        or (version[:1] == (2021,) and version < (2021, 3, 2))
        or (version[:1] == (2022,) and version < (2022, 1, 1))
    ):
        return ArchiveFlagsOld
    return ArchiveFlags


def read_vector(reader: EndianBinaryReader) -> tuple[bytes, bytes]:
    data = reader.read_bytes(0x10)
    key = reader.read_bytes(0x10)
    reader.Position += 1
    return data, key


def read_bundle_header(bundle_path: Path) -> dict[str, Any]:
    reader = EndianBinaryReader(bundle_path.read_bytes())
    signature = reader.read_string_to_null()
    version = reader.read_u_int()
    unity_version = reader.read_string_to_null()
    revision = reader.read_string_to_null()
    bundle_size = reader.read_long()
    compressed_blocks_info_size = reader.read_u_int()
    uncompressed_blocks_info_size = reader.read_u_int()
    flags_value = reader.read_u_int()
    unknown_1 = reader.read_u_int()
    data, key = read_vector(reader)
    data_sig, key_sig = read_vector(reader)
    return {
        "signature": signature,
        "format_version": version,
        "unity_version": unity_version,
        "revision": revision,
        "bundle_size": bundle_size,
        "compressed_blocks_info_size": compressed_blocks_info_size,
        "uncompressed_blocks_info_size": uncompressed_blocks_info_size,
        "flags_value": flags_value,
        "unknown_1": unknown_1,
        "data_hex": data.hex(),
        "key_hex": key.hex(),
        "data_sig_hex": data_sig.hex(),
        "key_sig_hex": key_sig.hex(),
        "key_sig_ascii": key_sig.decode("utf-8", "replace"),
    }


def parse_bundle_layout(bundle_path: Path, key: str) -> dict[str, Any]:
    UnityPy.set_assetbundle_decrypt_key(key)
    reader = EndianBinaryReader(bundle_path.read_bytes())
    signature = reader.read_string_to_null()
    version = reader.read_u_int()
    unity_version = reader.read_string_to_null()
    revision = reader.read_string_to_null()
    bundle_size = reader.read_long()
    compressed_blocks_info_size = reader.read_u_int()
    uncompressed_blocks_info_size = reader.read_u_int()
    flag_enum = archive_flag_enum(revision)
    dataflags = flag_enum(reader.read_u_int())
    decryptor = asm.ArchiveStorageDecryptor(reader)

    revision_version = parse_version_tuple(revision)
    if version >= 7 or (revision_version[:1] == (2019,) and revision_version >= (2019, 4, 15)):
        reader.align_stream(16)

    blocks_info_start = reader.Position
    blocks_info_raw = reader.read_bytes(compressed_blocks_info_size)
    compression_flag = int(dataflags & ArchiveFlags.CompressionTypeMask)
    blocks_info = DECOMPRESSION_MAP[compression_flag](blocks_info_raw, uncompressed_blocks_info_size)

    blocks_reader = EndianBinaryReader(blocks_info, offset=blocks_info_start)
    uncompressed_data_hash = blocks_reader.read_bytes(16).hex()
    block_count = blocks_reader.read_int()
    blocks: list[dict[str, Any]] = []
    for _ in range(block_count):
        blocks.append(
            {
                "uncompressed_size": blocks_reader.read_u_int(),
                "compressed_size": blocks_reader.read_u_int(),
                "flags": blocks_reader.read_u_short(),
            }
        )

    node_count = blocks_reader.read_int()
    nodes: list[dict[str, Any]] = []
    for _ in range(node_count):
        nodes.append(
            {
                "offset": blocks_reader.read_long(),
                "size": blocks_reader.read_long(),
                "flags": blocks_reader.read_u_int(),
                "path": blocks_reader.read_string_to_null(),
            }
        )

    block_attempts = []
    success_count = 0
    for index, block in enumerate(blocks):
        raw = reader.read_bytes(block["compressed_size"])
        try:
            decrypted = decryptor.decrypt_block(raw, index)
            DECOMPRESSION_MAP[int(block["flags"] & ArchiveFlags.CompressionTypeMask)](
                decrypted,
                block["uncompressed_size"],
            )
            block_attempts.append({"index": index, "status": "ok"})
            success_count += 1
        except Exception as exc:  # pragma: no cover - diagnostics path
            block_attempts.append(
                {
                    "index": index,
                    "status": "error",
                    "error_type": exc.__class__.__name__,
                    "error": str(exc),
                }
            )

    try:
        env = UnityPy.load(str(bundle_path))
        unitypy_status = {
            "status": "ok",
            "files": len(env.files),
            "objects": len(env.objects),
            "container_count": len(env.container),
        }
    except Exception as exc:  # pragma: no cover - diagnostics path
        unitypy_status = {
            "status": "error",
            "error_type": exc.__class__.__name__,
            "error": str(exc).replace("\r", ""),
        }

    return {
        "signature": signature,
        "format_version": version,
        "unity_version": unity_version,
        "revision": revision,
        "bundle_size": bundle_size,
        "compressed_blocks_info_size": compressed_blocks_info_size,
        "uncompressed_blocks_info_size": uncompressed_blocks_info_size,
        "dataflags_value": int(dataflags),
        "blocks_info_compression_flag": compression_flag,
        "uncompressed_data_hash": uncompressed_data_hash,
        "block_count": block_count,
        "node_count": node_count,
        "blocks": blocks,
        "nodes": nodes,
        "manual_block_decompression": {
            "successful_blocks": success_count,
            "total_blocks": len(blocks),
            "attempts": block_attempts,
        },
        "unitypy_load": unitypy_status,
    }


def inspect_bundle(bundle_path: Path, metadata_path: Path, configured_key: str | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "bundle_path": str(bundle_path),
        "exists": bundle_path.exists(),
        "header": {},
        "recovered_key": "",
        "configured_key": configured_key or "",
        "key_matches": False,
        "parse": None,
    }
    if not bundle_path.exists():
        return result

    header = read_bundle_header(bundle_path)
    brute_forced_key = asm.brute_force_key(
        str(metadata_path),
        bytes.fromhex(header["key_sig_hex"]),
        bytes.fromhex(header["data_sig_hex"]),
    )
    recovered_key = brute_forced_key.decode("utf-8", "replace") if brute_forced_key else ""
    key_to_use = configured_key or recovered_key

    result["header"] = header
    result["recovered_key"] = recovered_key
    result["key_matches"] = bool(recovered_key and configured_key and recovered_key == configured_key)
    if not key_to_use:
        result["parse"] = {"status": "error", "error": "No bundle key available"}
        return result

    try:
        result["parse"] = {"status": "ok", **parse_bundle_layout(bundle_path, key_to_use)}
    except Exception as exc:  # pragma: no cover - diagnostics path
        result["parse"] = {
            "status": "error",
            "error_type": exc.__class__.__name__,
            "error": str(exc).replace("\r", ""),
        }
    return result


def render_text_report(metadata_path: Path, inspections: list[dict[str, Any]]) -> str:
    lines = [f"Metadata path: {metadata_path}", ""]
    for item in inspections:
        lines.append(f"Bundle: {item['bundle_path']}")
        lines.append(f"  Exists: {item['exists']}")
        lines.append(f"  Recovered key: {item.get('recovered_key', '')}")
        configured_key = item.get("configured_key", "")
        if configured_key:
            lines.append(f"  Configured key: {configured_key}")
            lines.append(f"  Key matches recovered: {item.get('key_matches', False)}")
        header = item.get("header", {})
        if header:
            lines.append(
                "  Header: "
                f"{header.get('signature', '')} v{header.get('format_version', '')} "
                f"{header.get('revision', '')}"
            )
            lines.append(
                "  Blocks info: "
                f"{header.get('compressed_blocks_info_size', 0)} compressed / "
                f"{header.get('uncompressed_blocks_info_size', 0)} uncompressed bytes"
            )
        parse = item.get("parse") or {}
        lines.append(f"  Parse status: {parse.get('status', 'unknown')}")
        if parse.get("status") == "ok":
            lines.append(
                f"  Layout: {parse['block_count']} blocks, {parse['node_count']} nodes, "
                f"{parse['manual_block_decompression']['successful_blocks']} manually decompressed blocks"
            )
            for node in parse["nodes"][:5]:
                lines.append(f"    Node: {node['path']} (size={node['size']}, flags={node['flags']})")
            unitypy_load = parse["unitypy_load"]
            if unitypy_load["status"] == "ok":
                lines.append(
                    f"  UnityPy load: ok ({unitypy_load['files']} files, {unitypy_load['objects']} objects)"
                )
            else:
                lines.append(
                    f"  UnityPy load: {unitypy_load['error_type']}: {unitypy_load['error'].splitlines()[0]}"
                )
            failed = [attempt for attempt in parse["manual_block_decompression"]["attempts"] if attempt["status"] != "ok"]
            if failed:
                first = failed[0]
                lines.append(
                    f"  First block failure: block {first['index']} {first['error_type']}: {first['error']}"
                )
        else:
            lines.append(f"  Error: {parse.get('error_type', '')}: {parse.get('error', '')}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect Heartopia encrypted bundles that likely hold map-music metadata.")
    parser.add_argument("--game-root", type=Path, default=DEFAULT_GAME_ROOT)
    parser.add_argument("--metadata-path", type=Path, help="Override global-metadata.dat path.")
    parser.add_argument("--bundle", action="append", dest="bundles", help="Specific bundle path to inspect.")
    parser.add_argument("--key", help="Known 16-byte Unity asset-bundle decryption key.")
    parser.add_argument("--json-out", type=Path, default=DEFAULT_JSON_OUT)
    parser.add_argument("--text-out", type=Path, default=DEFAULT_TEXT_OUT)
    args = parser.parse_args()

    metadata_path = (args.metadata_path or (args.game_root / DEFAULT_METADATA)).resolve()
    if not metadata_path.is_file():
        raise SystemExit(f"Missing metadata file: {metadata_path}")

    if args.bundles:
        bundle_paths = [Path(bundle).resolve() for bundle in args.bundles]
    else:
        bundle_dir = (args.game_root / DEFAULT_BUNDLE_DIR).resolve()
        bundle_paths = [bundle_dir / name for name in DEFAULT_BUNDLES]

    inspections = [inspect_bundle(bundle_path, metadata_path, args.key) for bundle_path in bundle_paths]
    payload = {
        "metadata_path": str(metadata_path),
        "bundles": inspections,
    }

    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.text_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    args.text_out.write_text(render_text_report(metadata_path, inspections), encoding="utf-8")

    print(f"Wrote {args.json_out}")
    print(f"Wrote {args.text_out}")
    for item in inspections:
        parse = item.get("parse") or {}
        summary = parse.get("status", "unknown")
        if summary == "ok":
            summary = (
                f"ok, {parse['block_count']} blocks, {parse['node_count']} nodes, "
                f"{parse['manual_block_decompression']['successful_blocks']} block payloads decompressed"
            )
        print(f"{Path(item['bundle_path']).name}: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
