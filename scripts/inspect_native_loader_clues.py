from __future__ import annotations

import argparse
import json
import re
import struct
from pathlib import Path
from typing import Any

from heartopia_wwise import DEFAULT_GAME_ROOT


DEFAULT_METADATA = Path(r"xdt_Data\il2cpp_data\Metadata\global-metadata.dat")
DEFAULT_GAME_ASSEMBLY = Path("GameAssembly.dll")
DEFAULT_BUNDLE_REPORT = Path("reports/map_music_bundle_inspection.json")
DEFAULT_JSON_OUT = Path("reports/native_loader_clues.json")
DEFAULT_TEXT_OUT = Path("reports/native_loader_clues.txt")

DEFAULT_TEXT_TERMS = [
    "LoadSAFile",
    "LoadFileInternal",
    "CheckSAFileExists",
    "CheckPersistentFileExists",
    "SAFileExists",
    "InitKey",
    "SetupLookup",
    "ReInitResIndex",
    "EnsureResIndexLoaded",
    "SecureStorage",
    "GetKeyName",
    "GetDataCommand",
    "GetDecryptedData",
    "XDTSqlite",
    "AssetBundle",
    "isEncrypt",
    "SetAssetBundleKey",
    "SetAssetBundleDecryptKey",
    "encrypt",
    "decrypt",
    "sqlite",
    "AES",
    "SM4",
]

KNOWN_HEX_PATTERNS = {
    "aov_sm4_key": "0224dc74071b943625200ad6146205e3",
    "aov_sm4_iv": "797bcd5d7d7bb11143d00d713cdaa808",
}
MAX_XREF_HITS = 12


def read_printable_strings(data: bytes, min_len: int = 3) -> list[dict[str, Any]]:
    strings: list[dict[str, Any]] = []
    for match in re.finditer(rb"[ -~]{%d,}" % min_len, data):
        strings.append(
            {
                "offset": match.start(),
                "end": match.end(),
                "text": match.group().decode("ascii", "replace"),
            }
        )
    return strings


def find_all(data: bytes, needle: bytes) -> list[int]:
    hits: list[int] = []
    start = 0
    while True:
        index = data.find(needle, start)
        if index < 0:
            return hits
        hits.append(index)
        start = index + 1


def string_context(strings: list[dict[str, Any]], offset: int, radius: int = 5) -> list[dict[str, Any]]:
    if not strings:
        return []
    index = 0
    while index < len(strings) and strings[index]["offset"] <= offset:
        index += 1
    center = max(0, index - 1)
    start = max(0, center - radius)
    end = min(len(strings), center + radius + 1)
    return strings[start:end]


def cluster_hits(term_hits: list[dict[str, Any]], max_gap: int = 512) -> list[dict[str, Any]]:
    if not term_hits:
        return []
    ordered = sorted(term_hits, key=lambda item: item["offset"])
    clusters: list[dict[str, Any]] = []
    current = {
        "start": ordered[0]["offset"],
        "end": ordered[0]["offset"],
        "terms": [ordered[0]["term"]],
        "hits": [ordered[0]],
    }
    for hit in ordered[1:]:
        if hit["offset"] - current["end"] <= max_gap:
            current["end"] = hit["offset"]
            current["terms"].append(hit["term"])
            current["hits"].append(hit)
            continue
        clusters.append(current)
        current = {
            "start": hit["offset"],
            "end": hit["offset"],
            "terms": [hit["term"]],
            "hits": [hit],
        }
    clusters.append(current)
    for cluster in clusters:
        cluster["terms"] = sorted(set(cluster["terms"]))
    return clusters


def inspect_text_terms(data: bytes, strings: list[dict[str, Any]], terms: list[str]) -> dict[str, Any]:
    results: dict[str, Any] = {}
    clustered_hits: list[dict[str, Any]] = []
    for term in terms:
        ascii_hits = find_all(data, term.encode("ascii"))
        utf16_hits = find_all(data, term.encode("utf-16le"))
        term_result = {
            "ascii_hits": ascii_hits,
            "utf16_hits": utf16_hits,
        }
        if ascii_hits:
            term_result["context"] = string_context(strings, ascii_hits[0])
            clustered_hits.append({"term": term, "offset": ascii_hits[0], "encoding": "ascii"})
        elif utf16_hits:
            clustered_hits.append({"term": term, "offset": utf16_hits[0], "encoding": "utf16le"})
        results[term] = term_result
    return {
        "terms": results,
        "clusters": cluster_hits(clustered_hits),
    }


def load_bundle_report_patterns(report_path: Path) -> list[dict[str, Any]]:
    if not report_path.is_file():
        return []
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    patterns: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for bundle in payload.get("bundles", []):
        header = bundle.get("header") or {}
        bundle_name = Path(bundle.get("bundle_path", "")).name
        text_fields = {
            "configured_key": bundle.get("configured_key", ""),
            "recovered_key": bundle.get("recovered_key", ""),
            "key_sig_ascii": header.get("key_sig_ascii", ""),
        }
        for field_name, value in text_fields.items():
            value = value or ""
            if not value:
                continue
            key = ("ascii", value)
            if key in seen:
                continue
            seen.add(key)
            patterns.append({"kind": "ascii", "name": f"{bundle_name}:{field_name}", "value": value})

        hex_fields = {
            "data_hex": header.get("data_hex", ""),
            "key_hex": header.get("key_hex", ""),
            "data_sig_hex": header.get("data_sig_hex", ""),
            "key_sig_hex": header.get("key_sig_hex", ""),
        }
        for field_name, value in hex_fields.items():
            value = value or ""
            if not value:
                continue
            key = ("hex", value)
            if key in seen:
                continue
            seen.add(key)
            patterns.append({"kind": "hex", "name": f"{bundle_name}:{field_name}", "value": value})
    return patterns


def inspect_byte_patterns(data: bytes, patterns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for pattern in patterns:
        if pattern["kind"] == "ascii":
            needle = pattern["value"].encode("ascii", "replace")
        else:
            needle = bytes.fromhex(pattern["value"])
        hits = find_all(data, needle)
        results.append(
            {
                "name": pattern["name"],
                "kind": pattern["kind"],
                "value": pattern["value"],
                "hits": hits,
            }
        )
    return results


def parse_pe_image(data: bytes) -> dict[str, Any] | None:
    if data[:2] != b"MZ":
        return None
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return None

    number_of_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional_header_offset = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional_header_offset)[0]
    is_pe64 = magic == 0x20B
    image_base = (
        struct.unpack_from("<Q", data, optional_header_offset + 24)[0]
        if is_pe64
        else struct.unpack_from("<I", data, optional_header_offset + 28)[0]
    )
    data_directory_offset = optional_header_offset + (112 if is_pe64 else 96)
    import_rva, import_size = struct.unpack_from("<II", data, data_directory_offset + 8)

    sections: list[dict[str, Any]] = []
    section_table_offset = optional_header_offset + optional_header_size
    for index in range(number_of_sections):
        offset = section_table_offset + index * 40
        name = data[offset : offset + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", data, offset + 8)
        sections.append(
            {
                "name": name,
                "virtual_address": virtual_address,
                "virtual_size": virtual_size,
                "raw_pointer": raw_pointer,
                "raw_size": raw_size,
            }
        )
    return {
        "pe_offset": pe_offset,
        "is_pe64": is_pe64,
        "image_base": image_base,
        "import_rva": import_rva,
        "import_size": import_size,
        "sections": sections,
    }


def rva_to_file_offset(pe: dict[str, Any], rva: int) -> int | None:
    for section in pe["sections"]:
        size = max(section["virtual_size"], section["raw_size"])
        start = section["virtual_address"]
        if start <= rva < start + size:
            return section["raw_pointer"] + (rva - start)
    return None


def file_offset_to_rva(pe: dict[str, Any], file_offset: int) -> tuple[int | None, str | None]:
    for section in pe["sections"]:
        if section["raw_pointer"] <= file_offset < section["raw_pointer"] + section["raw_size"]:
            return section["virtual_address"] + (file_offset - section["raw_pointer"]), section["name"]
    return None, None


def read_c_string_at_rva(data: bytes, pe: dict[str, Any], rva: int) -> str | None:
    file_offset = rva_to_file_offset(pe, rva)
    if file_offset is None:
        return None
    end = data.find(b"\0", file_offset)
    if end < 0:
        return None
    return data[file_offset:end].decode("ascii", "replace")


def parse_imports(data: bytes, pe: dict[str, Any]) -> list[dict[str, Any]]:
    imports: list[dict[str, Any]] = []
    descriptor_offset = rva_to_file_offset(pe, pe["import_rva"])
    if descriptor_offset is None:
        return imports

    step = 8 if pe["is_pe64"] else 4
    while True:
        original_first_thunk, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", data, descriptor_offset)
        if original_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break

        dll_name = read_c_string_at_rva(data, pe, name_rva) or ""
        thunk_rva = original_first_thunk or first_thunk
        thunk_offset = rva_to_file_offset(pe, thunk_rva)
        functions: list[str] = []
        while thunk_offset is not None:
            entry = struct.unpack_from("<Q" if pe["is_pe64"] else "<I", data, thunk_offset)[0]
            if entry == 0:
                break
            if pe["is_pe64"] and (entry >> 63):
                functions.append(f"ordinal:{entry & 0xFFFF}")
            elif not pe["is_pe64"] and (entry >> 31):
                functions.append(f"ordinal:{entry & 0xFFFF}")
            else:
                name_offset = rva_to_file_offset(pe, entry)
                if name_offset is None:
                    break
                end = data.find(b"\0", name_offset + 2)
                functions.append(data[name_offset + 2 : end].decode("ascii", "replace"))
            thunk_offset += step

        imports.append({"dll": dll_name, "functions": functions})
        descriptor_offset += 20
    return imports


def scan_rip_relative_xrefs(data: bytes, pe: dict[str, Any], target_rva: int, limit: int = MAX_XREF_HITS) -> list[dict[str, Any]]:
    text_section = next((section for section in pe["sections"] if section["name"] == ".text"), None)
    if not text_section:
        return []
    text_offset = text_section["raw_pointer"]
    text_size = text_section["raw_size"]
    text_rva = text_section["virtual_address"]
    text_data = data[text_offset : text_offset + text_size]

    hits: list[dict[str, Any]] = []
    for index in range(len(text_data) - 7):
        rex = text_data[index]
        opcode = text_data[index + 1]
        modrm = text_data[index + 2]
        if rex not in range(0x48, 0x50):
            continue
        if opcode not in (0x8B, 0x8D):
            continue
        if (modrm & 0xC7) != 0x05:
            continue
        displacement = struct.unpack_from("<i", text_data, index + 3)[0]
        candidate_rva = text_rva + index + 7 + displacement
        if candidate_rva != target_rva:
            continue
        hits.append(
            {
                "instruction_rva": text_rva + index,
                "instruction_file_offset": text_offset + index,
                "opcode": opcode,
                "modrm": modrm,
            }
        )
        if len(hits) >= limit:
            break
    return hits


def find_pointer_slots(data: bytes, pe: dict[str, Any], target_va: int, limit: int = MAX_XREF_HITS) -> list[dict[str, Any]]:
    needle = struct.pack("<Q", target_va) if pe["is_pe64"] else struct.pack("<I", target_va & 0xFFFFFFFF)
    hits: list[dict[str, Any]] = []
    for section in pe["sections"]:
        if section["name"] == ".text":
            continue
        blob = data[section["raw_pointer"] : section["raw_pointer"] + section["raw_size"]]
        start = 0
        while len(hits) < limit:
            index = blob.find(needle, start)
            if index < 0:
                break
            file_offset = section["raw_pointer"] + index
            rva = section["virtual_address"] + index
            hits.append(
                {
                    "section": section["name"],
                    "file_offset": file_offset,
                    "rva": rva,
                    "xrefs": scan_rip_relative_xrefs(data, pe, rva, limit=limit),
                }
            )
            start = index + 1
    return hits


def inspect_game_assembly_xrefs(
    data: bytes,
    pe: dict[str, Any],
    term_results: dict[str, Any],
) -> list[dict[str, Any]]:
    xref_results: list[dict[str, Any]] = []
    for term, result in term_results.items():
        if not result["ascii_hits"]:
            continue
        file_offset = result["ascii_hits"][0]
        rva, section_name = file_offset_to_rva(pe, file_offset)
        if rva is None:
            continue
        va = pe["image_base"] + rva
        direct_xrefs = scan_rip_relative_xrefs(data, pe, rva)
        pointer_slots = find_pointer_slots(data, pe, va)
        xref_results.append(
            {
                "term": term,
                "file_offset": file_offset,
                "rva": rva,
                "va": va,
                "section": section_name,
                "direct_xrefs": direct_xrefs,
                "pointer_slots": pointer_slots,
            }
        )
    return xref_results


def inspect_file(path: Path, terms: list[str], byte_patterns: list[dict[str, Any]]) -> dict[str, Any]:
    data = path.read_bytes()
    strings = read_printable_strings(data)
    text_terms = inspect_text_terms(data, strings, terms)
    inspection = {
        "path": str(path),
        "size": len(data),
        "printable_string_count": len(strings),
        "text_terms": text_terms,
        "byte_patterns": inspect_byte_patterns(data, byte_patterns),
    }
    pe = parse_pe_image(data)
    if pe:
        inspection["pe"] = {
            "image_base": pe["image_base"],
            "is_pe64": pe["is_pe64"],
            "sections": pe["sections"],
            "imports": parse_imports(data, pe),
            "xrefs": inspect_game_assembly_xrefs(data, pe, text_terms["terms"]),
        }
    return inspection


def render_text_report(metadata_path: Path, game_assembly_path: Path, inspections: list[dict[str, Any]]) -> str:
    lines = [
        f"Metadata path: {metadata_path}",
        f"GameAssembly path: {game_assembly_path}",
        "",
    ]
    for inspection in inspections:
        lines.append(f"File: {inspection['path']}")
        lines.append(f"  Size: {inspection['size']}")
        lines.append(f"  Printable strings: {inspection['printable_string_count']}")
        clusters = inspection["text_terms"]["clusters"]
        if clusters:
            lines.append("  Term clusters:")
            for cluster in clusters:
                lines.append(
                    "    "
                    f"0x{cluster['start']:x}-0x{cluster['end']:x}: "
                    f"{', '.join(cluster['terms'])}"
                )
        else:
            lines.append("  Term clusters: none")

        term_lines = []
        for term, result in inspection["text_terms"]["terms"].items():
            ascii_hits = result["ascii_hits"]
            utf16_hits = result["utf16_hits"]
            if ascii_hits or utf16_hits:
                term_lines.append(
                    f"    {term}: ascii={ascii_hits[:3]} utf16={utf16_hits[:3]}"
                )
        if term_lines:
            lines.append("  Term hits:")
            lines.extend(term_lines)

        context_terms = [
            term
            for term, result in inspection["text_terms"]["terms"].items()
            if result.get("context")
        ]
        if context_terms:
            lines.append("  Context windows:")
            for term in context_terms[:4]:
                lines.append(f"    {term}:")
                for entry in inspection["text_terms"]["terms"][term]["context"]:
                    lines.append(f"      0x{entry['offset']:x}: {entry['text']}")

        pattern_hits = [entry for entry in inspection["byte_patterns"] if entry["hits"]]
        if pattern_hits:
            lines.append("  Byte-pattern hits:")
            for entry in pattern_hits:
                lines.append(
                    f"    {entry['name']}: {entry['kind']} hits at {entry['hits'][:5]}"
                )
        else:
            lines.append("  Byte-pattern hits: none")

        pe = inspection.get("pe")
        if pe:
            lines.append(f"  Image base: 0x{pe['image_base']:x}")
            lines.append("  Sections:")
            for section in pe["sections"]:
                lines.append(
                    "    "
                    f"{section['name']}: RVA=0x{section['virtual_address']:x} "
                    f"raw=0x{section['raw_pointer']:x} size=0x{section['raw_size']:x}"
                )
            lines.append("  Imports:")
            for entry in pe["imports"]:
                preview = ", ".join(entry["functions"][:8])
                suffix = " ..." if len(entry["functions"]) > 8 else ""
                lines.append(f"    {entry['dll']}: {preview}{suffix}")

            xref_hits = [
                entry
                for entry in pe["xrefs"]
                if entry["direct_xrefs"] or any(slot["xrefs"] for slot in entry["pointer_slots"])
            ]
            if xref_hits:
                lines.append("  Xref hits:")
                for entry in xref_hits[:8]:
                    lines.append(
                        "    "
                        f"{entry['term']}: {entry['section']} RVA=0x{entry['rva']:x}, "
                        f"direct={len(entry['direct_xrefs'])}, "
                        f"pointer_slots={len(entry['pointer_slots'])}"
                    )
                    for xref in entry["direct_xrefs"][:3]:
                        lines.append(
                            f"      direct .text RVA=0x{xref['instruction_rva']:x} opcode=0x{xref['opcode']:x}"
                        )
                    pointer_slots = [slot for slot in entry["pointer_slots"] if slot["xrefs"]]
                    for slot in pointer_slots[:2]:
                        lines.append(
                            f"      via {slot['section']} RVA=0x{slot['rva']:x} with {len(slot['xrefs'])} xrefs"
                        )
                        for xref in slot["xrefs"][:2]:
                            lines.append(
                                f"        .text RVA=0x{xref['instruction_rva']:x} opcode=0x{xref['opcode']:x}"
                            )
            else:
                lines.append("  Xref hits: none")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect GameAssembly.dll and IL2CPP metadata for Heartopia resource-loader and bundle-decrypt clues."
    )
    parser.add_argument("--game-root", type=Path, default=DEFAULT_GAME_ROOT)
    parser.add_argument("--metadata-path", type=Path, help="Override global-metadata.dat path.")
    parser.add_argument("--game-assembly-path", type=Path, help="Override GameAssembly.dll path.")
    parser.add_argument("--bundle-report", type=Path, default=DEFAULT_BUNDLE_REPORT)
    parser.add_argument("--json-out", type=Path, default=DEFAULT_JSON_OUT)
    parser.add_argument("--text-out", type=Path, default=DEFAULT_TEXT_OUT)
    args = parser.parse_args()

    metadata_path = (args.metadata_path or (args.game_root / DEFAULT_METADATA)).resolve()
    game_assembly_path = (args.game_assembly_path or (args.game_root / DEFAULT_GAME_ASSEMBLY)).resolve()
    if not metadata_path.is_file():
        raise SystemExit(f"Missing metadata file: {metadata_path}")
    if not game_assembly_path.is_file():
        raise SystemExit(f"Missing GameAssembly.dll: {game_assembly_path}")

    byte_patterns = [{"kind": "hex", "name": name, "value": value} for name, value in KNOWN_HEX_PATTERNS.items()]
    byte_patterns.extend(load_bundle_report_patterns(args.bundle_report.resolve()))

    inspections = [
        inspect_file(metadata_path, DEFAULT_TEXT_TERMS, byte_patterns),
        inspect_file(game_assembly_path, DEFAULT_TEXT_TERMS, byte_patterns),
    ]
    payload = {
        "metadata_path": str(metadata_path),
        "game_assembly_path": str(game_assembly_path),
        "bundle_report": str(args.bundle_report.resolve()) if args.bundle_report else "",
        "text_terms": DEFAULT_TEXT_TERMS,
        "byte_patterns": byte_patterns,
        "inspections": inspections,
    }

    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.text_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    args.text_out.write_text(render_text_report(metadata_path, game_assembly_path, inspections), encoding="utf-8")

    print(f"Wrote {args.json_out}")
    print(f"Wrote {args.text_out}")
    for inspection in inspections:
        term_hits = sum(
            1
            for result in inspection["text_terms"]["terms"].values()
            if result["ascii_hits"] or result["utf16_hits"]
        )
        pattern_hits = sum(1 for entry in inspection["byte_patterns"] if entry["hits"])
        print(
            f"{Path(inspection['path']).name}: "
            f"{term_hits} term hits, {len(inspection['text_terms']['clusters'])} clusters, {pattern_hits} byte patterns"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
