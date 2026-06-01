from __future__ import annotations

import re
from pathlib import Path


DEFAULT_GAME_ROOT = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Heartopia")
KEY = b"XD_Audio"

_BANK_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^Musictheme_", re.IGNORECASE), "instrument_theme_music"),
    (re.compile(r"^MusicBridge_", re.IGNORECASE), "bridge_music"),
    (re.compile(r"^Mus_map$", re.IGNORECASE), "map_music"),
    (re.compile(r"^Mus_ui$", re.IGNORECASE), "ui_music"),
    (re.compile(r"^timeline2d.*mus", re.IGNORECASE), "timeline_music"),
    (re.compile(r"^Amb_general$", re.IGNORECASE), "general_ambience"),
    (re.compile(r"music", re.IGNORECASE), "music_named_bank"),
]


def default_bank_root(game_root: Path | None = None) -> Path:
    root = (game_root or DEFAULT_GAME_ROOT).resolve()
    return root / "xdt_Data" / "StreamingAssets" / "Audio" / "GeneratedSoundBanks" / "Windows"


def xor_data(data: bytes) -> bytes:
    return bytes(byte ^ KEY[index % len(KEY)] for index, byte in enumerate(data))


def decode_bank_if_needed(data: bytes) -> bytes:
    if data.startswith(b"BKHD"):
        return data
    decoded = xor_data(data)
    return decoded if decoded.startswith(b"BKHD") else data


def decode_wem_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if data.startswith(b"RIFF"):
        return data
    decoded = xor_data(data)
    return decoded if decoded.startswith(b"RIFF") else data


def chunks(data: bytes):
    offset = 0
    while offset + 8 <= len(data):
        tag = data[offset : offset + 4]
        size = int.from_bytes(data[offset + 4 : offset + 8], "little")
        start = offset + 8
        end = start + size
        if size < 0 or end > len(data):
            break
        yield tag, data[start:end]
        offset = end


def didx_entries(bank: bytes) -> list[tuple[int, int, int]]:
    entries: list[tuple[int, int, int]] = []
    for tag, payload in chunks(bank):
        if tag != b"DIDX":
            continue
        for offset in range(0, len(payload) - 11, 12):
            media_id = int.from_bytes(payload[offset : offset + 4], "little")
            data_offset = int.from_bytes(payload[offset + 4 : offset + 8], "little")
            size = int.from_bytes(payload[offset + 8 : offset + 12], "little")
            entries.append((media_id, data_offset, size))
    return entries


def didx_media_ids(bank: bytes) -> set[int]:
    return {media_id for media_id, _, _ in didx_entries(bank)}


def data_chunk(bank: bytes) -> bytes:
    for tag, payload in chunks(bank):
        if tag == b"DATA":
            return payload
    return b""


def hirc_media_ids(bank: bytes, known_media_ids: set[int]) -> set[int]:
    ids: set[int] = set()
    for tag, payload in chunks(bank):
        if tag != b"HIRC" or len(payload) < 4:
            continue
        count = int.from_bytes(payload[:4], "little")
        pos = 4
        for _ in range(count):
            if pos + 9 > len(payload):
                break
            size = int.from_bytes(payload[pos + 1 : pos + 5], "little")
            obj_start = pos + 5
            obj_end = obj_start + size
            if obj_end > len(payload) or size < 4:
                break
            obj_data = payload[obj_start:obj_end]
            for offset in range(0, len(obj_data) - 3):
                value = int.from_bytes(obj_data[offset : offset + 4], "little")
                if value in known_media_ids:
                    ids.add(value)
            pos = obj_end
    return ids


def relative_posix(path: Path, root: Path) -> str:
    return str(path.relative_to(root)).replace("\\", "/")


def sanitize(text: str) -> str:
    text = text.strip()
    text = re.sub(r"\.(bnk|wem)$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"[^A-Za-z0-9]+", "_", text)
    return re.sub(r"_+", "_", text).strip("_")


def classify_bank(bank_name: str) -> str:
    stem = Path(bank_name).stem
    for pattern, label in _BANK_RULES:
        if pattern.search(stem):
            return label
    return "non_music_bank"


def is_music_bank(bank_name: str, include_ambience: bool = True) -> bool:
    category = classify_bank(bank_name)
    if category == "general_ambience":
        return include_ambience
    return category != "non_music_bank"


def choose_title(bank_names: list[str]) -> str:
    titles = [sanitize(Path(name).stem) for name in bank_names if name]
    unique = sorted(set(title for title in titles if title))
    if not unique:
        return ""
    preferred = [
        title
        for title in unique
        if not re.fullmatch(r"(Mus_map|Amb_general|Music|mus_ui)", title, flags=re.IGNORECASE)
    ]
    if preferred:
        unique = preferred
    if len(unique) == 1:
        return unique[0]
    unique.sort(key=lambda item: (item.lower().startswith("amb_"), len(item), item))
    return "__".join(unique[:4]) + ("__multiple" if len(unique) > 4 else "")
