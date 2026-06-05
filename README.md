# heartopia_assets_extract

Python scripts for evaluating and extracting Heartopia audio assets, adapted from the Sword of Convallaria extraction workflow.

## Included

- `scripts\inventory_assets.py`
- `scripts\extract_embedded_wems.py`
- `scripts\name_unnamed_music_from_banks.py`
- `scripts\analyze_unnamed_audio.py`
- `scripts\export_named_music.py`
- `scripts\inspect_map_music_bundle.py`
- `scripts\inspect_native_loader_clues.py`
- `scripts\inspect_wrapped_assemblies.py`
- `scripts\heartopia_wwise.py`
- `NOTES.md`

## Not committed

This repo intentionally excludes generated artifacts and bulky local dependencies:

- `extracted\`
- `reports\`
- `tools\`

## Setup

1. Install Python dependencies:
   - `pip install -r requirements.txt`
2. Install `ffmpeg` and make it available on `PATH`.
3. Download `vgmstream-cli.exe` and place it at:
   - `tools\vgmstream\vgmstream-cli.exe`

## Default game path

The scripts currently default to:

`C:\Program Files (x86)\Steam\steamapps\common\Heartopia`

## Typical flow

1. Inventory audio:
   - `python .\scripts\inventory_assets.py`
2. Extract embedded WEMs:
   - `python .\scripts\extract_embedded_wems.py`
3. Build naming candidates:
   - `python .\scripts\name_unnamed_music_from_banks.py`
4. Analyze candidates:
   - `python .\scripts\analyze_unnamed_audio.py`
5. Inspect encrypted map-music metadata bundles when bank names are too generic:
   - `python .\scripts\inspect_map_music_bundle.py --key 27v8HxLIptguw3Jn`
6. Inspect native loader clues in `GameAssembly.dll` and `global-metadata.dat`:
   - `python .\scripts\inspect_native_loader_clues.py`
7. Inspect wrapped managed assemblies when the next lead is Unity-side resource decryption:
   - `python .\scripts\inspect_wrapped_assemblies.py`
8. Export playable files:
   - `python .\scripts\export_named_music.py --overwrite`
