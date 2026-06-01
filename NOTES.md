# Heartopia audio extraction notes

## Goal

Extract Heartopia audio assets, especially music, from:

`C:\Program Files (x86)\Steam\steamapps\common\Heartopia`

Follow the same general patterns, Python scripts, and tools as the working Sword repo:

`E:\dev\sword_assets_extract`

This repo is the Heartopia-adapted evaluation/extraction workspace:

`E:\dev\heartopia_asset_extract`

## High-level findings

- Heartopia stores audio in **Wwise** banks and WEM files.
- The main audio root is:
  `C:\Program Files (x86)\Steam\steamapps\common\Heartopia\xdt_Data\StreamingAssets\Audio\GeneratedSoundBanks\Windows`
- Heartopia uses plain formats in the samples checked:
  - `.bnk` files start with `BKHD`
  - `.wem` files start with `RIFF/WAVE`
- The Sword repo's XOR/decoding support was preserved in helpers where useful, but Heartopia does **not** appear to require XOR decoding for the assets examined.
- A large amount of the useful music is **embedded inside `.bnk` DATA chunks**, not only present as loose `.wem` files.

## Inventory results

First-pass inventory of the Wwise audio root found:

- **2901** `.bnk` files
- **328** loose `.wem` files
- **5451** embedded DIDX WEM entries across banks
- **3229** total files under the audio root

## Naming / metadata findings

- No usable shipped Wwise naming manifest was found during evaluation.
- Specifically, no `SoundBanksInfo.xml`, `SoundBanksInfo.json`, or equivalent event-name export was confirmed in the install.
- Because of that, the practical human-readable naming strategy is:
  1. Use the **bank filename**
  2. Map bank contents to **media IDs**
  3. Use extracted or loose WEM paths as the concrete source files
- Bank filenames are often already human-readable and useful for music labeling.

Examples of music-like bank naming patterns seen in Heartopia:

- `Musictheme_*`
- `MusicBridge_*`
- `Mus_map`
- `Mus_ui`
- `timeline2d...mus`
- `Amb_general`

## Important heuristic note

Broad keyword heuristics such as `loop`, `homeland`, and similar terms were **not** treated as strong signals by themselves, because they matched too many SFX/non-music banks.

More reliable music-focused bank categories were derived from filename patterns instead.

## Main storage/layout conclusion

Heartopia differs from a naive loose-file workflow in an important way:

- loose `.wem` files exist, but they are only part of the picture
- much of the music-like content must be recovered from `.bnk` `DIDX` + `DATA` chunks

That is why a new embedded extractor was added rather than only reusing Sword's existing loose-file flow.

## Work completed

- Investigated Heartopia's install layout and audio storage.
- Compared Heartopia with the working Sword extraction repo.
- Confirmed Heartopia uses plain Wwise banks and WEM files.
- Confirmed the naming problem is mostly a **bank filename / media ID** problem, not an external metadata import problem.
- Copied and adapted the relevant Sword-style scripts and tools into this repo.
- Added a new embedded-WEM extractor for `.bnk` `DIDX` / `DATA` chunks.
- Ran a first-pass evaluation pipeline and generated reports.

## Scripts in this repo

### `scripts\heartopia_wwise.py`

Shared Heartopia/Wwise helper module. It centralizes:

- default Heartopia paths
- optional XOR decode helpers
- RIFF/BKHD decoding helpers
- Wwise chunk parsing
- DIDX parsing
- DATA chunk extraction
- HIRC media-id scanning
- bank classification
- title sanitization / title choice helpers

### `scripts\extract_embedded_wems.py`

New script added for Heartopia.

Purpose:

- parse `.bnk` files
- read `DIDX` and `DATA`
- extract embedded `.wem` files

Default behavior:

- extracts from music-related banks only

Output path pattern:

`extracted\embedded_wems\<bank_name>\<bank_name>__<media_id>.wem`

It also supports widening scope with `--all-banks`.

### `scripts\inventory_assets.py`

Adapted from the Sword repo's asset inventory flow.

Now it inventories the Heartopia Wwise audio root and records:

- file type / header classification
- bank category
- embedded WEM count per bank

### `scripts\name_unnamed_music_from_banks.py`

Main first-pass naming report generator.

Adapted away from the Sword repo's Unity text-asset event-name JSON dependency.

Now it builds a candidate report using:

- bank filenames
- media IDs
- extracted/loose source paths
- basic bank-category confidence rules

Output:

`reports\heartopia_music_name_candidates.csv`

### `scripts\analyze_unnamed_audio.py`

Adapted to analyze Heartopia candidate audio using:

- `tools\vgmstream\vgmstream-cli.exe`

It reads the Heartopia candidate report and classifies tracks using basic properties such as:

- duration
- channel count
- music/ambience/stinger-like behavior

### `scripts\export_named_music.py`

Adapted for Heartopia's report format and source paths.

It was updated for later use in exporting named Heartopia tracks, but it was **not** run yet during this evaluation pass.

## Reports generated

- `reports\asset_manifest.csv`
- `reports\summary.txt`
- `reports\embedded_wem_manifest.csv`
- `reports\embedded_wem_summary.txt`
- `reports\heartopia_music_name_candidates.csv`
- `reports\heartopia_music_name_strategy_notes.txt`
- `reports\heartopia_music_analysis.csv`
- `reports\heartopia_music_analysis_summary.txt`

## Report highlights

### `reports\embedded_wem_summary.txt`

Embedded extraction recovered **628** WEMs from music-related banks.

Notable categories included:

- `general_ambience`
- `music_named_bank`
- `timeline_music`
- `instrument_theme_music`
- `map_music`
- `bridge_music`
- `ui_music`

### `reports\heartopia_music_name_strategy_notes.txt`

Candidate naming pass summary:

- **681** candidate rows
- **52** `high` confidence
- **629** `medium` confidence
- **628** `embedded`
- **52** `loose`
- **1** `embedded_and_loose`

Confidence model used:

- `high`: strong music bank types with an actual source file
- `medium`: weaker/general ambience or bank-reference-driven cases
- `low`: poor/noisy matches

### `reports\heartopia_music_analysis_summary.txt`

First-pass audio classification summary:

- **284** `likely_sfx_or_stinger`
- **187** `possibly_music_ambience_or_long_sfx`
- **126** `likely_music_or_ambience`
- **79** `likely_ambience_loop`
- **5** `unknown`

## Interpretation of the results

- Many clearly named `Musictheme_*` banks are useful for labeling, but a lot of their contents look like short cues, instrument phrases, or stingers rather than full-length background music.
- Some of the longest and strongest continuous music/ambience candidates appear in more generic banks such as:
  - `Mus_map`
  - `Amb_general`
- This means "human-readable bank name" and "full song/BGM" are related but not identical.

## Current practical conclusion

The adapted Sword-style workflow is working for Heartopia, with one major Heartopia-specific addition:

- **embedded WEM extraction from `.bnk` files is necessary**

The current best source of human-readable naming is:

- **bank filename**

The current best source of actual audio for evaluation/export is:

- **loose `.wem` files plus extracted embedded `.wem` files**

## Current state of the repo

- Evaluation tooling is working.
- Embedded WEM extraction is working.
- Human-readable candidate naming is working at a first-pass level.
- vgmstream-based analysis is working.
- Export to MP3 was adapted but has not yet been run in this pass.

## Remaining unresolved point

The main unfinished task is **final curation**:

- separate true full-length music/BGM from:
  - ambience loops
  - short stingers
  - non-music long-form audio

This likely needs an additional refinement pass over the longest candidates and possibly tighter title/category heuristics.

## Suggested next steps

1. Review the longest analyzed tracks in `reports\heartopia_music_analysis.csv`.
2. Build a conservative shortlist of likely real music/BGM tracks.
3. If desired, run `scripts\export_named_music.py` on the curated shortlist.
4. Optionally investigate whether more metadata exists outside the obvious Wwise audio root, such as in asset bundles or patch resources, if higher-fidelity naming is required.
