# Audio naming investigation notes

## Goal

Get human-readable names for extracted Heartopia songs, especially the many long `Mus_map` tracks that currently only inherit the generic bank name.

## Current progress

- The Wwise-side pipeline is working:
  - embedded WEM extraction works
  - bank/media-id candidate naming works
  - vgmstream analysis works
- The current blocker is no longer on the Wwise side.
- The remaining name gap is now clearly in Heartopia's encrypted Unity asset/resource path.

## Confirmed findings

- `403211966` currently resolves only to `Mus_map.bnk`, so the extracted file remains `Mus_map_403211966.mp3`.
- `reports\heartopia_music_name_candidates.csv` does not provide a richer name for this ID.
- `xdt_Data\StreamingAssets\ResHotFixConfig.txt` and `GameFileInfo.json` list bank-style names such as `Mus_map.bnk`, `MusicBridge_daytime.bnk`, and `Musictheme_acousticBass.bnk`, but not a descriptive label for `Mus_map`.
- The strongest current metadata targets are:
  - `xdt_Data\StreamingAssets\AssetBundle\5d0746fd3d7d_prefab.ab`
  - `xdt_Data\StreamingAssets\AssetBundle\27041feea928_mainlevelconfig_1.ab`
- Both target bundles are encrypted `UnityFS` bundles with revision `2020.3.13f1XD1.1.971b`.
- The recovered Unity asset-bundle decrypt key is `27v8HxLIptguw3Jn`.
- The recovered key is confirmed by UnityPy's `brute_force_key(...)` against `global-metadata.dat`, so the current blocker is not key discovery.
- `scripts\inspect_map_music_bundle.py` now records the key check, block table, node list, and the current block-decompression failure for the target bundles.

## Bundle inspection results

### `5d0746fd3d7d_prefab.ab`

- key verification succeeds
- block table parses successfully
- layout:
  - 4 blocks
  - 2 nodes
  - `CAB-8dba97ded821a06f424575e59539abae`
  - `CAB-8dba97ded821a06f424575e59539abae.resS`
- block flags are `0x103`
- both UnityPy load and manual block decrypt+LZ4 decompress fail with `LZ4BlockError`

### `27041feea928_mainlevelconfig_1.ab`

- key verification succeeds
- block table parses successfully
- layout:
  - 62 blocks
  - 1 node
  - `CAB-206b448388861fd0eb6e7489f7ac669c`
- block flags are also `0x103`
- both UnityPy load and manual block decrypt+LZ4 decompress fail with `LZ4BlockError`
- this is currently the stronger target because `mainlevelconfig` is a better fit for `MapSoundConfig` / `MapSoundDetail` instance data

## Important interpretation

- The bundle password is valid.
- The failure point is after key acceptance, during payload block decode.
- That means the current problem is specifically:
  - Heartopia/Unity-CN encrypted bundle payload decode
  - not "find the password"

## New lead: wrapped managed assemblies

- Most files in `xdt_Data\StreamingAssets\DotnetAssemblies\*.dll.bytes` are not plain PE files.
- They begin with a custom wrapper header:
  - `XDENCODE0001`
- `TypeRegister.dll.bytes` is the notable exception:
  - it is plain/loadable
  - it contains `TypeRegister.ModuleEntry`
  - `ModuleInit()` is a large type-registration loop
- `TypeRegister.ModuleInit()` references wrapped assemblies including:
  - `EngineWrapper`
  - `ScriptBridge`
  - `MonoUniTask`
  - `XDTLevelAndEntity`
  - `XDTGameUI`
  - `XDKWPerf`
  - `MsgPackFormatters`
  - `XDTBaseService`
  - `EcsClient`

## `XDENCODE0001` wrapper findings

- Wrapped assemblies are not directly loadable with reflection (`Bad IL format`).
- The first 4 bytes after `XDENCODE0001` match:
  - wrapped file size minus `298`
- This strongly suggests:
  - a fixed `298`-byte wrapper header
  - followed by a transformed payload
- After offset `298`, the payload still does not look like a valid PE file.
- A later `MZ` appears inside the wrapped blob, but it does not line up to a valid `PE` header in-place, so this is not just a simple prefix.
- Simple transforms tried so far did **not** recover a PE header:
  - raw LZ4 on bundle payload blocks
  - UnityPy-style decrypted LZ4 on bundle payload blocks
  - short-period XOR/add/sub guesses on wrapped assembly payload bytes
  - simple byte-stride extraction guesses

## Loader / decryption-related metadata clues

IL2CPP metadata contains a promising resource-loader cluster with strings such as:

- `InitLoad`
- `GetLoadableFilePath`
- `Initialize_BSA`
- `LoadSAFile`
- `InitKey`
- `SetupLookup`
- `_ResKeyToPathAndBundlePath`
- `SecureStorage`
- `GetDecryptedData`
- `cachedABDeps`

It also contains Unity-China asset-bundle APIs:

- `AssetBundle.isEncrypt`
- `AssetBundle.SetAssetBundleKey`
- `AssetBundle.SetAssetBundleDecryptKey`

Public Unity source confirms `SetAssetBundleDecryptKey(string password)`, but that still does not explain the post-key payload decode failure.

## Best guesses on what to investigate next

### 1. Decode the `XDENCODE0001` wrapper first

This is currently the highest-leverage lead.

Why:

- if the wrapped assemblies can be restored to normal PE DLLs, they can likely be decompiled
- that may expose:
  - the exact `LoadSAFile` / `GetDecryptedData` logic
  - the `InitKey` path
  - any game-specific bundle/block transform
- this is probably easier than blind native IL2CPP reversing

Concrete angles:

- inspect the fixed `298`-byte header as a structured container
- compare many wrapped assemblies to infer which bytes are:
  - payload length
  - table offsets
  - keys / seeds
  - transform tables
- test whether the wrapper is:
  - chunked
  - nibble-swizzled
  - word-reordered
  - substitution-table based
  - per-byte add/sub/xor using header-derived state

### 2. Focus on the game's `LoadSAFile` / `GetDecryptedData` path

Why:

- the IL2CPP metadata cluster strongly suggests a custom secure resource loader
- the names `InitKey`, `SecureStorage`, and `GetDecryptedData` look directly relevant to both wrapped DLLs and encrypted bundles

Concrete angles:

- identify the owning type/class for the `LoadSAFile` cluster
- look for that class in any decoded managed assembly if `XDENCODE` is cracked
- otherwise inspect `GameAssembly.dll` / IL2CPP metadata around the same subsystem names

### 3. Treat `mainlevelconfig_1.ab` as the primary bundle target

Why:

- it is more likely than the prefab bundle to contain concrete `MapSoundConfig` / `MapSoundDetail` data
- once the correct payload decode path is known, this is the bundle most likely to yield:
  - map IDs
  - area names
  - music assignments
  - or direct references that can be mapped back to `Mus_map` media IDs

### 4. Keep the current bundle key, but do not spend more time re-proving it

Why:

- the key is already confirmed by:
  - UnityPy brute-force against `global-metadata.dat`
  - successful encrypted bundle header/block-table parsing
- further work should assume the password is correct and focus on:
  - additional transform
  - loader-specific setup
  - wrapper/resource decode logic

## Practical next command already added

Use this to regenerate the current bundle diagnostics:

- `python .\scripts\inspect_map_music_bundle.py --key 27v8HxLIptguw3Jn`

## Current best summary

- `Mus_map` naming is blocked by encrypted Unity-side metadata, not by Wwise extraction anymore.
- The bundle password is known and verified.
- The next real breakthrough will likely come from either:
  1. cracking `XDENCODE0001` for wrapped managed assemblies, or
  2. recovering the exact `LoadSAFile` / `GetDecryptedData` logic that explains the post-password bundle payload transform.
