# Audio naming investigation notes

- `403211966` currently resolves only to `Mus_map.bnk`, so the extracted file remains `Mus_map_403211966.mp3`.
- `reports\heartopia_music_name_candidates.csv` does not provide a richer name for this ID.
- `xdt_Data\StreamingAssets\ResHotFixConfig.txt` and `GameFileInfo.json` list bank-style names such as `Mus_map.bnk`, `MusicBridge_daytime.bnk`, and `Musictheme_acousticBass.bnk`, but not a descriptive label for `Mus_map`.
- `Mus_map` appears in exactly one encrypted asset bundle: `xdt_Data\StreamingAssets\AssetBundle\5d0746fd3d7d_prefab.ab`.
- `xdt_Data\StreamingAssets\DotnetAssemblies\TypeRegister.dll.bytes` contains `MapSoundConfig` and `MapSoundDetail`, which likely point to a more detailed map-music lookup.
- The recovered Unity asset-bundle decrypt key is `27v8HxLIptguw3Jn`.
- Best next step: decrypt and parse the bundle(s) that reference `Mus_map`, then inspect data tied to `MapSoundConfig` / `MapSoundDetail` for human-readable map or area names.
