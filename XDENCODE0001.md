# XDENCODE0001 notes

## What it is

`XDENCODE0001` appears to be Heartopia's custom protection wrapper for selected `.dll.bytes` managed assemblies.

The goal of decoding it is:

```text
XDENCODE0001-wrapped .dll.bytes
-> normal MZ/PE .NET DLL
-> decompile with dnSpy/ILSpy
```

## Confirmed observations

- 15 of 100 files under `xdt_Data\StreamingAssets\DotnetAssemblies\*.dll.bytes` use this wrapper.
- The other 85 files are normal PE/.NET DLLs starting with `MZ`.
- Wrapped files start with ASCII magic `XDENCODE0001`.
- Every wrapped file has a consistent 298-byte header.
- The first little-endian `u32` after `XDENCODE0001` equals `file_size - 298` for all 15 wrapped files, so it is almost certainly the wrapped payload size.
- The payload after byte 298 is not directly a valid PE DLL.
- Some wrapped payloads contain raw `MZ` byte sequences later in the file, but none resolve to a valid `PE\0\0` header in place.
- Simple transforms tested so far did not recover a valid DLL:
  - single-byte XOR
  - add/sub
  - nibble swap
  - bit rotations
  - repeating XOR using obvious header fields

Likely high-level layout:

```text
XDENCODE0001
[fixed 286-byte metadata/header area]
[encoded/transformed DLL payload]
```

The header contains fields that look structured rather than random. The current inspection found consistent deltas relative to payload size:

```text
field[0] = payload_size
field[3] = payload_size + 4
field[4] = payload_size + 6
field[6] = payload_size + 188
field[7] = payload_size + 5
field[8] = payload_size + 70
field[9] = payload_size + 7
```

This suggests the header likely stores sizes, offsets, loader parameters, checksums, chunk metadata, or transform seeds.

## Why it matters

The wrapped assemblies include high-value game code:

- `EngineWrapper.dll.bytes`
- `ScriptBridge.dll.bytes`
- `XDTLevelAndEntity.dll.bytes`
- `XDTGameUI.dll.bytes`
- `XDTBaseService.dll.bytes`
- `EcsClient.dll.bytes`

These are likely to contain or reference resource loading, map config, entity placement, and asset-bundle decode logic. Decoding `XDENCODE0001` is probably the best route to understanding Heartopia's protected Unity assets.

## What decoding would require

Decrypting or decoding `XDENCODE0001` means recovering the game's runtime unpacking logic. The game must have code that reads these files, transforms the payload back into loadable assembly bytes, and then loads/registers the assembly.

Likely places to find the loader:

- `GameAssembly.dll`
- `TypeRegister.dll.bytes`
- plain `.dll.bytes` assemblies
- Unity player/native plugins

Useful strings and concepts already seen elsewhere in the game metadata:

```text
LoadSAFile
GetDecryptedData
SecureStorage
InitKey
TypeRegister.ModuleInit
DotnetAssemblies
XDENCODE0001
```

If the literal string `XDENCODE0001` appears in `GameAssembly.dll` or a plain managed assembly, the fastest path is to follow xrefs to the decode routine.

## Usual workflow for this kind of wrapper

1. Find the loader.
   - Search native and managed code for `XDENCODE0001`, `DotnetAssemblies`, file-read paths, and assembly-load calls.
   - In native code, use Ghidra/IDA/x64dbg to follow string references and buffer transforms.

2. Understand the wrapper format.
   - Compare all 15 headers byte-for-byte.
   - Identify fields for payload size, offsets, constants, per-file seeds, checksums, IVs, or chunk tables.

3. Identify the transform.
   - Common schemes include generated XOR streams, AES/XXTEA/TEA/SM4, compression plus encryption, chunk reordering, byte permutation, or table-driven transforms.
   - The failed simple probes mean this is probably not a trivial fixed single-byte transform.

4. Reimplement the decode.
   - Read the wrapped file.
   - Validate `XDENCODE0001`.
   - Parse the 298-byte header.
   - Decode the payload.
   - Write the restored `.dll`.
   - Verify it starts with `MZ` and has a valid `PE\0\0` header.

5. Validate across multiple wrapped files.
   - A real solution should decode more than one assembly.
   - A one-file decode may be coincidental or missing per-file metadata.

## Practical attack routes

- Static reversing: inspect `GameAssembly.dll` and plain assemblies in Ghidra/IDA/dnSpy/ILSpy, then reconstruct the decode function.
- Dynamic reversing: run the game under x64dbg/WinDbg, break on file reads or assembly loads, and dump the decoded DLL bytes from memory.
- Hooking: intercept file read, decrypt/decompress output, or managed assembly-load calls and write the decoded buffer to disk.
- Comparative analysis: infer the algorithm from the 15 wrapped files and headers, but this is usually slower unless the wrapper is simple.

The likely fastest path is dynamic dumping. The game has to decode these assemblies to use them, so catching the decoded buffer in memory may be easier than fully reconstructing the algorithm first. Static reimplementation can come after a successful dump.
