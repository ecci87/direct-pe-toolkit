# LLMPE64 indexed executable protocol

The frontend is optional. Direct binary inspection/editing remains permitted. This protocol makes named retrieval and managed editing convenient; it is not a required implementation language or a security signature.

## Storage

A read-only, non-executable .llm section holds a 512-byte header and up to 128 independently indexed 192-byte records. Records carry names, kinds, public/body RVAs, code length/capacity, document location/capacity, hashes and generation. RVAs are image-relative; the frontend also returns file offsets and the preferred image base.

Header major 1 remains supported. Minor 0 stores legacy expanded JSON. Minor 1 supports concise descriptions and separate optional mechanical records:

| Position | Meaning |
| --- | --- |
| Header 8/10 | uint16 major/minor |
| Header 12..40 | eight uint32: header size, record width, capacity/count, directory/arena offsets, arena end/capacity |
| Record 0..63 | ASCII name |
| Record 64/68/70 | name CRC32, uint16 kind/version |
| Record 72..96 | seven uint32: entry/body RVA, used/slot bytes, document RVA/length/whole-slot capacity |
| Record 100..179 | code SHA-256, description SHA-256, truncated ABI digest |
| Record 180/184/188 | flags, generation, technical-record RVA |

Kinds are function=1, data=2, architecture=3, symbols=4. Flag bit 0 enables concise storage. A record's technical pointer is zero or points inside its own metadata slot after the readable JSON/NUL. The 48-byte technical header is LLMFX64 plus NUL, packed length, decoded length and packed SHA-256; a bounded zlib-compressed JSON payload follows. It stores fixups/labels, implementation/unwind records, full ABI defaults or the symbol map. It stores no change history or test transcript. Compression is a tooling/storage feature, not a runtime application dependency.

The readable description stays ordinary compact UTF-8 JSON, schema llm-pe.module.v1. Functions have one purpose, essential arguments/result/contracts, a frame profile and unique declared calls/imports. Data contracts retain field types, offsets, sizes, units and bounds; meaningful fields are never silently truncated. Architecture stays brief. Native --describe implementations that print the indexed JSON keep working without decoding the technical records.

PE.brief reads only a description. PE.document expands the mechanical records for compatibility with editing/verification. ABI digests use the expanded contract. Technical checksums and consistency checks detect stale/corrupt records. The format does not prove semantic accuracy or authenticate code.

## Optional views

```text
overview App.exe
graph App.exe
graph App.exe ProcessRecord
get App.exe ProcessRecord --bytes
get App.exe Data.Context
get App.exe ProcessRecord --bytes --fixups
```

Views return compact JSON with a default 32768-byte output budget; --output writes a new file. overview reads descriptions and directory entries, not function bodies. graph reports declared direct calls, with imports separately; indirect/dynamic calls are not inferred. get returns one description, addresses and revision, optionally its used bytes and expanded edit records.

inspect and context remain expanded compatibility views. --raw with get --bytes reads an edited body despite a stale code hash and reports whether the hash matches. Address/length indexing still must be valid. Raw unannotated EXEs have no names to retrieve; normal PE/binary tools can edit them.

## Editing

Managed patch-template/patch uses revision hashes, ABI checks, declared fixups and the supported leaf/stack56 unwind profiles. It writes a new candidate and preserves other bodies. Concise descriptions need not change after a code-only patch; technical revisions are checked separately. Metadata capacity covers the whole per-module slot, including its technical tail.

Direct edits can use any suitable method. Keep actual instruction fields, PE directories, stable call targets and unwind records consistent. For same-slot edits:

```text
get edited.exe ProcessRecord --bytes --raw
sync edited.exe ProcessRecord --used-bytes 123 --manifest full-module.json --output candidate.exe
```

The manifest is optional when existing declarations still apply. sync preserves bytes as edited; it never silently resolves/rewrites their displacements. Changed instruction positions/references require accurate declarations. It refreshes lengths, hashes, padding and unwind range, then verifies. Structural/interface changes beyond this helper remain possible through a correct direct edit or explicit layout migration.

Relocation through patch --relocate appends a body behind its stable public jump gate. Finite code, document and unwind reserves can be exhausted. Helper restrictions do not prohibit other editing approaches.

## Repacking and reproduction

compact EXE --output NEW repacks the final .llm section while retaining every function/data RVA and byte. It requires no overlay/certificate and leaves all other sections intact apart from PE size fields. Specifications with metadata.format=concise-v1 select this storage during migrate; legacy specifications keep legacy byte-identical packing. new uses concise storage by default and remains EXIT-ONLY.

export/build provides lossless raw checkpoints. Edited human views that disagree with snapshots are rejected by build. migrate handles a raw base plus explicit bytes/layout declarations; neither helper is a compiler or general linker.

verify checks the supported structural profile, hashes, fixups, padding, imports and unwind. Optional audit independently decodes selected instructions. Neither proves register/memory behavior or application acceptance; run the relevant native path.
