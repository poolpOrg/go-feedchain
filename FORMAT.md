# feedchain file format

This document describes the on-disk / on-the-wire format of a feedchain, as
implemented by the `feedchain` package. It is a description of the **current**
format (no version negotiation exists yet), written so the file can be parsed
by an independent implementation.

All multi-byte integers are **big-endian**. Byte offsets are zero-based.

## Overview

A feed is a single file. Its identity is the author's ed25519 public key; the
feed id is that key, `base64.RawURLEncoding`-encoded (43 ASCII characters).

```
+--------------------+  offset 0
| header signature   |  64 bytes   ed25519(sha256(header))
+--------------------+  offset 64
| header             |  266 bytes  fixed-size, see below
+--------------------+  offset 330  ── data region origin ──
| block 0            |  variable   JSON
| block 1            |             JSON
| ...                |
| block N-1          |
+--------------------+
| index              |  variable   JSON
+--------------------+
| metadata           |  variable   JSON
+--------------------+  EOF
```

The data region begins at offset **330** (`64 + 266`). All offsets stored in
the header (`IndexOffset`, `MetadataOffset`) and in index records
(`BlockOffset`) are **relative to offset 330**, not to the start of the file.

> **Note (known limitation).** The index and metadata are stored *after* the
> blocks, and the header at the front carries their offsets and signatures.
> Appending a block therefore rewrites the index, header and signatures — the
> whole file is rewritten on every append. See "Known issues" below.

## Header signature (64 bytes)

`ed25519.Sign(privateKey, sha256(headerBytes))`, where `headerBytes` is the
266-byte header that immediately follows. A reader MUST verify this against the
public key contained in the header before trusting any header field.

## Header (266 bytes, fixed)

| Offset | Len | Field              | Type        | Notes |
|-------:|----:|--------------------|-------------|-------|
|   0    |   2 | Version            | uint16      | currently `1`. Not branched on by readers yet. |
|   2    |   8 | GenerationTime     | uint64      | Unix seconds when the file was written. |
|  10    |   8 | IndexOffset        | uint64      | offset of the index, relative to 330. |
|  18    |   8 | IndexLength        | uint64      | byte length of the index JSON. |
|  26    |  32 | IndexChecksum      | [32]byte    | `sha256(indexBytes)`. |
|  58    |  64 | IndexSignature     | [64]byte    | `ed25519.Sign(priv, IndexChecksum)`. |
| 122    |   8 | MetadataOffset     | uint64      | offset of the metadata, relative to 330. |
| 130    |   8 | MetadataLength     | uint64      | byte length of the metadata JSON. |
| 138    |  32 | MetadataChecksum   | [32]byte    | `sha256(metadataBytes)`. |
| 170    |  64 | MetadataSignature  | [64]byte    | `ed25519.Sign(priv, MetadataChecksum)`. |
| 234    |  32 | PublicKey          | [32]byte    | ed25519 public key. The feed id. |

There is **no magic number**. A reader cannot distinguish a feedchain file from
arbitrary bytes except by verifying the header signature.

`IndexOffset` equals the sum of all block lengths (the blocks are contiguous
from offset 330). `MetadataOffset` equals `IndexOffset + IndexLength`.

## Index (JSON)

UTF-8 JSON, `IndexLength` bytes at `330 + IndexOffset`. Verified against
`IndexChecksum` (sha256) and `IndexSignature`.

```jsonc
{
  "name": "alice",            // display name (duplicated from metadata)
  "description": "...",        // (duplicated from metadata)
  "picture": "...",            // (duplicated from metadata)

  "records": [
    {
      "creation_time": 1700000000000,  // int64, Unix MILLIseconds
      "offset": 0,                      // uint64, block offset relative to 330
      "length": 142,                    // uint64, block byte length
      "digest": "<base64url sha256>",   // base64.RawURLEncoding of block sha256
      "signature": "<base64url ed25519>"// base64.RawURLEncoding, signs the digest
    }
    // ... one per block, in file order
  ],

  "hashtags":   { "tag":  ["<base64url block digest>", ...] },
  "mentions":   { "name": ["<base64url block digest>", ...] },
  "references": { "name": ["<base64url block digest>", ...] },
  "threads":    { "id":   ["<base64url block digest>", ...] }
}
```

- `records` is the source of truth for locating and verifying blocks. A reader
  finds block `i` at file offset `330 + records[i].offset`, reads
  `records[i].length` bytes, checks `sha256` against `records[i].digest`, then
  checks `records[i].signature` over that digest with the feed public key.
- `offset` is redundant with the running sum of `length`; the two MUST agree.
- The inverted-index maps (`hashtags` etc.) point at block digests, not
  offsets. They are a convenience cache derived from block content.

## Metadata (JSON)

UTF-8 JSON, `MetadataLength` bytes at `330 + MetadataOffset`. Verified against
`MetadataChecksum` / `MetadataSignature`.

```jsonc
{
  "picture":     "...",
  "name":        "alice",
  "description": "...",
  "location":    "..."
}
```

## Block (JSON)

Each block is a UTF-8 JSON object. Its bytes are exactly what `encoding/json`
produces for this struct, in this field order:

```jsonc
{
  "creation_time": 1700000000000,  // int64, Unix MILLIseconds
  "message":       "hello #world @bob",
  "payloads": [                     // attachments, may be empty/omitted
    {
      "name":         "cat.png",
      "content_type": "image/png",
      "data":         "<base64url bytes>"  // base64.RawURLEncoding
    }
  ],
  "thread": "",                     // optional thread id
  "parent": "<base64std sha256>"    // see encoding caveat below
}
```

### Block identity and signing

- A block's **digest** is `sha256(blockBytes)`, where `blockBytes` is the JSON
  serialization above.
- The index `digest` / `signature` for the block are
  `base64.RawURLEncoding(digest)` and
  `base64.RawURLEncoding(ed25519.Sign(priv, digest))`.
- `parent` is the digest of the previous block (for block 0 it is
  `sha256(publicKey)`). **Caveat:** `parent` is encoded with
  `base64.RawStdEncoding` (standard alphabet), whereas every other digest in
  the format uses `base64.RawURLEncoding`. This inconsistency is part of the
  current format.

> **Canonicalization warning.** The signed bytes are "whatever Go's
> `encoding/json` emits" for the block struct — there is no defined canonical
> form. A reimplementation that orders fields or escapes strings differently
> will compute a different digest and fail signature verification. Treat the Go
> serialization as normative until a canonical encoding is specified.

## Reading procedure

1. Read bytes `[0,64)` → header signature; read `[64,330)` → header.
2. Verify `ed25519.Verify(header.PublicKey, sha256(header), headerSig)`.
3. Read index at `[330+IndexOffset, +IndexLength)`; check sha256 ==
   `IndexChecksum`, then `ed25519.Verify(PublicKey, IndexChecksum,
   IndexSignature)`.
4. Read metadata at `[330+MetadataOffset, +MetadataLength)`; check sha256 ==
   `MetadataChecksum`, then `ed25519.Verify(PublicKey, MetadataChecksum,
   MetadataSignature)`.
5. For each record, read the block, check sha256 == `record.digest`, then
   `ed25519.Verify(PublicKey, digest, record.signature)`.

Reads can be served over HTTP using `Range` requests: fetch the fixed header
first, then the index, then individual blocks by offset — a static file server
is a sufficient backend.

## Known issues / would-change

These are documented so a v2 can address them deliberately:

1. **Not append-friendly.** Trailer (index/metadata) lives after the blocks and
   the front header carries their offsets, so every append rewrites the whole
   file. A relocatable fixed-size footer (or a log-structured layout where the
   index is a derivable cache) would make appends O(1) and allow tailing.
2. **Redundant offsets.** `records[i].offset` duplicates information already in
   `length`; storing both invites desync. Keep one.
3. **No magic / no real versioning.** Add a 4-byte magic and have readers branch
   on `Version`; today a v2 file would be mis-sliced as v1.
4. **Mixed base64 alphabets.** `parent` uses RawStd, everything else uses
   RawURL. Pick one.
5. **No canonical block encoding.** Signature verification is tied to Go's JSON
   output (see warning above).
6. **Hash chain not enforced.** `parent` links exist but no reader verifies that
   `records[i]`'s block parent equals `records[i-1]`'s digest, so the chain is
   currently decorative.
