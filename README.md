# wrenfield-history-proofs

Public, append-only proofs that the **Wrenfield Data history panel** was not revised after the day it was collected.

This repository contains **hashes only**. It never contains the underlying data (AI answers, keyword demand, SERP features).
Anyone we share a day's files with can check them against the proofs here.

Methodology: https://wrenfielddata.com/methodology/

## What is sealed each day

Every morning (about 3:15 AM Pacific) the panel collects AI answers from ChatGPT, Google AI Mode, Gemini and Perplexity, keyword
demand and SERP features. Right after collection, `seal.py`:

1. Computes **SHA-256** of every file in the day's folder, including a frozen copy of the panel configuration (prompts, engines, keywords).
2. Builds a **Merkle root** over those hashes.
3. Links the day to the previous day: `prev_manifest_sha256` = SHA-256 of the previous `manifest.json` (a hash chain, so days cannot be
   inserted, removed or swapped without breaking every later link).
4. Signs the exact bytes of `manifest.json` with **Ed25519** (`manifest.json.sig`, base64). Public key: `keys/`.
5. Anchors `manifest.json` in Bitcoin with **[OpenTimestamps](https://opentimestamps.org)** (`manifest.json.ots`). A fresh stamp is
   "pending" for a few hours; later runs upgrade it to a full Bitcoin attestation.

A sealed day is never re-sealed. If a day ever had to be re-collected, the re-run gets its own snapshot (`YYYY-MM-DD_rerun_HHMMSS`) and
both stay in the chain.

## Layout

```
proofs/YYYY/YYYY-MM-DD/manifest.json        file hashes, Merkle root, previous-manifest hash
proofs/YYYY/YYYY-MM-DD/manifest.json.sig    Ed25519 signature (base64) over manifest.json
proofs/YYYY/YYYY-MM-DD/manifest.json.ots    OpenTimestamps proof
keys/                                       Ed25519 public key(s)
CHAIN.md                                    index of every sealed snapshot
verify.py                                   verifier
```

## Verify

```bash
pip install cryptography opentimestamps-client
python3 verify.py proofs/2026/2026-10-19                   # signature, Merkle root, chain link
python3 verify.py proofs/2026/2026-10-19 --data /path/day   # re-hash files you were given
ots verify proofs/2026/2026-10-19/manifest.json.ots         # Bitcoin timestamp
```

Merkle construction: leaves sorted by path; `leaf = SHA256(0x00 || path || 0x00 || file_sha256_bytes)`,
`node = SHA256(0x01 || left || right)`, an odd node is promoted unchanged.

## Notes

- The first snapshot (2026-10-19) was sealed on the afternoon of Oct 19, 2026 PT, a few hours after collection; its `panel/` files were
  copied in from the v1 panel backups at seal time. Every later day is sealed minutes after collection.
- The timestamp proves a manifest existed no later than its Bitcoin block. It does not prove the data is correct, only that it has not changed since.

Contact: hello@wrenfielddata.com · License: CC0 for the proof files.
