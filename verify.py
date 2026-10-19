#!/usr/bin/env python3
"""Verify Wrenfield history proofs.  pip install cryptography opentimestamps-client

  python3 verify.py proofs/2026/2026-10-19                 # signature + Merkle root + chain link
  python3 verify.py proofs/2026/2026-10-19 --data DIR      # also re-hash data files you were given
  ots verify proofs/2026/2026-10-19/manifest.json.ots       # Bitcoin timestamp (needs a node or uses public explorers with -l)
"""
import argparse, base64, glob, hashlib, json, os, pathlib, sys

def sha(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

def merkle(leaves):
    lv = [hashlib.sha256(b"\x00" + p.encode() + b"\x00" + bytes.fromhex(h)).digest() for p, h in sorted(leaves)]
    if not lv: return hashlib.sha256(b"").hexdigest()
    while len(lv) > 1:
        lv = [hashlib.sha256(b"\x01" + lv[i] + lv[i + 1]).digest() if i + 1 < len(lv) else lv[i] for i in range(0, len(lv), 2)]
    return lv[0].hex()

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("snapshot_dir"); ap.add_argument("--data"); ap.add_argument("--key")
    a = ap.parse_args(); d = pathlib.Path(a.snapshot_dir); here = pathlib.Path(__file__).resolve().parent
    body = (d / "manifest.json").read_bytes(); m = json.loads(body); ok = True
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    keyf = a.key or next(iter(glob.glob(str(here / "keys" / f"*{m['signing_key_id']}.pub.b64"))), None)
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pathlib.Path(keyf).read_text().strip()))
    try:
        pub.verify(base64.b64decode((d / "manifest.json.sig").read_text().strip()), body); print("signature: OK")
    except Exception:
        print("signature: FAIL"); ok = False
    r = merkle([(f["path"], f["sha256"]) for f in m["files"]])
    print("merkle root:", "OK" if r == m["merkle_root"] else "FAIL"); ok &= r == m["merkle_root"]
    if m.get("prev_manifest"):
        prev = d.parent.parent / m["prev_manifest"][:4] / m["prev_manifest"] / "manifest.json"
        if prev.exists():
            good = sha(prev) == m["prev_manifest_sha256"]; print("chain link to", m["prev_manifest"] + ":", "OK" if good else "FAIL"); ok &= good
        else:
            print("chain link: previous manifest not found locally")
    if a.data:
        for f in m["files"]:
            p = pathlib.Path(a.data) / f["path"]
            if p.exists():
                g = sha(p) == f["sha256"]; print(f"  {f['path']}: {'OK' if g else 'MISMATCH'}"); ok &= g
            else:
                print(f"  {f['path']}: not provided")
    print("RESULT:", "VERIFIED" if ok else "FAILED"); sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
