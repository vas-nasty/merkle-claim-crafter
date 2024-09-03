#!/usr/bin/env python3
"""
Merkle Claim Crafter — утилита для сборки мерклового дерева под airdrop-дистрибьюторы
(лист = keccak256(abi.encodePacked(account, uint256 amount)), пары на уровне сортируются).
Полезность: быстро готовит merkleRoot, proofs и claims для контракта-дистрибьютора.
"""
import argparse, csv, json, re, sys, hashlib
from typing import List, Tuple, Dict

# ---------- Keccak256 ----------
def _keccak256(data: bytes) -> bytes:
    try:
        from eth_utils import keccak as _k
        return _k(data)
    except Exception:
        pass
    try:
        import sha3  # pysha3
        k = sha3.keccak_256()
        k.update(data)
        return k.digest()
    except Exception:
        pass
    h = hashlib.sha3_256()  # WARNING: не keccak-256
    h.update(data)
    sys.stderr.write("[WARN] hashlib.sha3_256 != keccak-256. Установите eth-utils или pysha3.\n")
    return h.digest()

ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

def norm_addr(addr: str) -> str:
    if not isinstance(addr, str):
        raise ValueError("address must be string")
    a = addr.strip()
    if not ADDR_RE.match(a):
        raise ValueError(f"Invalid EVM address: {addr}")
    return a.lower()

def uint256_str(x: str) -> str:
    x = str(x).strip()
    if not x.isdigit():
        raise ValueError(f"amount must be a non-negative integer string, got: {x}")
    return x

def leaf_hash(address: str, amount: str) -> bytes:
    addr_bytes = bytes.fromhex(address[2:])
    amt = int(amount)
    amt_bytes = amt.to_bytes(32, byteorder="big")
    return _keccak256(addr_bytes + amt_bytes)

def build_levels(leaves: List[bytes]) -> List[List[bytes]]:
    if not leaves:
        raise ValueError("No leaves to build tree")
    levels = [leaves]
    cur = leaves
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur), 2):
            left = cur[i]
            right = cur[i+1] if i+1 < len(cur) else cur[i]
            if right < left:
                left, right = right, left
            nxt.append(_keccak256(left + right))
        levels.append(nxt)
        cur = nxt
    return levels

def merkle_root(leaves: List[bytes]) -> bytes:
    return build_levels(leaves)[-1][0]

def build_from_rows(rows: List[Tuple[str, str]]):
    norm = [(norm_addr(a), uint256_str(v)) for (a, v) in rows]
    leaves = [leaf_hash(a, v) for (a, v) in norm]
    order = sorted(range(len(leaves)), key=lambda i: leaves[i])
    leaves_sorted = [leaves[i] for i in order]
    norm_sorted   = [norm[i]   for i in order]
    levels = build_levels(leaves_sorted)

    def proof_for(idx: int) -> list:
        proof = []
        pos = idx
        for level in levels[:-1]:
            sib = pos ^ 1
            if sib < len(level):
                proof.append("0x" + level[sib].hex())
            pos //= 2
        return proof

    claims: Dict[str, dict] = {}
    token_total = 0
    for i, (addr, amt) in enumerate(norm_sorted):
        token_total += int(amt)
        claims[addr] = {"index": i, "amount": amt, "proof": proof_for(i)}
    root_hex = "0x" + merkle_root(leaves_sorted).hex()
    return root_hex, claims, str(token_total)

def load_csv(path: str) -> List[Tuple[str, str]]:
    import csv
    out = []
    with open(path, newline="") as f:
        rdr = csv.DictReader(f)
        assert "address" in rdr.fieldnames and "amount" in rdr.fieldnames, "CSV needs header: address,amount"
        for r in rdr:
            a = (r.get("address") or "").strip()
            v = (r.get("amount") or "").strip()
            if a and v:
                out.append((a, v))
    if not out:
        raise ValueError("No valid rows in CSV")
    return out

def save_json(obj, path: str):
    with open(path, "w") as f:
        import json; json.dump(obj, f, indent=2)

def save_claims_csv(claims: Dict[str, dict], path: str):
    import csv, json
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["address", "amount", "index", "proof"])
        for addr, c in claims.items():
            w.writerow([addr, c["amount"], c["index"], json.dumps(c["proof"])])

def cmd_sample(args):
    import csv
    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["address", "amount"])
        w.writerow(["0x1111111111111111111111111111111111111111", "1000"])
        w.writerow(["0x2222222222222222222222222222222222222222", "2500"])
        w.writerow(["0x3333333333333333333333333333333333333333", "5000"])
    print(f"Sample CSV written to {args.out}")

def cmd_build(args):
    rows = load_csv(args.csv)
    root, claims, total = build_from_rows(rows)
    master = {"merkleRoot": root, "tokenTotal": total, "claims": claims}
    save_json(master, "merkle.json")
    save_claims_csv(claims, "claims.csv")
    print("Merkle root:", root)
    print("Token total:", total)
    print("Wrote merkle.json and claims.csv")

def cmd_proof(args):
    import json
    with open(args.json, "r") as f:
        master = json.load(f)
    addr = norm_addr(args.address)
    c = master["claims"].get(addr)
    if not c:
        print("Address not found in claims"); sys.exit(1)
    print(json.dumps({"address": addr, "amount": c["amount"], "index": c["index"], "proof": c["proof"]}, indent=2))

def cmd_verify(args):
    import json
    with open(args.json, "r") as f:
        master = json.load(f)
    addr = norm_addr(args.address)
    amt  = uint256_str(args.amount)
    claim = master["claims"].get(addr)
    if not claim:
        print("Address not in claims"); sys.exit(1)
    if claim["amount"] != amt:
        print("Amount mismatch. Expected:", claim["amount"]); sys.exit(1)
    h = leaf_hash(addr, amt)
    for sib_hex in claim["proof"]:
        sib = bytes.fromhex(sib_hex[2:])
        left, right = (h, sib) if h <= sib else (sib, h)
        h = _keccak256(left + right)
    ok = ("0x" + h.hex()).lower() == master["merkleRoot"].lower()
    print("Valid proof:", ok)
    if not ok: sys.exit(1)

def main():
    import argparse
    ap = argparse.ArgumentParser(description="Merkle Claim Crafter (sorted pairs)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("sample", help="write sample CSV")
    p.add_argument("--out", default="sample.csv")
    p.set_defaults(func=cmd_sample)

    p = sub.add_parser("build", help="build merkle.json & claims.csv from CSV")
    p.add_argument("--csv", required=True)
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("proof", help="print proof JSON for an address")
    p.add_argument("--json", default="merkle.json")
    p.add_argument("--address", required=True)
    p.set_defaults(func=cmd_proof)

    p = sub.add_parser("verify", help="verify a claim against merkle.json")
    p.add_argument("--json", default="merkle.json")
    p.add_argument("--address", required=True)
    p.add_argument("--amount", required=True)
    p.set_defaults(func=cmd_verify)

    args = ap.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
