#!/usr/bin/env python3
"""zip_enc.py — password-protected zip (ZipCrypto, store method) in pure Python.

Why: python's zipfile can't WRITE encrypted entries; a protected zip defeats
AV archive scan-on-open (e.g. 360 scanning a zip before extraction).

Implementation: manual zip layout + classic PKZIP ZipCrypto stream cipher.
Weak crypto by modern standards, but AV engines do not brute-force zip
passwords — they skip protected entries, which is exactly what we want.
"""
import os
import sys
import struct
import time
import zlib


def crc32_byte(crc, b):
    crc ^= b
    for _ in range(8):
        if crc & 1:
            crc = (crc >> 1) ^ 0xEDB88320
        else:
            crc >>= 1
    return crc


class ZipCrypto:
    def __init__(self, password):
        self.key0 = 0x12345678
        self.key1 = 0x23456789
        self.key2 = 0x34567890
        for b in password:
            self.update(b)

    def update(self, b):
        self.key0 = crc32_byte(self.key0, b) & 0xFFFFFFFF
        self.key1 = ((self.key1 + (self.key0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        self.key2 = crc32_byte(self.key2, (self.key1 >> 24) & 0xFF) & 0xFFFFFFFF

    def keystream(self):
        tmp = (self.key2 | 2) & 0xFFFF
        return ((tmp * (tmp ^ 1)) >> 8) & 0xFF

    def encrypt(self, data):
        out = bytearray()
        for b in data:
            c = (b ^ self.keystream()) & 0xFF
            self.update(b)  # PKZIP: keys updated with the PLAINTEXT byte
            out.append(c)
        return bytes(out)


def dos_time():
    now = time.localtime()
    t = (now.tm_hour << 11) | (now.tm_min << 5) | (now.tm_sec // 2)
    d = ((now.tm_year - 1980) << 9) | ((now.tm_mon) << 5) | now.tm_mday
    return t, d


def make_zip(src, dst, password):
    data = open(src, "rb").read()
    name = os.path.basename(src).encode("utf-8")
    crc = zlib.crc32(data) & 0xFFFFFFFF
    method = 0  # store (payload is already high-entropy; compression gains nothing)

    t, d = dos_time()
    flag = 0x0001  # encrypted

    # encryption header: 11 random bytes + 1 check byte (12th byte = CRC high byte)
    import random
    check = (crc >> 24) & 0xFF
    hdr = bytes(random.randrange(256) for _ in range(11)) + bytes([check])
    zc = ZipCrypto(password)
    enc_hdr = zc.encrypt(hdr)
    enc_data = zc.encrypt(data)

    comp_size = len(enc_hdr) + len(enc_data)
    uncomp_size = len(data)

    def local_header():
        return struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50, 20, flag, method, t, d,
            crc, comp_size, uncomp_size, len(name), 0,
        ) + name

    def central_header():
        return struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50, 20, 20, flag, method, t, d,
            crc, comp_size, uncomp_size, len(name), 0, 0, 0, 0, 0, 0,
        ) + name

    def eocd(offset, count, size):
        return struct.pack(
            "<IHHHHIIH",
            0x06054B50, 0, 0, count, count, size, offset, 0,
        )

    lh = local_header()
    ch = central_header()
    offset = 0
    central_offset = offset + len(lh) + comp_size
    with open(dst, "wb") as f:
        f.write(lh)
        f.write(enc_hdr)
        f.write(enc_data)
        f.write(ch)
        f.write(eocd(central_offset, 1, len(ch)))
    print("created %s (%d bytes) password: %s" % (dst, os.path.getsize(dst), password))


def main():
    if len(sys.argv) < 4:
        print("usage: zip_enc.py <src_file> <dst_zip> <password>")
        return 1
    src, dst, pwd = sys.argv[1], sys.argv[2], sys.argv[3]
    if not os.path.isfile(src):
        print("src not found:", src)
        return 1
    make_zip(src, dst, pwd.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
