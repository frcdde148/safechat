"""DES encryption and decryption helpers — pure-Python implementation.

DES-CBC is implemented from scratch following FIPS 46-3:
  - 64-bit block, 56-bit effective key (8 bytes with parity bits stripped)
  - 16 rounds of Feistel network using the standard S-boxes and P-box
  - PKCS#7 padding
  - CBC mode with a random 8-byte IV
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct


BLOCK_SIZE = 8  # bytes

# ---------------------------------------------------------------------------
# DES standard tables (indices are 1-based in the spec; stored 0-based here)
# ---------------------------------------------------------------------------

# Initial Permutation (IP)
_IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

# Final Permutation (IP^-1)
_FP = [
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
]

# Expansion table E (32 -> 48 bits)
_E = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
]

# Permutation P (32 bits)
_P = [
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25,
]

# Permuted-Choice 1 (64 -> 56 bits, selects key bits)
_PC1 = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
]

# Permuted-Choice 2 (56 -> 48 bits, generates round keys)
_PC2 = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

# Number of left-shifts per round
_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# S-boxes S1..S8  (each is 4 rows × 16 cols)
_SBOXES = [
    # S1
    [
        [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
        [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
        [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
        [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13],
    ],
    # S2
    [
        [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
        [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
        [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
        [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9],
    ],
    # S3
    [
        [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
        [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
        [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
        [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12],
    ],
    # S4
    [
        [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
        [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
        [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
        [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14],
    ],
    # S5
    [
        [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
        [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
        [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
        [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3],
    ],
    # S6
    [
        [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
        [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
        [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
        [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13],
    ],
    # S7
    [
        [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
        [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
        [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
        [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12],
    ],
    # S8
    [
        [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
        [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
        [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
        [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11],
    ],
]

# ---------------------------------------------------------------------------
# Bit-manipulation helpers
# ---------------------------------------------------------------------------

def _bytes_to_bits(data: bytes) -> list[int]:
    """Convert bytes to a list of bits (MSB first)."""
    bits: list[int] = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    """Convert a list of bits (MSB first) back to bytes."""
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)


def _permute(bits: list[int], table: list[int]) -> list[int]:
    """Apply a permutation table (1-based indices) to a bit list."""
    return [bits[t - 1] for t in table]


def _left_rotate(bits: list[int], n: int) -> list[int]:
    """Left-rotate a bit list by n positions."""
    return bits[n:] + bits[:n]


def _xor(a: list[int], b: list[int]) -> list[int]:
    return [x ^ y for x, y in zip(a, b)]


# ---------------------------------------------------------------------------
# Key schedule
# ---------------------------------------------------------------------------

def _generate_round_keys(key_bytes: bytes) -> list[list[int]]:
    """Produce 16 × 48-bit round keys from an 8-byte DES key."""
    key_bits = _bytes_to_bits(key_bytes)
    key56 = _permute(key_bits, _PC1)
    C, D = key56[:28], key56[28:]
    round_keys: list[list[int]] = []
    for shift in _SHIFTS:
        C = _left_rotate(C, shift)
        D = _left_rotate(D, shift)
        round_keys.append(_permute(C + D, _PC2))
    return round_keys


# ---------------------------------------------------------------------------
# Feistel function f(R, K)
# ---------------------------------------------------------------------------

def _feistel(right: list[int], round_key: list[int]) -> list[int]:
    expanded = _permute(right, _E)           # 32 -> 48 bits
    xored = _xor(expanded, round_key)        # XOR with round key
    sbox_out: list[int] = []
    for i in range(8):
        block = xored[i * 6:(i + 1) * 6]
        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        val = _SBOXES[i][row][col]
        for j in range(3, -1, -1):
            sbox_out.append((val >> j) & 1)
    return _permute(sbox_out, _P)


# ---------------------------------------------------------------------------
# Single-block DES encrypt / decrypt
# ---------------------------------------------------------------------------

def _des_block(block: bytes, round_keys: list[list[int]], decrypt: bool = False) -> bytes:
    bits = _permute(_bytes_to_bits(block), _IP)
    L, R = bits[:32], bits[32:]
    keys = list(reversed(round_keys)) if decrypt else round_keys
    for rk in keys:
        L, R = R, _xor(L, _feistel(R, rk))
    return _bits_to_bytes(_permute(R + L, _FP))


# ---------------------------------------------------------------------------
# PKCS#7 padding
# ---------------------------------------------------------------------------

def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("invalid PKCS#7 padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("invalid PKCS#7 padding bytes")
    return data[:-pad_len]


# ---------------------------------------------------------------------------
# Public API  (interface identical to the original library-based version)
# ---------------------------------------------------------------------------

def derive_des_key(secret: str | bytes) -> bytes:
    """Derive a DES-sized key from a text or binary secret."""
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hashlib.sha256(secret).digest()[:BLOCK_SIZE]


def encrypt_text(plaintext: str, secret: str | bytes) -> dict[str, str]:
    """Encrypt UTF-8 text with DES-CBC (pure Python) and return Base64 fields."""
    key = derive_des_key(secret)
    iv = os.urandom(BLOCK_SIZE)
    round_keys = _generate_round_keys(key)
    padded = _pkcs7_pad(plaintext.encode("utf-8"), BLOCK_SIZE)
    ciphertext = bytearray()
    prev = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = bytes(p ^ c for p, c in zip(padded[i:i + BLOCK_SIZE], prev))
        enc = _des_block(block, round_keys, decrypt=False)
        ciphertext.extend(enc)
        prev = enc
    return {
        "ciphertext": base64.b64encode(bytes(ciphertext)).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
    }


def decrypt_text(ciphertext_b64: str, iv_b64: str, secret: str | bytes) -> str:
    """Decrypt Base64 DES-CBC fields (pure Python) into UTF-8 text."""
    key = derive_des_key(secret)
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    round_keys = _generate_round_keys(key)
    plaintext = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        dec = _des_block(block, round_keys, decrypt=True)
        plaintext.extend(p ^ c for p, c in zip(dec, prev))
        prev = block
    return _pkcs7_unpad(bytes(plaintext)).decode("utf-8")
