"""AES 加密工具（用于审计日志内容加密）— 纯 Python 实现。

按照 FIPS 197 从零实现 AES-CBC：
  - 支持 AES-128、AES-192、AES-256（由密钥长度决定）
  - 128 位（16 字节）分组大小
  - CBC 模式，使用随机 16 字节 IV
  - PKCS#7 填充
"""

from __future__ import annotations

import base64
import hashlib
import os


BLOCK_SIZE = 16  # 字节（AES 固定使用 128 位分组）

# ---------------------------------------------------------------------------
# AES 常量
# ---------------------------------------------------------------------------

# AES S 盒
_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# AES 逆 S 盒
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

# 轮常量（Rcon）
_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# ---------------------------------------------------------------------------
# GF(2^8) 乘法（AES 域多项式 0x11b）
# ---------------------------------------------------------------------------

def _gf_mul(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11b
        b >>= 1
    return result & 0xFF


# ---------------------------------------------------------------------------
# AES 密钥扩展
# ---------------------------------------------------------------------------

def _key_expansion(key: bytes) -> list[list[int]]:
    """将密钥字节扩展为 Nb*(Nr+1) 个 4 字节字。"""
    key_len = len(key)
    if key_len == 16:
        nk, nr = 4, 10
    elif key_len == 24:
        nk, nr = 6, 12
    elif key_len == 32:
        nk, nr = 8, 14
    else:
        raise ValueError("AES key must be 16, 24, or 32 bytes")

    w = [list(key[i:i + 4]) for i in range(0, key_len, 4)]
    total_words = 4 * (nr + 1)
    i = nk
    while i < total_words:
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]           # 字循环左移（RotWord）
            temp = [_SBOX[b] for b in temp]      # 字节替换（SubWord）
            temp[0] ^= _RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]      # 字节替换（仅 AES-256）
        w.append([a ^ b for a, b in zip(w[i - nk], temp)])
        i += 1

    # 按轮分组，每轮密钥为 16 字节列表
    round_keys = []
    for r in range(nr + 1):
        rk = []
        for c in range(4):
            rk.extend(w[r * 4 + c])
        round_keys.append(rk)
    return round_keys


# ---------------------------------------------------------------------------
# AES 状态操作（状态 = 4×4 字节矩阵，列主序）
# ---------------------------------------------------------------------------

def _bytes_to_state(block: bytes) -> list[list[int]]:
    return [[block[r + 4 * c] for r in range(4)] for c in range(4)]


def _state_to_bytes(state: list[list[int]]) -> bytes:
    return bytes(state[c][r] for c in range(4) for r in range(4))


def _add_round_key(state: list[list[int]], rk: list[int]) -> list[list[int]]:
    for c in range(4):
        for r in range(4):
            state[c][r] ^= rk[r + 4 * c]
    return state


def _sub_bytes(state: list[list[int]], inv: bool = False) -> list[list[int]]:
    box = _INV_SBOX if inv else _SBOX
    return [[box[state[c][r]] for r in range(4)] for c in range(4)]


def _shift_rows(state: list[list[int]]) -> list[list[int]]:
    for r in range(1, 4):
        row = [state[c][r] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            state[c][r] = row[c]
    return state


def _inv_shift_rows(state: list[list[int]]) -> list[list[int]]:
    for r in range(1, 4):
        row = [state[c][r] for c in range(4)]
        row = row[-r:] + row[:-r]
        for c in range(4):
            state[c][r] = row[c]
    return state


def _mix_columns(state: list[list[int]]) -> list[list[int]]:
    for c in range(4):
        s = state[c]
        state[c] = [
            _gf_mul(0x02, s[0]) ^ _gf_mul(0x03, s[1]) ^ s[2] ^ s[3],
            s[0] ^ _gf_mul(0x02, s[1]) ^ _gf_mul(0x03, s[2]) ^ s[3],
            s[0] ^ s[1] ^ _gf_mul(0x02, s[2]) ^ _gf_mul(0x03, s[3]),
            _gf_mul(0x03, s[0]) ^ s[1] ^ s[2] ^ _gf_mul(0x02, s[3]),
        ]
    return state


def _inv_mix_columns(state: list[list[int]]) -> list[list[int]]:
    for c in range(4):
        s = state[c]
        state[c] = [
            _gf_mul(0x0e, s[0]) ^ _gf_mul(0x0b, s[1]) ^ _gf_mul(0x0d, s[2]) ^ _gf_mul(0x09, s[3]),
            _gf_mul(0x09, s[0]) ^ _gf_mul(0x0e, s[1]) ^ _gf_mul(0x0b, s[2]) ^ _gf_mul(0x0d, s[3]),
            _gf_mul(0x0d, s[0]) ^ _gf_mul(0x09, s[1]) ^ _gf_mul(0x0e, s[2]) ^ _gf_mul(0x0b, s[3]),
            _gf_mul(0x0b, s[0]) ^ _gf_mul(0x0d, s[1]) ^ _gf_mul(0x09, s[2]) ^ _gf_mul(0x0e, s[3]),
        ]
    return state


# ---------------------------------------------------------------------------
# 单分组 AES 加密 / 解密
# ---------------------------------------------------------------------------

def _aes_block(block: bytes, round_keys: list[list[int]], decrypt: bool = False) -> bytes:
    nr = len(round_keys) - 1
    state = _bytes_to_state(block)

    if not decrypt:
        state = _add_round_key(state, round_keys[0])
        for rnd in range(1, nr):
            state = _sub_bytes(state)
            state = _shift_rows(state)
            state = _mix_columns(state)
            state = _add_round_key(state, round_keys[rnd])
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _add_round_key(state, round_keys[nr])
    else:
        state = _add_round_key(state, round_keys[nr])
        for rnd in range(nr - 1, 0, -1):
            state = _inv_shift_rows(state)
            state = _sub_bytes(state, inv=True)
            state = _add_round_key(state, round_keys[rnd])
            state = _inv_mix_columns(state)
        state = _inv_shift_rows(state)
        state = _sub_bytes(state, inv=True)
        state = _add_round_key(state, round_keys[0])

    return _state_to_bytes(state)


# ---------------------------------------------------------------------------
# PKCS#7 填充
# ---------------------------------------------------------------------------

def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("invalid PKCS#7 padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("invalid PKCS#7 padding bytes")
    return data[:-pad_len]


# ---------------------------------------------------------------------------
# 公开 API（接口与原调库版本完全一致）
# ---------------------------------------------------------------------------

def derive_aes_key(secret: str | bytes) -> bytes:
    """从文本或二进制 secret 派生 AES-256 密钥。"""
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hashlib.sha256(secret).digest()


def encrypt_text(plaintext: str, secret: str | bytes) -> dict[str, str]:
    """使用 AES-CBC（纯 Python）加密 UTF-8 文本，返回 Base64 字段字典。"""
    key = derive_aes_key(secret)
    iv = os.urandom(BLOCK_SIZE)
    round_keys = _key_expansion(key)
    padded = _pkcs7_pad(plaintext.encode("utf-8"))
    ciphertext = bytearray()
    prev = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = bytes(p ^ c for p, c in zip(padded[i:i + BLOCK_SIZE], prev))
        enc = _aes_block(block, round_keys, decrypt=False)
        ciphertext.extend(enc)
        prev = enc
    return {
        "ciphertext": base64.b64encode(bytes(ciphertext)).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
    }


def decrypt_text(ciphertext_b64: str, iv_b64: str, secret: str | bytes) -> str:
    """使用 AES-CBC（纯 Python）将 Base64 密文字段解密为 UTF-8 文本。"""
    key = derive_aes_key(secret)
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    round_keys = _key_expansion(key)
    plaintext = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        dec = _aes_block(block, round_keys, decrypt=True)
        plaintext.extend(p ^ c for p, c in zip(dec, prev))
        prev = block
    return _pkcs7_unpad(bytes(plaintext)).decode("utf-8")
