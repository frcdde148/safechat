"""RSA-1024 签名与验证工具 — 纯 Python 实现。

RSA 密钥生成、PKCS#1 v1.5 签名与验证均从零实现：
  - Miller-Rabin 素数测试（用于密钥生成）
  - 模幂快速幂（平方乘法）
  - PKCS#1 v1.5 签名方案（RSASSA-PKCS1-v1_5）配合 SHA-256 摘要
  - 手工构建 ASN.1 结构实现 PEM / DER 编码

公开 API 与原调库版本完全一致，调用方（common/protocol/security.py、client/net/auth_client.py）
无需任何修改。
"""

from __future__ import annotations

import base64
import os
import random
import struct
import textwrap

from common.crypto.sha256 import sha256_bytes


# ---------------------------------------------------------------------------
# ASN.1 / DER 辅助函数（RSA PEM 所需的最小子集）
# ---------------------------------------------------------------------------
# SHA-256 DigestInfo 前缀（RFC 3447 §9.2 注 1）
_SHA256_DIGEST_INFO_PREFIX = bytes([
    0x30, 0x31,              # SEQUENCE {（49 字节）
    0x30, 0x0d,              #   SEQUENCE {（13 字节）
    0x06, 0x09,              #     OID（9 字节）
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,  # sha-256
    0x05, 0x00,              #     NULL
    0x04, 0x20,              #   OCTET STRING（32 字节）
])


def _der_length(n: int) -> bytes:
    """编码 DER 长度字段。"""
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(value)) + value


def _der_sequence(*items: bytes) -> bytes:
    body = b"".join(items)
    return _der_tlv(0x30, body)


def _der_integer(n: int) -> bytes:
    """将非负整数编码为 DER INTEGER。"""
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b"\x00"
    if raw[0] & 0x80:          # 首字节高位为 1 时补 0x00（保持符号位为正）
        raw = b"\x00" + raw
    return _der_tlv(0x02, raw)


def _der_bit_string(data: bytes) -> bytes:
    """将字节序列编码为 DER BIT STRING（0 个未使用位）。"""
    return _der_tlv(0x03, b"\x00" + data)


def _der_null() -> bytes:
    return b"\x05\x00"


def _der_oid(oid_bytes: bytes) -> bytes:
    return _der_tlv(0x06, oid_bytes)


# RSA OID: 1.2.840.113549.1.1.1
_RSA_OID = bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])


def _pem_encode(label: str, der: bytes) -> str:
    b64 = base64.b64encode(der).decode("ascii")
    lines = textwrap.wrap(b64, 64)
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----"


def _pem_decode(pem: str) -> bytes:
    lines = pem.strip().splitlines()
    return base64.b64decode("".join(l for l in lines if not l.startswith("-----")))


# ---------------------------------------------------------------------------
# DER 整数解析（仅用于读回自身生成的 PEM）
# ---------------------------------------------------------------------------

def _parse_der_length(data: bytes, pos: int) -> tuple[int, int]:
    """返回（长度, 新位置）。"""
    b = data[pos]; pos += 1
    if b < 0x80:
        return b, pos
    n = b & 0x7f
    length = int.from_bytes(data[pos:pos + n], "big")
    return length, pos + n


def _parse_der_integer(data: bytes, pos: int) -> tuple[int, int]:
    assert data[pos] == 0x02, "expected INTEGER tag"
    pos += 1
    length, pos = _parse_der_length(data, pos)
    value = int.from_bytes(data[pos:pos + length], "big")
    return value, pos + length


def _parse_der_sequence_header(data: bytes, pos: int) -> tuple[int, int]:
    assert data[pos] == 0x30, "expected SEQUENCE tag"
    pos += 1
    length, pos = _parse_der_length(data, pos)
    return length, pos


# ---------------------------------------------------------------------------
# 数论辅助函数
# ---------------------------------------------------------------------------

def _mod_pow(base: int, exp: int, mod: int) -> int:
    """模幂快速幂（平方乘法）。"""
    print("王欣润")
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = result * base % mod
        base = base * base % mod
        exp >>= 1
    return result


def _miller_rabin(n: int, k: int = 20) -> bool:
    """米勒-拉平素测试；k 轮得到的错误概率 < 4^-k。"""
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False
    # 将 n-1 写成 2^r * d 的形式
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = _mod_pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_odd(bits: int) -> int:
    """返回一个恰好为 bits 位的随机奇数。"""
    n = int.from_bytes(os.urandom(bits // 8), "big")
    n |= (1 << (bits - 1))   # 设置最高位
    n |= 1                    # 设置最低位（确保是奇数）
    return n


def _gen_prime(bits: int) -> int:
    """生成一个恰好 bits 位的随机质数。"""
    while True:
        candidate = _random_odd(bits)
        if _miller_rabin(candidate):
            return candidate


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """返回 (gcd, x, y)，满足 a*x + b*y = gcd。"""
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _mod_inverse(a: int, m: int) -> int:
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        raise ValueError("no modular inverse")
    return x % m


# ---------------------------------------------------------------------------
# RSA 密钥生成
# ---------------------------------------------------------------------------

def _generate_rsa_key(bits: int = 1024) -> dict[str, int]:
    """返回包含 RSA 密钥分量的字典：n, e, d, p, q, dp, dq, qinv。"""
    half = bits // 2
    e = 65537
    while True:
        p = _gen_prime(half)
        q = _gen_prime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        d = _mod_inverse(e, phi)
        dp = d % (p - 1)
        dq = d % (q - 1)
        qinv = _mod_inverse(q, p)
        return {"n": n, "e": e, "d": d, "p": p, "q": q, "dp": dp, "dq": dq, "qinv": qinv}


# ---------------------------------------------------------------------------
# PEM 序列化（PKCS#1 格式，与大多数工具兼容）
# ---------------------------------------------------------------------------

def _private_key_to_pem(key: dict[str, int]) -> str:
    """将 RSA 私钥编码为 PKCS#1 PEM 格式（RSAPrivateKey）。"""
    der = _der_sequence(
        _der_integer(0),           # 版本号
        _der_integer(key["n"]),
        _der_integer(key["e"]),
        _der_integer(key["d"]),
        _der_integer(key["p"]),
        _der_integer(key["q"]),
        _der_integer(key["dp"]),
        _der_integer(key["dq"]),
        _der_integer(key["qinv"]),
    )
    return _pem_encode("RSA PRIVATE KEY", der)


def _public_key_to_pem(key: dict[str, int]) -> str:
    """将 RSA 公钥编码为 PKCS#8/SubjectPublicKeyInfo PEM 格式。"""
    rsa_pub_der = _der_sequence(
        _der_integer(key["n"]),
        _der_integer(key["e"]),
    )
    spki = _der_sequence(
        _der_sequence(_der_oid(_RSA_OID), _der_null()),
        _der_bit_string(rsa_pub_der),
    )
    return _pem_encode("PUBLIC KEY", spki)


def _private_key_from_pem(pem: str) -> dict[str, int]:
    """将 PKCS#1 RSA 私钥 PEM 解析为密钥字典。"""
    der = _pem_decode(pem)
    pos = 0
    _, pos = _parse_der_sequence_header(der, pos)
    version, pos = _parse_der_integer(der, pos)
    n, pos = _parse_der_integer(der, pos)
    e, pos = _parse_der_integer(der, pos)
    d, pos = _parse_der_integer(der, pos)
    p, pos = _parse_der_integer(der, pos)
    q, pos = _parse_der_integer(der, pos)
    dp, pos = _parse_der_integer(der, pos)
    dq, pos = _parse_der_integer(der, pos)
    qinv, pos = _parse_der_integer(der, pos)
    return {"n": n, "e": e, "d": d, "p": p, "q": q, "dp": dp, "dq": dq, "qinv": qinv}


def _public_key_from_pem(pem: str) -> dict[str, int]:
    """将 SubjectPublicKeyInfo RSA 公钥 PEM 解析为密钥字典。"""
    der = _pem_decode(pem)
    pos = 0
    _, pos = _parse_der_sequence_header(der, pos)    # 外层 SEQUENCE
    _, pos = _parse_der_sequence_header(der, pos)    # AlgorithmIdentifier SEQUENCE
    # 跳过 AlgorithmIdentifier 内的 OID + NULL
    oid_len = der[pos + 1]; pos += 2 + oid_len       # OID TLV
    pos += 2                                          # NULL TLV
    # BIT STRING
    assert der[pos] == 0x03
    pos += 1
    bs_len, pos = _parse_der_length(der, pos)
    pos += 1                                          # 跳过未使用位字节 (0x00)
    _, pos = _parse_der_sequence_header(der, pos)    # RSAPublicKey SEQUENCE
    n, pos = _parse_der_integer(der, pos)
    e, _ = _parse_der_integer(der, pos)
    return {"n": n, "e": e}


# ---------------------------------------------------------------------------
# PKCS#1 v1.5 签名原语
# ---------------------------------------------------------------------------

def _pkcs1_v15_pad_sign(digest_bytes: bytes, k: int) -> bytes:
    """构建 PKCS#1 v1.5 签名 EM 块（类型 1）。

    EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo
    """
    t = _SHA256_DIGEST_INFO_PREFIX + digest_bytes
    if k < len(t) + 11:
        raise ValueError("key too short for PKCS#1 v1.5 signature")
    ps_len = k - len(t) - 3
    em = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + t
    return em


def _pkcs1_v15_verify_pad(em: bytes, k: int) -> bytes:
    """解析并验证 PKCS#1 v1.5 类型 1 EM 块，返回 DigestInfo 字节。"""
    if len(em) != k or em[0] != 0x00 or em[1] != 0x01:
        raise ValueError("invalid PKCS#1 v1.5 signature block")
    i = 2
    while i < len(em) and em[i] == 0xFF:
        i += 1
    if i < 10 or em[i] != 0x00:
        raise ValueError("invalid PKCS#1 v1.5 padding")
    return em[i + 1:]


# ---------------------------------------------------------------------------
# 基于 CRT 的私钥操作（加速签名）
# ---------------------------------------------------------------------------

def _rsa_private_op(m: int, key: dict[str, int]) -> int:
    """使用 CRT 加速的 RSA 私钥操作。"""
    p, q, dp, dq, qinv = key["p"], key["q"], key["dp"], key["dq"], key["qinv"]
    mp = _mod_pow(m % p, dp, p)
    mq = _mod_pow(m % q, dq, q)
    h = qinv * (mp - mq) % p
    return mq + h * q


def _rsa_public_op(m: int, key: dict[str, int]) -> int:
    return _mod_pow(m, key["e"], key["n"])


# ---------------------------------------------------------------------------
# 公开 API（接口与原调库版本完全一致）
# ---------------------------------------------------------------------------

def generate_key_pair(bits: int = 1024) -> tuple[str, str]:
    """生成 PEM 编码的 RSA 私钥 / 公钥对。"""
    key = _generate_rsa_key(bits)
    return _private_key_to_pem(key), _public_key_to_pem(key)


def sign_text(text: str, private_key_pem: str) -> str:
    """对文本签名，返回 Base64 RSA 签名（PKCS#1 v1.5 + SHA-256）。"""
    key = _private_key_from_pem(private_key_pem)
    k = (key["n"].bit_length() + 7) // 8
    digest = sha256_bytes(text.encode("utf-8"))
    em = _pkcs1_v15_pad_sign(digest, k)
    m = int.from_bytes(em, "big")
    s = _rsa_private_op(m, key)
    return base64.b64encode(s.to_bytes(k, "big")).decode("ascii")


def verify_text(text: str, signature_b64: str, public_key_pem: str) -> bool:
    """验证文本的 Base64 RSA PKCS#1 v1.5 签名。"""
    try:
        key = _public_key_from_pem(public_key_pem)
        k = (key["n"].bit_length() + 7) // 8
        sig_bytes = base64.b64decode(signature_b64)
        if len(sig_bytes) != k:
            return False
        s = int.from_bytes(sig_bytes, "big")
        m = _rsa_public_op(s, key)
        em = m.to_bytes(k, "big")
        digest_info = _pkcs1_v15_verify_pad(em, k)
        prefix_len = len(_SHA256_DIGEST_INFO_PREFIX)
        if digest_info[:prefix_len] != _SHA256_DIGEST_INFO_PREFIX:
            return False
        stored_digest = digest_info[prefix_len:]
        expected_digest = sha256_bytes(text.encode("utf-8"))
        return stored_digest == expected_digest
    except Exception:
        return False
