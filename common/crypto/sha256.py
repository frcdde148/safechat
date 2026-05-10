"""SHA-256 digest helpers - 纯 Python 实现 (本科生水平)

参考 FIPS 180-4 标准实现：
- 消息填充规则
- 64 轮压缩函数
- 8 个初始哈希值
- 64 个常量（前64个素数的立方根小数部分）
"""

from __future__ import annotations

import os


# ==========================
# SHA-256 常量定义
# ==========================

# 初始哈希值（前8个素数的平方根小数部分取前32位）
_INITIAL_HASH = [
    0x6A09E667,  # sqrt(2)
    0xBB67AE85,  # sqrt(3)
    0x3C6EF372,  # sqrt(5)
    0xA54FF53A,  # sqrt(7)
    0x510E527F,  # sqrt(11)
    0x9B05688C,  # sqrt(13)
    0x1F83D9AB,  # sqrt(17)
    0x5BE0CD19,  # sqrt(19)
]

# 64 个常量（前64个素数的立方根小数部分取前32位）
_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


# ==========================
# 辅助函数
# ==========================

def _right_rotate(n: int, bits: int) -> int:
    """32位循环右移"""
    return ((n >> bits) | (n << (32 - bits))) & 0xFFFFFFFF


def _right_shift(n: int, bits: int) -> int:
    """32位逻辑右移"""
    return n >> bits


# ==========================
# 单块压缩函数
# ==========================

def _compress_block(block: bytes, h: list[int]) -> list[int]:
    """处理一个 512 位的消息块，更新哈希值"""
    
    # 将 64 字节块拆分为 16 个 32 位字
    w = [0] * 64
    for i in range(16):
        w[i] = int.from_bytes(block[i*4 : (i+1)*4], 'big')
    
    # 扩展为 64 个 32 位字
    for i in range(16, 64):
        s0 = _right_rotate(w[i-15], 7) ^ _right_rotate(w[i-15], 18) ^ _right_shift(w[i-15], 3)
        s1 = _right_rotate(w[i-2], 17) ^ _right_rotate(w[i-2], 19) ^ _right_shift(w[i-2], 10)
        w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF
    
    # 初始化工作变量
    a, b, c, d, e, f, g, hh = h
    
    # 64 轮压缩
    for i in range(64):
        s1 = _right_rotate(e, 6) ^ _right_rotate(e, 11) ^ _right_rotate(e, 25)
        ch = (e & f) ^ (~e & g)
        temp1 = (hh + s1 + ch + _K[i] + w[i]) & 0xFFFFFFFF
        
        s0 = _right_rotate(a, 2) ^ _right_rotate(a, 13) ^ _right_rotate(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (s0 + maj) & 0xFFFFFFFF
        
        # 轮换
        hh = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF
    
    # 更新哈希值
    return [
        (h[0] + a) & 0xFFFFFFFF,
        (h[1] + b) & 0xFFFFFFFF,
        (h[2] + c) & 0xFFFFFFFF,
        (h[3] + d) & 0xFFFFFFFF,
        (h[4] + e) & 0xFFFFFFFF,
        (h[5] + f) & 0xFFFFFFFF,
        (h[6] + g) & 0xFFFFFFFF,
        (h[7] + hh) & 0xFFFFFFFF,
    ]


# ==========================
# 主哈希函数
# ==========================

def sha256_bytes(data: bytes) -> bytes:
    """计算 SHA-256 哈希值，返回原始字节"""
    
    # 消息填充规则：
    # 1. 添加一个 '1' 位（0x80）
    # 2. 添加 '0' 位，使总长度模 512 = 448（即模 64 = 56）
    # 3. 添加原始长度（64位，大端序）
    original_length = len(data) * 8  # 位长度
    
    # 计算需要的填充 0 字节数（已包含 0x80 这一个字节）
    padding_length = (55 - (len(data) % 64)) % 64
    
    # 构造填充后的消息
    padded = data + b'\x80'  # 添加 '1' 位
    padded += b'\x00' * padding_length  # 添加 '0' 位
    padded += original_length.to_bytes(8, 'big')  # 添加原始长度（大端序）
    
    # 初始化哈希值
    h = _INITIAL_HASH.copy()
    
    # 分块处理（每块 64 字节 = 512 位）
    for i in range(0, len(padded), 64):
        block = padded[i:i+64]
        h = _compress_block(block, h)
    
    # 将哈希值转换为字节
    return b''.join(word.to_bytes(4, 'big') for word in h)


def sha256_hex(data: bytes) -> str:
    """计算 SHA-256 哈希值，返回十六进制字符串"""
    return sha256_bytes(data).hex()


# ==========================
# 项目辅助函数
# ==========================

def new_salt_hex(size: int = 32) -> str:
    """生成随机盐值（十六进制）"""
    return os.urandom(size).hex()


def salted_password_hash(password: str, salt_hex: str) -> str:
    """带盐密码哈希：SHA-256(salt + password)"""
    salt = bytes.fromhex(salt_hex)
    return sha256_hex(salt + password.encode('utf-8'))


def verify_password(password: str, salt_hex: str, expected_hash: str) -> bool:
    """验证密码是否正确（安全比较）"""
    computed = salted_password_hash(password, salt_hex)
    
    # 安全比较（防止时序攻击）
    if len(computed) != len(expected_hash):
        return False
    
    result = 0
    for a, b in zip(computed, expected_hash):
        result |= ord(a) ^ ord(b)
    
    return result == 0


# ==========================
# HMAC-SHA256 实现
# ==========================

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """计算 HMAC-SHA256"""
    # HMAC 常量
    IPAD = 0x36
    OPAD = 0x5C
    BLOCK_SIZE = 64  # SHA-256 使用 64 字节块
    
    # 如果密钥长度 > 64，先哈希
    if len(key) > BLOCK_SIZE:
        key = sha256_bytes(key)
    
    # 填充密钥到 64 字节
    key_padded = key + b'\x00' * (BLOCK_SIZE - len(key))
    
    # 计算 inner 和 outer
    inner = bytes(x ^ IPAD for x in key_padded) + message
    inner_hash = sha256_bytes(inner)
    
    outer = bytes(x ^ OPAD for x in key_padded) + inner_hash
    return sha256_bytes(outer)


def hmac_compare_digest(a: str, b: str) -> bool:
    """安全比较两个字符串（防止时序攻击）"""
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    
    return result == 0


# ==========================
# 测试函数（可选）
# ==========================

def _test_sha256():
    """简单测试 SHA-256 实现是否正确"""
    test_cases = [
        (b'', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
        (b'abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
        (b'Hello, World!', 'dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f'),
    ]
    
    print("SHA-256 测试：")
    all_pass = True
    for data, expected in test_cases:
        computed = sha256_hex(data)
        if computed == expected:
            print(f"  PASS: {data[:20]!r}")
        else:
            print(f"  FAIL: {data[:20]!r}")
            print(f"    Expected: {expected}")
            print(f"    Got:      {computed}")
            all_pass = False
    
    if all_pass:
        print("所有测试通过！")


if __name__ == '__main__':
    _test_sha256()
