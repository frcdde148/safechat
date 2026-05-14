"""协议安全单元 smoke 测试。

运行方式：
    python tests/security_smoke.py
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from common.crypto.rsa_sign import generate_key_pair
from common.protocol.security import canonical_body, sign_body, verify_body_signature


def main() -> int:
    private_key, public_key = generate_key_pair()
    other_private_key, other_public_key = generate_key_pair()
    body = {
        "ticket_v": {"ciphertext": "abc", "iv": "123"},
        "message_cipher": {"iv": "iv", "ciphertext": "hello"},
        "recipient": "bob",
    }
    same_body_different_order = {
        "recipient": "bob",
        "message_cipher": {"ciphertext": "hello", "iv": "iv"},
        "ticket_v": {"iv": "123", "ciphertext": "abc"},
    }

    assert canonical_body(body) == canonical_body(same_body_different_order), "规范化 JSON 应与字段顺序无关"

    digest, signature = sign_body(body, private_key, "kc-v-secret")
    assert verify_body_signature(body, digest, signature, public_key, "kc-v-secret"), "正确 HMAC/签名应验证通过"

    tampered_body = dict(body)
    tampered_body["recipient"] = "carol"
    assert not verify_body_signature(tampered_body, digest, signature, public_key, "kc-v-secret"), "篡改正文必须失败"
    assert not verify_body_signature(body, "0" * 64, signature, public_key, "kc-v-secret"), "篡改 HMAC 必须失败"
    assert not verify_body_signature(body, digest, signature, public_key, "wrong-secret"), "错误 HMAC 密钥必须失败"
    assert not verify_body_signature(body, digest, signature, other_public_key, "kc-v-secret"), "错误公钥必须失败"

    other_digest, other_signature = sign_body(body, other_private_key, "kc-v-secret")
    assert not verify_body_signature(body, other_digest, other_signature, public_key, "kc-v-secret"), "错误私钥签名必须失败"

    print("[通过] 协议安全 smoke 测试完成")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
