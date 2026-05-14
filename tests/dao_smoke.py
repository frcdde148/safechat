"""SQLite DAO smoke 测试。

运行方式：
    python tests/dao_smoke.py
"""

from __future__ import annotations

import tempfile
import time
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from database.dao.sqlite_dao import SQLiteDAO
from database.init_db import init_database


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="safechat-dao-", ignore_cleanup_errors=True) as tmp:
        db_path = Path(tmp) / "chat.db"
        init_database(db_path, "chat")
        dao = SQLiteDAO(db_path=db_path)

        _test_history_paging(dao)
        _test_private_permissions(dao)
        _test_mute_rules(dao)
        _test_session_revocation(dao)

    print("[通过] DAO smoke 测试完成")
    return 0


def _test_history_paging(dao: SQLiteDAO) -> None:
    ids = []
    for idx in range(5):
        ids.append(
            dao.store_chat_message(
                sender="alice",
                recipient="",
                chat_type="group",
                session_key="group:public",
                message_text=f"group-{idx}",
            )
        )

    latest = dao.list_chat_messages("group:public", 0, "alice", limit=2, latest=True)
    assert [item["id"] for item in latest] == ids[-2:], "latest=True 应返回最近 N 条并保持正序"

    incremental = dao.list_chat_messages("group:public", ids[2], "alice", limit=10)
    assert [item["id"] for item in incremental] == ids[3:], "after_id 增量查询结果不正确"


def _test_private_permissions(dao: SQLiteDAO) -> None:
    message_id = dao.store_chat_message(
        sender="alice",
        recipient="bob",
        chat_type="private",
        session_key="private:alice:bob",
        message_text="private-message",
    )

    alice_view = dao.list_chat_messages("private:alice:bob", 0, "alice")
    bob_view = dao.list_chat_messages("private:alice:bob", 0, "bob")
    carol_view = dao.list_chat_messages("private:alice:bob", 0, "carol")

    assert any(item["id"] == message_id for item in alice_view), "私聊发送者应能读取消息"
    assert any(item["id"] == message_id for item in bob_view), "私聊接收者应能读取消息"
    assert not carol_view, "非私聊参与者不应读取消息"


def _test_mute_rules(dao: SQLiteDAO) -> None:
    expires_at = int(time.time() * 1000) + 60_000
    rule_id = dao.add_mute_rule("user", "alice", "admin", expires_at, reason="dao test")
    active = dao.get_active_mute("user", "alice")
    assert active and active["id"] == rule_id, "应能读取有效禁言规则"

    affected = dao.revoke_mute_rule("user", "alice")
    assert affected == 1, "撤销禁言应影响一条记录"
    assert dao.get_active_mute("user", "alice") is None, "撤销后不应再有有效禁言"


def _test_session_revocation(dao: SQLiteDAO) -> None:
    revocation_id = dao.add_session_revocation("bob", "admin", "dao test")
    active = dao.get_active_session_revocation("bob")
    assert active and active["id"] == revocation_id, "应能读取有效会话撤销记录"

    cleared = dao.clear_session_revocations("bob")
    assert cleared == 1, "清理会话撤销应影响一条记录"
    assert dao.get_active_session_revocation("bob") is None, "清理后不应再有有效撤销记录"


if __name__ == "__main__":
    raise SystemExit(main())
