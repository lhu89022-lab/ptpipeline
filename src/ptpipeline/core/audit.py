"""审计账本 —— 带哈希链的防篡改动作记录。

为什么要哈希链:
    渗透测试报告的争议点往往不是"发现了什么", 而是"你到底做了什么"。
    普通 JSONL 日志可以被事后编辑, 而哈希链让任何一条记录的修改都会
    导致其后所有记录的 `prev` 校验失败。这与区块链审计中的证据留存思路
    一致, 也是本项目在同类工具中最主要的差异化。

链结构:
    rec_0.prev = "0" * 64
    rec_n.prev = rec_{n-1}.hash
    rec_n.hash = sha256(canonical_json(rec_n without hash) + rec_n.prev)

只依赖标准库 hashlib / json, 无第三方依赖。
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

__all__ = ["AuditLedger", "ChainVerification", "GENESIS", "actor_identity"]

GENESIS = "0" * 64


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _canonical(record: dict[str, Any]) -> str:
    """规范化序列化: 键排序 + 紧凑分隔符 + 强制 ASCII, 保证跨平台哈希一致。"""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def actor_identity() -> str:
    """本机默认的操作者标识: `主机名#PID`, 用于区分同一次审计中的不同执行者。

    可用环境变量 `PTP_ACTOR` 覆盖。真实场景里这个覆盖是有用的: 容器与 CI 的主机名
    往往是一次性的随机串, 把它写进证据链反而让同一执行者无法归并; 值班轮转时也可以
    固定成岗位标识。发布演示账本时同样用它, 避免把本机主机名带进公开仓库。
    """
    override = os.environ.get("PTP_ACTOR", "").strip()
    if override:
        return override
    return f"{socket.gethostname()}#{os.getpid()}"


@dataclass(slots=True)
class ChainVerification:
    """账本完整性校验结果。"""

    ok: bool
    records: int
    broken_at: int | None = None
    reason: str = ""
    head_hash: str = GENESIS
    first_ts: str = ""
    last_ts: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "records": self.records,
            "broken_at": self.broken_at,
            "reason": self.reason,
            "head_hash": self.head_hash,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
        }


@dataclass(slots=True)
class AuditLedger:
    """追加写 + 哈希链的审计账本。

    strict=True (默认): 续写已损坏的账本会直接抛错 —— 保护写入路径,
        绝不把新记录接到一条已经不可信的链上。
    strict=False: 只读/取证模式, 允许打开损坏的账本以定位断链位置。
    """

    path: Path
    algorithm: str = "sha256"
    redact: bool = True
    strict: bool = True
    _counter: int = field(default=0, init=False, repr=False)
    _head: str = field(default=GENESIS, init=False, repr=False)
    _broken: ChainVerification | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.algorithm != "sha256":
            raise ValueError("only sha256 is supported")
        # 续写已有账本时, 必须承接其链头, 否则链断裂
        if self.path.exists() and self.path.stat().st_size > 0:
            state = self.verify()
            if not state.ok:
                self._broken = state
                if self.strict:
                    raise ValueError(
                        "refusing to append to a broken ledger "
                        f"(broken_at={state.broken_at}: {state.reason})"
                    )
                return
            self._counter = state.records
            self._head = state.head_hash

    @property
    def broken(self) -> ChainVerification | None:
        """若账本在打开时已被判定损坏, 返回当时的校验结果 (取证模式)。"""
        return self._broken

    # -- 读取 ------------------------------------------------------------- #

    def _iter_raw(self) -> Iterator[tuple[int, dict[str, Any]]]:
        with self.path.open("r", encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"line {lineno} is not valid JSON: {exc}") from exc
                if not isinstance(record, dict):
                    raise ValueError(f"line {lineno} is not a JSON object")
                yield lineno, record

    def records(self) -> list[dict[str, Any]]:
        return [record for _, record in self._iter_raw()]

    # -- 写入 ------------------------------------------------------------- #

    def append(
        self,
        *,
        mode: str,
        target: str,
        action: str,
        verdict: str,
        reason: str = "",
        matched_rule: str = "",
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """追加一条审计记录, 返回落盘后的完整记录 (含 hash)。"""
        if self._broken is not None:
            raise ValueError(
                "ledger is broken; refusing to append "
                f"(broken_at={self._broken.broken_at}: {self._broken.reason})"
            )
        body: dict[str, Any] = {
            "seq": self._counter,
            "ts": _utc_now_iso(),
            "actor": actor_identity(),
            "mode": mode,
            "target": target,
            "action": action,
            "verdict": verdict,
            "reason": reason,
            "matched_rule": matched_rule,
            "prev": self._head,
        }
        if extra:
            body["extra"] = extra

        digest = _sha256(_canonical(body) + self._head)
        record = {**body, "hash": digest}

        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(_canonical(record) + "\n")

        self._counter += 1
        self._head = digest
        return record

    def record_decision(self, decision: Any, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        """直接把 core.scope.Decision 落账。"""
        fields = decision.as_audit_fields()
        return self.append(**fields, extra=extra)

    # -- 校验 ------------------------------------------------------------- #

    def verify(self) -> ChainVerification:
        """逐条重算哈希链。任何一处被篡改都会在 broken_at 指明位置。"""
        if not self.path.exists():
            return ChainVerification(ok=True, records=0, head_hash=GENESIS)

        count = 0
        head = GENESIS
        first_ts = last_ts = ""
        try:
            for lineno, record in self._iter_raw():
                expected_prev = head
                actual_prev = record.get("prev")
                if actual_prev != expected_prev:
                    return ChainVerification(
                        False, count, lineno,
                        f"prev mismatch: expected {expected_prev[:12]}… got {str(actual_prev)[:12]}…",
                        head, first_ts, last_ts,
                    )
                claimed = record.get("hash")
                body = {key: value for key, value in record.items() if key != "hash"}
                recomputed = _sha256(_canonical(body) + expected_prev)
                if claimed != recomputed:
                    return ChainVerification(
                        False, count, lineno,
                        f"hash mismatch at seq={record.get('seq')}: content was modified after write",
                        head, first_ts, last_ts,
                    )
                head = str(claimed)
                count += 1
                if lineno and not first_ts:
                    first_ts = str(record.get("ts", ""))
                last_ts = str(record.get("ts", ""))
        except ValueError as exc:
            return ChainVerification(False, count, None, str(exc), head, first_ts, last_ts)

        return ChainVerification(True, count, None, "", head, first_ts, last_ts)

    # -- 便捷统计 --------------------------------------------------------- #

    def summary(self) -> dict[str, Any]:
        total = allow = deny = 0
        by_action: dict[str, int] = {}
        for record in self.records():
            total += 1
            verdict = record.get("verdict")
            if verdict == "allow":
                allow += 1
            elif verdict == "deny":
                deny += 1
            action = str(record.get("action", ""))
            by_action[action] = by_action.get(action, 0) + 1
        return {"total": total, "allow": allow, "deny": deny, "by_action": by_action}
