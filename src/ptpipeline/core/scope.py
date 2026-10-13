"""授权范围守卫 —— 本项目的核心不变量。

设计原则: **授权范围不是一个文档, 而是一段可执行、可测试、可审计的代码。**

本模块刻意只依赖 Python 标准库, 目的是让任何人在任何机器上
`git clone` 后无需安装依赖即可 `python -m ptpipeline doctor` 自验。

合规边界:
    - 本模块只做"判断是否放行", 不具备任何扫描、利用、爆破能力。
    - 所有目标以 RFC1918 私有地址 / 回环 / 用户自建靶场为前提。
    - 拒绝行为本身也会被记录, 用于证明"工具尝试越过边界时被拦下"。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

__all__ = [
    "Decision",
    "Guard",
    "ManifestError",
    "Request",
    "load_manifest",
]

# --------------------------------------------------------------------------- #
# 错误类型
# --------------------------------------------------------------------------- #


class ManifestError(ValueError):
    """授权声明文件缺失关键字段或格式非法时抛出。"""


# --------------------------------------------------------------------------- #
# 数据结构
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Decision:
    """一次范围判定的结果, 可与审计记录直接互转。"""

    allowed: bool
    mode: str
    target: str
    action: str
    reason: str
    matched_rule: str = ""

    def as_audit_fields(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "target": self.target,
            "action": self.action,
            "verdict": "allow" if self.allowed else "deny",
            "reason": self.reason,
            "matched_rule": self.matched_rule,
        }


@dataclass(frozen=True, slots=True)
class Request:
    """一个待授权的出站动作。经由 Guard.check() 之后才允许执行。"""

    mode: str
    target: str
    action: str
    # 附带上下文, 例如 HTTP 方法、端口; 仅用于审计留痕
    context: dict[str, Any] | None = None


# --------------------------------------------------------------------------- #
# 目标解析
# --------------------------------------------------------------------------- #

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _classify(target: str) -> tuple[str, str]:
    """把一个目标归一化为 ('url'|'ip'|'host', 可比较的值)。

    返回值第二个元素对 ip 是规范化字符串, 对 host 是小写去尾点的主机名,
    对 url 是 (主机, 路径)。
    """
    raw = (target or "").strip()
    if not raw:
        raise ValueError("target is empty")

    if "://" in raw:
        parts = urlsplit(raw)
        if not parts.hostname:
            raise ValueError(f"malformed URL: {raw!r}")
        return "url", f"{parts.hostname.lower()}|{parts.path or '/'}"

    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]  # IPv6 字面量

    if _IPV4_RE.match(raw) or ":" in raw:
        return "ip", str(ipaddress.ip_address(raw))

    return "host", raw.rstrip(".").lower()


def _host_in_domain(host: str, rule: str) -> bool:
    """域名规则匹配。

    规则以 '.' 开头 -> 匹配该域自身及其全部子域 (".lab.internal" 匹配
    "lab.internal" 与 "a.lab.internal")
    否则 -> 仅精确匹配
    """
    rule = rule.strip().lower().rstrip(".")
    if not rule:
        return False
    if rule.startswith("."):
        base = rule[1:]
        return host == base or host.endswith("." + base)
    return host == rule


def _ip_in_ranges(ip_str: str, ranges: list[str]) -> str:
    """返回命中的网段字符串, 未命中返回空串。"""
    addr = ipaddress.ip_address(ip_str)
    for entry in ranges:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        # 禁止用 IPv4 网段去匹配 IPv6 地址 (版本不同不能比较)
        if net.version != addr.version:
            continue
        if addr in net:
            return entry
    return ""


def _utc_iso(moment: datetime) -> str:
    """统一的 UTC 展示格式: 2026-01-01T00:00:00Z。"""
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_utc(text: str) -> datetime:
    """解析 ISO8601 时间, 兼容结尾的 'Z'。"""
    value = (text or "").strip()
    if not value:
        raise ManifestError("timestamp is empty")
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# 极简 YAML 读取
# --------------------------------------------------------------------------- #
# 刻意不引入 PyYAML: 目标是零依赖。支持的能力恰好覆盖本项目所需的
# "两层嵌套 + 标量 + 字符串列表" 结构, 不支持锚点/多行块/流式映射。


def _strip_comment(line: str) -> str:
    """去掉行内注释, 但不破坏引号内的 '#'。"""
    in_single = in_double = False
    for idx, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:idx]
    return line


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _coerce(value: str) -> Any:
    text = _unquote(value)
    low = text.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~", ""):
        return None
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?\d+\.\d+", text):
        return float(text)
    return text


def _parse_scalar_or_list(value: str) -> Any:
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_coerce(item) for item in inner.split(",")]
    return _coerce(value)


def _parse_block(lines: list[str], index: int, indent: int) -> tuple[dict[str, Any], int]:
    """递归下降解析一个缩进层级, 返回 (映射, 下一个待处理行号)。"""
    result: dict[str, Any] = {}
    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()
        if not stripped:
            index += 1
            continue

        current_indent = len(raw) - len(raw.lstrip(" "))
        if current_indent < indent:
            break
        if current_indent > indent:
            # 多余的缩进属于上一个 key, 但上一个 key 已被消费 -> 跳过
            index += 1
            continue

        if stripped.startswith("- "):
            # 裸列表项出现在映射位置, 视为非法, 跳过
            index += 1
            continue

        if ":" not in stripped:
            index += 1
            continue

        key, _, rest = stripped.partition(":")
        key = key.strip()
        rest = rest.strip()
        index += 1

        if rest:
            result[key] = _parse_scalar_or_list(rest)
            continue

        # 值为空 -> 可能是嵌套映射, 也可能是列表
        child_lines: list[str] = []
        probe = index
        while probe < len(lines):
            candidate = lines[probe]
            if not candidate.strip():
                probe += 1
                continue
            cand_indent = len(candidate) - len(candidate.lstrip(" "))
            if cand_indent <= indent:
                break
            child_lines.append(candidate)
            probe += 1

        if not child_lines:
            result[key] = None
            continue

        first = child_lines[0].strip()
        if first.startswith("- "):
            items: list[Any] = []
            for item_line in child_lines:
                item = item_line.strip()
                if not item.startswith("- "):
                    continue
                items.append(_coerce(item[2:]))
            result[key] = items
            index = probe
        else:
            nested, consumed = _parse_block(child_lines, 0, len(child_lines[0]) - len(child_lines[0].lstrip(" ")))
            result[key] = nested
            index = probe
            del consumed
    return result, index


def parse_manifest_text(text: str) -> dict[str, Any]:
    """把授权声明的文本解析成嵌套字典。"""
    lines = [_strip_comment(line) for line in text.splitlines()]
    data, _ = _parse_block(lines, 0, 0)
    return data


def load_manifest(path: str | Path) -> dict[str, Any]:
    """读取并校验授权声明文件。"""
    file_path = Path(path)
    if not file_path.is_file():
        raise ManifestError(f"manifest not found: {file_path}")
    data = parse_manifest_text(file_path.read_text(encoding="utf-8"))

    for section in ("authorization", "scope"):
        if not isinstance(data.get(section), dict):
            raise ManifestError(f"missing required section: {section!r}")

    scope = data["scope"]
    if not scope.get("domains") and not scope.get("ip_ranges") and not scope.get("url_prefixes"):
        raise ManifestError(
            "scope is empty: declare at least one of domains / ip_ranges / url_prefixes"
        )

    auth = data["authorization"]
    for field in ("window_start", "window_end"):
        if not auth.get(field):
            raise ManifestError(f"authorization.{field} is required (UTC ISO8601)")
    try:
        _parse_utc(str(auth["window_start"]))
        _parse_utc(str(auth["window_end"]))
    except ValueError as exc:
        raise ManifestError(f"authorization window is not valid ISO8601: {exc}") from exc

    return data


# --------------------------------------------------------------------------- #
# 守卫
# --------------------------------------------------------------------------- #


class Guard:
    """授权范围守卫。所有出站动作的唯一入口。"""

    def __init__(self, manifest: dict[str, Any]) -> None:
        self.manifest = manifest
        self.auth: dict[str, Any] = manifest["authorization"]
        self.scope: dict[str, Any] = manifest["scope"]
        self.domains: list[str] = list(self.scope.get("domains") or [])
        self.ip_ranges: list[str] = list(self.scope.get("ip_ranges") or [])
        self.url_prefixes: list[str] = list(self.scope.get("url_prefixes") or [])
        self.exclusions: list[str] = list(self.scope.get("exclusions") or [])
        self.allow_actions: set[str] = {str(a) for a in (self.scope.get("allow_actions") or [])}
        rate = self.scope.get("rate_limit") or {}
        self.rate_limit: dict[str, Any] = dict(rate)
        self.window_start = _parse_utc(str(self.auth["window_start"]))
        self.window_end = _parse_utc(str(self.auth["window_end"]))

    # -- 供外部展示 ------------------------------------------------------- #

    def describe(self) -> dict[str, Any]:
        allowed = sorted(self.allow_actions)
        unimplemented = [
            a for a in ("exploit", "brute_force", "packet_capture", "denial_of_service")
            if a not in allowed
        ]
        return {
            "engagement": self.auth.get("engagement"),
            "client": self.auth.get("client"),
            "contract_ref": self.auth.get("contract_ref"),
            "window": f"{_utc_iso(self.window_start)} .. {_utc_iso(self.window_end)}",
            "window_open": self.window_is_open(),
            "domains": self.domains,
            "ip_ranges": self.ip_ranges,
            "url_prefixes": self.url_prefixes,
            "exclusions": self.exclusions,
            "allow_actions": allowed,
            "rate_limit": self.rate_limit,
            "not_implemented_by_design": unimplemented,
        }

    def window_is_open(self, now: datetime | None = None) -> bool:
        moment = now or _now_utc()
        return self.window_start <= moment <= self.window_end

    # -- 核心判定 --------------------------------------------------------- #

    def check(self, request: Request, now: datetime | None = None) -> Decision:
        """判定一个出站动作是否被授权。**永不抛异常**, 一律返回判定结果。"""
        moment = now or _now_utc()

        def deny(reason: str, rule: str = "") -> Decision:
            return Decision(False, request.mode, request.target, request.action, reason, rule)

        # 1) 时间窗
        if not (self.window_start <= moment <= self.window_end):
            return deny(
                f"outside authorized window ({self.window_start.isoformat()} .. {self.window_end.isoformat()})",
                "authorization.window",
            )

        # 2) 动作白名单 —— 未实现的动作也在这里被挡下
        if request.action not in self.allow_actions:
            return deny(
                f"action {request.action!r} is not in allow_actions",
                "scope.allow_actions",
            )

        # 3) 目标解析
        try:
            kind, normalized = _classify(request.target)
        except ValueError as exc:
            return deny(f"unparsable target: {exc}", "scope")

        host = normalized.split("|", 1)[0]

        # 目标可能是 IP 字面量 (裸 IP, 或 http://10.0.0.5/ 这类 URL)。
        # 只要能解析成 IP, 就必须走网段校验, 而不是域名匹配 —— 否则
        # "http://127.0.0.1/" 会因为 '127.0.0.1' 不属于任何 domain 规则而被误拒。
        literal_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
        try:
            if _IPV4_RE.match(host) or ":" in host:
                literal_ip = ipaddress.ip_address(host)
        except ValueError:
            literal_ip = None

        # 4) 排除项优先于任何 allow 规则
        for entry in self.exclusions:
            candidate = str(entry).strip()
            if not candidate:
                continue
            if candidate.startswith(".") or not _IPV4_RE.match(candidate.lstrip(".")):
                if kind in ("host", "url") and _host_in_domain(host, candidate):
                    return deny(f"target matched exclusion {candidate!r}", f"exclusion:{candidate}")
            try:
                net = ipaddress.ip_network(candidate, strict=False)
            except ValueError:
                continue
            try:
                addr = ipaddress.ip_address(host)
            except ValueError:
                continue
            if net.version == addr.version and addr in net:
                return deny(f"target matched exclusion {candidate!r}", f"exclusion:{candidate}")

        # 5) URL 前缀 (若声明了, 则必须先命中前缀)
        if self.url_prefixes:
            raw = request.target.strip()
            for prefix in self.url_prefixes:
                if raw.startswith(str(prefix)):
                    return Decision(True, request.mode, request.target, request.action,
                                    "matched url_prefixes", f"url_prefixes:{prefix}")
            if kind == "url":
                return deny("URL did not match any url_prefixes entry", "scope.url_prefixes")

        # 6) IP 字面量目标 (含 URL 中的 IP 主机名)
        if literal_ip is not None:
            hit = _ip_in_ranges(str(literal_ip), self.ip_ranges)
            if hit:
                return Decision(True, request.mode, request.target, request.action,
                                "IP literal inside authorized range", f"ip_ranges:{hit}")
            return deny("IP outside all authorized ranges", "scope.ip_ranges")

        # 7) 域名目标
        for rule in self.domains:
            if _host_in_domain(host, str(rule)):
                return Decision(True, request.mode, request.target, request.action,
                                "host inside authorized domain", f"domains:{rule}")

        return deny("host outside all authorized domains", "scope.domains")
