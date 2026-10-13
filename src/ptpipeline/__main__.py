"""命令行入口。

四个子命令刻意保持最小:
    doctor  自检: 证明范围守卫与哈希链按预期工作 (无需网络)
    scope   查看/校验授权声明, 拒绝任何"范围为空"的松散配置
    audit   校验审计账本完整性, 并演示篡改检测
    probe   在授权范围内对目标做非侵入式配置检测, 全程落账并产出证据包
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .checks.probe import Finding, RawResponse, analyze, probe_once, run_probe_plan
from .core.audit import AuditLedger
from .core.scope import Guard, ManifestError, Request, load_manifest

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = REPO_ROOT / "scope" / "manifest.example.yaml"
DEFAULT_LEDGER = REPO_ROOT / "evidence" / "audit-ledger.jsonl"
BANNER = "ptpipeline — 授权范围内的渗透测试流程与证据链平台"


# --------------------------------------------------------------------------- #
# 输出helpers
# --------------------------------------------------------------------------- #


def _rule(title: str = "") -> None:
    line = "─" * 68
    print(line if not title else f"{title}\n{line}")


def _ok(text: str) -> None:
    print(f"  [PASS] {text}")


def _bad(text: str) -> None:
    print(f"  [FAIL] {text}")


def _load_guard(manifest_path: Path) -> Guard:
    return Guard(load_manifest(manifest_path))


# --------------------------------------------------------------------------- #
# doctor
# --------------------------------------------------------------------------- #


def cmd_doctor(args: argparse.Namespace) -> int:
    _rule(BANNER)
    print(f"python : {sys.version.split()[0]}")
    print(f"version: {__version__}")
    failures = 0

    print("\n[1/4] 加载授权声明")
    try:
        guard = _load_guard(args.manifest)
        info = guard.describe()
        _ok(f"manifest 合法: {args.manifest}")
        print(f"       委托: {info['engagement']} | 凭据: {info['contract_ref']}")
        print(f"       时间窗: {info['window']} (open={info['window_open']})")
    except ManifestError as exc:
        _bad(f"manifest 不合法: {exc}")
        return 1

    print("\n[2/4] 范围守卫: 越界目标必须被拒绝")
    negative_cases = [
        ("evil.example.com", "dns_resolve", "公网域名"),
        ("8.8.8.8", "tcp_connect", "公网 IP"),
        ("172.16.5.5", "tcp_connect", "未声明的私有网段"),
        ("10.0.0.1", "tcp_connect", "排除清单内的主机"),
        ("127.0.0.1", "exploit", "未在 allow_actions 中的动作"),
    ]
    for target, action, why in negative_cases:
        decision = guard.check(Request("doctor", target, action))
        if decision.allowed:
            _bad(f"{target} ({why}) 被错误放行")
            failures += 1
        else:
            _ok(f"{target:22s} 已拒绝 -> {decision.reason}")

    print("\n[3/4] 范围守卫: 授权内目标必须被放行")
    positive_cases = [
        ("127.0.0.1", "tcp_connect"),
        ("localhost", "dns_resolve"),
        ("10.20.30.40", "http_request"),
        ("http://127.0.0.1:8080/", "http_request"),
    ]
    for target, action in positive_cases:
        decision = guard.check(Request("doctor", target, action))
        if decision.allowed:
            _ok(f"{target:22s} 已放行 -> {decision.matched_rule}")
        else:
            _bad(f"{target} 被错误拒绝: {decision.reason}")
            failures += 1

    print("\n[4/4] 审计账本: 哈希链完整性 + 篡改检测")
    scratch = REPO_ROOT / "evidence" / "_doctor-scratch.jsonl"
    scratch.unlink(missing_ok=True)
    ledger = AuditLedger(scratch)
    ledger.append(mode="doctor", target="127.0.0.1", action="tcp_connect",
                  verdict="allow", reason="self-test", matched_rule="ip_ranges:127.0.0.0/8")
    ledger.append(mode="doctor", target="evil.example.com", action="dns_resolve",
                  verdict="deny", reason="host outside all authorized domains",
                  matched_rule="scope.domains")

    state = ledger.verify()
    if state.ok and state.records == 2:
        _ok(f"链完整, 2 条记录, head={state.head_hash[:16]}…")
    else:
        _bad(f"链校验失败: {state.reason}")
        failures += 1

    lines = scratch.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["target"] = "10.99.99.99"  # 事后篡改第一条记录的目标
    destroyed = [json.dumps(tampered, sort_keys=True, separators=(",", ":"), ensure_ascii=True)]
    destroyed.extend(lines[1:])
    scratch.write_text("\n".join(destroyed) + "\n", encoding="utf-8", newline="\n")

    state = AuditLedger(scratch, strict=False).verify()
    if not state.ok and state.broken_at == 1:
        _ok(f"篡改被检出: broken_at=line {state.broken_at} -> {state.reason}")
    else:
        _bad(f"篡改未被检出 (broken_at={state.broken_at}) —— 哈希链实现有缺陷")
        failures += 1

    try:
        AuditLedger(scratch, strict=False).append(
            mode="doctor", target="127.0.0.1", action="tcp_connect", verdict="allow")
        _bad("已损坏的账本仍被允许追加写入 —— 写入保护失效")
        failures += 1
    except ValueError:
        _ok("写入保护生效: 拒绝向已损坏的账本追加新记录")

    scratch.unlink(missing_ok=True)

    print()
    _rule()
    if failures:
        print(f"自检失败: {failures} 项未通过")
        return 1
    print("自检全部通过。范围守卫与审计账本行为符合预期。")
    print("合规提示: 本工具仅用于你本人拥有或已获书面授权的目标。")
    return 0


# --------------------------------------------------------------------------- #
# scope
# --------------------------------------------------------------------------- #


def cmd_scope(args: argparse.Namespace) -> int:
    try:
        guard = _load_guard(args.manifest)
    except (ManifestError, ValueError) as exc:
        print(f"[FAIL] 无法加载授权声明: {exc}")
        return 2

    info = guard.describe()
    if args.json:
        print(json.dumps(info, indent=2, ensure_ascii=False))
        return 0 if info["window_open"] else 1

    _rule(f"授权声明: {args.manifest}")
    print(f"  委托主体      : {info['engagement']} ({info['client']})")
    print(f"  授权凭据编号  : {info['contract_ref']}")
    print(f"  测试时间窗     : {info['window']}")
    print(f"  时间窗当前状态 : {'开放' if info['window_open'] else '已关闭 —— 所有动作将被拒绝'}")
    print(f"  允许域名       : {', '.join(info['domains']) or '(无)'}")
    print(f"  允许 IP 网段   : {', '.join(info['ip_ranges']) or '(无)'}")
    print(f"  允许 URL 前缀  : {', '.join(info['url_prefixes']) or '(未限制)'}")
    print(f"  排除项         : {', '.join(info['exclusions']) or '(无)'}")
    print(f"  允许动作       : {', '.join(info['allow_actions']) or '(无)'}")
    print(f"  未实现动作     : {', '.join(info['not_implemented_by_design'])}")
    print(f"  速率限制       : {info['rate_limit'] or '(未设置)'}")

    if args.target:
        decision = guard.check(Request("scope", args.target, args.action))
        print()
        verdict = "ALLOW" if decision.allowed else "DENY"
        print(f"  判定: {args.target} / {args.action} -> {verdict}")
        print(f"        理由: {decision.reason}")
        if decision.matched_rule:
            print(f"        命中: {decision.matched_rule}")
        return 0 if decision.allowed else 1
    return 0 if info["window_open"] else 1


# --------------------------------------------------------------------------- #
# audit
# --------------------------------------------------------------------------- #


def cmd_audit(args: argparse.Namespace) -> int:
    ledger_path = Path(args.ledger)
    _rule(f"审计账本: {ledger_path}")

    if not ledger_path.exists():
        print("  账本尚不存在 —— 先执行 `probe` 生成记录。")
        return 0

    ledger = AuditLedger(ledger_path, strict=False)
    state = ledger.verify()
    summary = ledger.summary()

    print(f"  记录条数   : {summary['total']}")
    if not state.ok:
        print(f"  可链式验证 : {state.records} 条 —— 其后断链, 这几条不再可信")
    print(f"  允许 / 拒绝: {summary['allow']} / {summary['deny']}")
    print(f"  时间范围   : {state.first_ts or '(空)'} .. {state.last_ts or '(空)'}")
    print(f"  链头哈希   : {state.head_hash}")
    if summary["by_action"]:
        detail = ", ".join(f"{k}={v}" for k, v in sorted(summary["by_action"].items()))
        print(f"  动作分布   : {detail}")

    print()
    if state.ok:
        print("  完整性: OK —— 全部记录的哈希链连续且未被修改。")
    else:
        print(f"  完整性: BROKEN —— 第 {state.broken_at} 行: {state.reason}")
        print("  这意味着账本在该行之后被编辑过, 证据链已不可信。")

    if args.show:
        print()
        _rule("记录明细")
        for record in ledger.records():
            print(f"  #{record.get('seq'):>3} {record.get('ts')} "
                  f"{record.get('verdict').upper():5s} {record.get('action'):14s} "
                  f"{record.get('target')}")
            if record.get("reason"):
                print(f"        └─ {record['reason']}")
    return 0 if state.ok else 1


# --------------------------------------------------------------------------- #
# probe
# --------------------------------------------------------------------------- #


def _severity_badge(severity: str) -> str:
    return {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW ", "info": "INFO"}.get(severity, "????")


def cmd_probe(args: argparse.Namespace) -> int:
    try:
        guard = _load_guard(args.manifest)
    except (ManifestError, ValueError) as exc:
        print(f"[FAIL] 无法加载授权声明: {exc}")
        return 2

    decision = guard.check(Request("probe", args.url, "http_request"))
    _rule(f"目标: {args.url}")
    verdict = "ALLOW" if decision.allowed else "DENY"
    print(f"  范围判定: {verdict} —— {decision.reason}")
    if not decision.allowed:
        print("\n  已按授权边界终止, 未发起任何网络请求。")
        if decision.reason.startswith("outside authorized window"):
            print("  提示: 时间窗已过期, 请更新 scope/manifest 中的 window 字段。")
        else:
            print("  提示: 若该目标确在授权范围内, 请先在 manifest 的 scope 段显式声明。")
        return 1

    ledger = AuditLedger(Path(args.ledger), redact=True)
    responses: list[RawResponse] = []

    def executor(method: str, path: str) -> RawResponse:
        # 统一拼接审计记录里的目标: 去掉重复斜杠, 保证账本里的 URL 可读且可复现
        audited_target = args.url.rstrip("/") + (path if path.startswith("/") else "/" + path)
        req = Request("probe", args.url, "http_request", {"method": method, "path": path})
        local = guard.check(req)
        if not local.allowed:
            ledger.record_decision(local)
            return RawResponse(method, args.url, 0, {}, "", None, f"blocked by scope guard: {local.reason}")
        response = probe_once(args.url, method=method, path=path, timeout=args.timeout)
        ledger.append(
            mode="probe", target=audited_target, action="http_request",
            verdict="allow", reason=local.reason, matched_rule=local.matched_rule,
            extra={
                "method": method,
                "response_status": response.status,
                "response_bytes": len(response.body_excerpt),
                "error": response.error,
            },
        )
        return response

    print(f"  探测计划: {' / '.join(f'{m} {p}' for m, p in [('GET', '/'), ('OPTIONS', '/'), ('TRACE', '/')])}")
    print("  说明: 仅发送非侵入式请求, 不包含任何注入或爆破载荷。\n")
    responses = run_probe_plan(args.url, timeout=args.timeout, executor=executor)

    for response in responses:
        status = response.status if response.status else "-"
        note = f" <- {response.error}" if response.error else ""
        print(f"    {response.method:8s} {status:>4} bytes={len(response.body_excerpt):>5}{note}")

    findings = analyze(args.url, responses)
    print()
    confirmed = sum(1 for f in findings if f.confidence == "high")
    _rule(f"检测结论: {len(findings)} 条 (可直接确认 {confirmed} / 需人工复核 {len(findings) - confirmed})")
    if not findings:
        print("  未发现配置类问题。注意: 未发现问题不等于不存在问题。")
    for finding in findings:
        print(f"  [{_severity_badge(finding.severity)}] {finding.rule_id}  "
              f"({finding.wstg_id}, 置信度={finding.confidence})")
        print(f"        {finding.title}")
        print(f"        修复: {finding.remediation}")

    state = ledger.verify()
    print()
    _rule("证据与审计")
    print(f"  账本     : {args.ledger}")
    print(f"  记录条数 : {state.records} | 链完整性: {'OK' if state.ok else 'BROKEN'}")
    print(f"  链头哈希 : {state.head_hash}")

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "target": args.url,
            "scope_decision": decision.as_audit_fields(),
            "responses": [r.as_dict() for r in responses],
            "findings": [f.as_dict() for f in findings],
            "ledger": {"path": str(args.ledger), **state.as_dict()},
        }
        out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  证据包   : {out_path}")

    return 0


# --------------------------------------------------------------------------- #
# 参数解析
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ptpipeline",
        description="授权范围内的渗透测试流程与证据链平台 (仅限你拥有或已获书面授权的目标)",
    )
    parser.add_argument("--version", action="version", version=f"ptpipeline {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_doctor = sub.add_parser("doctor", help="自检: 验证范围守卫与哈希链行为")
    p_doctor.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    p_doctor.set_defaults(func=cmd_doctor)

    p_scope = sub.add_parser("scope", help="展示/校验授权声明, 可对单个目标预判放行与否")
    p_scope.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    p_scope.add_argument("--target", default="", help="可选: 对单个目标做干跑判定")
    p_scope.add_argument("--action", default="http_request")
    p_scope.add_argument("--json", action="store_true")
    p_scope.set_defaults(func=cmd_scope)

    p_audit = sub.add_parser("audit", help="校验审计账本哈希链完整性")
    p_audit.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    p_audit.add_argument("--show", action="store_true", help="打印逐条记录")
    p_audit.set_defaults(func=cmd_audit)

    p_probe = sub.add_parser("probe", help="在授权范围内执行非侵入式配置检测")
    p_probe.add_argument("url", help="目标 URL, 必须落在 manifest 声明的范围内")
    p_probe.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    p_probe.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    p_probe.add_argument("--out", type=Path, default=None, help="导出证据包 JSON 的路径")
    p_probe.add_argument("--timeout", type=float, default=6.0)
    p_probe.set_defaults(func=cmd_probe)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
