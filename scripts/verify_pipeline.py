"""端到端自检 —— 不依赖任何第三方测试框架。

覆盖:
    1. 范围守卫拒绝公网目标 (干跑, 不产生任何网络请求)
    2. 范围守卫放行本地靶场
    3. 对本地靶场执行完整 probe, 并确认命中了预期缺陷
    4. 审计账本哈希链完整
    5. 事后篡改账本必须被检出

运行: python scripts/verify_pipeline.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(REPO_ROOT))

from ptpipeline.checks.probe import analyze, run_probe_plan  # noqa: E402
from ptpipeline.core.audit import AuditLedger  # noqa: E402
from ptpipeline.core.scope import Guard, Request, load_manifest  # noqa: E402
from labs.vulnerable_server import VulnerableHandler  # noqa: E402  (需要 labs 在 sys.path)
from http.server import ThreadingHTTPServer  # noqa: E402

MANIFEST = REPO_ROOT / "scope" / "manifest.example.yaml"
PORT = 8099
passed = failed = 0


def check(condition: bool, label: str) -> None:
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {label}")
    else:
        failed += 1
        print(f"  [FAIL] {label}")


def main() -> int:
    print("=" * 70)
    print("ptpipeline 端到端自检")
    print("=" * 70)

    guard = Guard(load_manifest(MANIFEST))

    print("\n[1] 范围守卫: 授权外目标必须被拒绝 (不产生网络流量)")
    for target in ("https://www.baidu.com/", "http://10.0.0.1/", "http://172.16.0.9/"):
        decision = guard.check(Request("verify", target, "http_request"))
        check(not decision.allowed, f"{target} -> {decision.reason}")

    print("\n[2] 范围守卫: 本地靶场必须被放行")
    target = f"http://127.0.0.1:{PORT}/"
    decision = guard.check(Request("verify", target, "http_request"))
    check(decision.allowed, f"{target} -> {decision.matched_rule}")

    print("\n[3] 启动靶场并执行完整探测")
    server = ThreadingHTTPServer(("127.0.0.1", PORT), VulnerableHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.4)

    ledger_path = REPO_ROOT / ".verify-tmp" / "audit.jsonl"
    shutil.rmtree(ledger_path.parent, ignore_errors=True)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger = AuditLedger(ledger_path)

    responses = []
    try:
        def executor(method: str, path: str):
            from ptpipeline.checks.probe import probe_once
            local = guard.check(Request("verify", target, "http_request", {"method": method}))
            if not local.allowed:
                ledger.record_decision(local)
                raise AssertionError(f"scope guard blocked an in-scope target: {local.reason}")
            response = probe_once(target, method=method, path=path, timeout=5.0)
            audited_target = target.rstrip("/") + (path if path.startswith("/") else "/" + path)
            ledger.append(mode="verify", target=audited_target,
                          action="http_request", verdict="allow", reason=local.reason,
                          matched_rule=local.matched_rule,
                          extra={"method": method, "status": response.status})
            return response

        responses = run_probe_plan(target, timeout=5.0, executor=executor)
    finally:
        server.shutdown()
        server.server_close()

    statuses = {r.method: r.status for r in responses}
    check(statuses.get("GET") == 200, f"GET 返回 200 (实际 {statuses.get('GET')})")
    check(statuses.get("OPTIONS") == 200, f"OPTIONS 返回 200 (实际 {statuses.get('OPTIONS')})")
    check(statuses.get("TRACE") == 200, f"TRACE 返回 200 (实际 {statuses.get('TRACE')})")

    print("\n[4] 检测规则应命中的缺陷")
    findings = analyze(target, responses)
    rule_ids = {f.rule_id for f in findings}
    for expected in (
        "HEADER-MISSING-CONTENT-SECURITY-POLICY",
        "HEADER-MISSING-X-CONTENT-TYPE-OPTIONS",
        "BANNER-SERVER",
        "BANNER-X-POWERED-BY",
        "DIR-LISTING",
        "CORS-WILDCARD-CREDS",
        "HTTP-TRACE-ENABLED",
        "HTTP-RISKY-METHODS",
    ):
        check(expected in rule_ids, f"命中规则 {expected}")
    check(len(findings) >= 10, f"finding 总数 >= 10 (实际 {len(findings)})")
    for finding in findings:
        check(bool(finding.remediation) and bool(finding.wstg_id),
              f"{finding.rule_id} 带修复建议与 WSTG 编号")

    print("\n[5] 审计账本完整性")
    state = ledger.verify()
    check(state.ok, f"哈希链完整 ({state.records} 条记录)")
    check(state.records >= 3, f"记录数 >= 3 (实际 {state.records})")
    summary = ledger.summary()
    check(summary["allow"] == state.records, f"全部记录 verdict=allow (实际 {summary})")

    print("\n[6] 事后篡改必须被检出")
    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[-1])
    tampered["target"] = "http://10.99.99.99/"
    lines[-1] = json.dumps(tampered, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    state = AuditLedger(ledger_path, strict=False).verify()
    check(not state.ok, f"篡改被检出 (broken_at={state.broken_at})")
    check(state.broken_at == len(lines), f"断链位置精确定位在最后一行 (line {len(lines)})")

    print("\n[7] CLI 冒烟: scope 干跑判定")
    child_env = {**os.environ, "PYTHONPATH": str(SRC), "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run(
        [sys.executable, "-m", "ptpipeline", "scope", "--target", "https://www.baidu.com/"],
        cwd=str(REPO_ROOT), env=child_env,
        capture_output=True, text=True, encoding="utf-8",
    )
    check(proc.returncode == 1, f"公网目标 exit code = 1 (实际 {proc.returncode})")
    check("DENY" in (proc.stdout or ""), "输出包含 DENY")

    print("\n" + "=" * 70)
    print(f"结果: {passed} 项通过, {failed} 项失败")
    print("=" * 70)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
