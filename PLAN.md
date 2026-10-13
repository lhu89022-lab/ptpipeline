# ptpipeline 技术设计

## 1. 定位

一句话：**把"这次测试在授权范围内、且结论可复现"从口头承诺变成机器可验证的属性。**

边界声明（写进 README 和代码注释，避免被误读）：本项目的检测模块**可以被 nuclei / testssl.sh 等成熟工具替换**——替换后范围守卫与证据链的价值一点不减少。这恰恰证明它不是扫描器，而是**治理层 + 证据层**。

---

## 2. 分层架构

```
┌─────────────────────────────────────────────────────────────┐
│  CLI 层        __main__.py                                  │
│  doctor / scope / audit / probe   （退出码即契约）           │
├─────────────────────────────────────────────────────────────┤
│  检测层        checks/probe.py                              │
│  非侵入式请求 → 原始响应 → 规则归约 → Finding                │
├─────────────────────────────────────────────────────────────┤
│  证据层        core/audit.py                                │
│  哈希链账本 · 篡改定位 · 写入保护 · 取证模式                  │
├─────────────────────────────────────────────────────────────┤
│  治理层        core/scope.py        ← 核心不变量             │
│  Manifest → Guard.check(Request) → Decision                 │
└─────────────────────────────────────────────────────────────┘
```

**依赖方向严格单向**：上层可以依赖下层，下层**不知道**上层的存在。`core/scope.py` 不 import 任何其他项目模块——它是纯函数式的判定逻辑，可以脱离整个项目单独测试。这是刻意的：核心不变量的可信度不应该依赖于周边代码的正确性。

---

## 3. 核心接口契约

### 3.1 授权判定（`core/scope.py`）

```python
@dataclass(frozen=True, slots=True)
class Request:
    mode: str                      # 调用场景: "probe" / "retest" / "doctor"
    target: str                    # 域名 / IP / CIDR 内地址 / 完整 URL
    action: str                    # 必须命中 scope.allow_actions
    context: dict[str, Any] | None # 附加上下文 (HTTP 方法等), 仅用于留痕

@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    mode: str
    target: str
    action: str
    reason: str          # 人类可读理由, 直接进审计记录与报告
    matched_rule: str    # 命中的具体规则, 如 "ip_ranges:127.0.0.0/8"

    def as_audit_fields(self) -> dict[str, Any]: ...

class Guard:
    def check(self, request: Request, now: datetime | None = None) -> Decision: ...
    def describe(self) -> dict[str, Any]: ...
    def window_is_open(self, now: datetime | None = None) -> bool: ...
```

**契约要点**

| 约定 | 理由 |
|------|------|
| `check()` **永不抛异常**，一切失败都以 `Decision(allowed=False, reason=...)` 表达 | 拒绝是正常控制流，必须能被统计、展示、留痕。抛异常会让调用方倾向于"用 try 包起来然后忽略" |
| `now` 可注入 | 时间窗逻辑必须能被确定性测试，不能依赖真实时钟 |
| `Decision` 是 frozen dataclass | 判定结果一旦产生就不可变，避免在传递过程中被"顺手改成放行" |
| 判定顺序固定：`时间窗 → 动作白名单 → 目标解析 → 排除项 → URL 前缀 → IP 网段 → 域名规则` | **排除项永远优先于任何 allow 规则** |

### 3.2 审计账本（`core/audit.py`）

```python
GENESIS = "0" * 64

class AuditLedger:
    def __init__(self, path, algorithm="sha256", redact=True, strict=True): ...
    def append(self, *, mode, target, action, verdict, reason="",
               matched_rule="", extra=None) -> dict: ...
    def record_decision(self, decision: Decision, extra=None) -> dict: ...
    def verify(self) -> ChainVerification: ...
    def summary(self) -> dict: ...

@dataclass(slots=True)
class ChainVerification:
    ok: bool
    records: int
    broken_at: int | None    # 行号 (1-based)
    reason: str              # "hash mismatch at seq=0: content was modified after write"
    head_hash: str
    first_ts: str
    last_ts: str
```

**链式计算**

```
rec_0.prev = GENESIS
rec_n.prev = rec_{n-1}.hash
rec_n.hash = sha256( canonical_json(rec_n \ {hash}) + rec_n.prev )
```

`canonical_json` = `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
→ 键排序保证字段顺序无关；紧凑分隔符消除空白差异；`ensure_ascii=True` 保证跨平台/跨 locale 的字节级一致。**三者缺一，哈希都会在不同环境上算出不同值。**

**两个刻意的行为设计**

| 模式 | 行为 | 用途 |
|------|------|------|
| `strict=True`（默认） | 续写已损坏账本 → 抛 `ValueError` | 绝不把新证据接到一条已不可信的链上 |
| `strict=False` | 允许打开损坏账本，`broken` 属性暴露损坏详情 | 取证：定位断链位置。此时 `append()` 仍会拒绝 |

**已知局限（主动写进 README，不等读者自己发现）**：哈希链**不能**防住"从头重写整条链"。它防的是**事后局部篡改**。要抵抗整链重写，需要把 `head_hash` 定期锚定到外部不可篡改存储（RFC 3161 时间戳、公开的透明日志）。这是一个明确的后续工作项，不是被忽略的漏洞。

### 3.3 检测与归约（`checks/probe.py`）

```python
@dataclass(slots=True)
class RawResponse:
    method: str; url: str; status: int
    headers: dict[str, str]; body_excerpt: str
    tls: dict | None; error: str

@dataclass(slots=True)
class Finding:
    rule_id: str; title: str
    severity: str      # info / low / medium / high / critical
    confidence: str    # high / medium / low
    wstg_id: str       # OWASP WSTG 编号, 如 "WSTG-CONF-07"
    target: str; detail: str; remediation: str
    evidence: dict

def analyze(target: str, responses: list[RawResponse]) -> list[Finding]
def run_probe_plan(url: str, *, timeout: float = 6.0,
                   executor: Callable[[str, str], RawResponse] | None = None) -> list[RawResponse]
```

**依赖注入点**：`executor` 由调用方提供。生产路径是 `probe_once`，但**调用方要负责在 executor 内部先过 `Guard.check()` 再落账**。这样检测模块完全不知道授权与审计的存在，三层的耦合度降到最低，也让检测逻辑可以脱离网络单独测试（喂假的 `RawResponse` 即可）。

**置信度分级规则**（这是最容易被质疑的一处，依据必须明确）

| 置信度 | 判据 | 例子 |
|--------|------|------|
| `high` | **单次观测即可判定**，不存在歧义 | `X-Content-Type-Options` 头缺失——响应头里没有就是没有 |
| `medium` | 需要**读响应体或语义推断**，可能有边界情况 | 目录索引——看的是正文里的 `Index of /` 标记，可能被自定义错误页干扰 |
| `low` | **单次请求无法区分良性/恶意实现**，必须人工多态验证 | `Access-Control-Allow-Origin` 返回具体来源——无法区分"固定白名单"与"任意来源反射" |

---

## 4. M4–M6 详细设计

### M4 报告生成（W4）

**不做**：花哨的模板引擎选型、PDF 渲染链（Windows 上的 PDF 工具链是个坑）。
**要做**：从账本 + 证据包生成 Markdown，一份文件同时服务两类读者。

```python
# report/generate.py
def build_report(ledger_path: Path, findings_path: Path, manifest_path: Path,
                 *, template: Path = TEMPLATES / "report.md.j2") -> str
```

报告结构：

```
执行摘要           ← 非技术读者: 测试了什么 / 发现几类问题 / 风险最高的是什么
 ├ 授权信息        ← 委托方 / 凭据编号 / 时间窗 / 实际动作统计 (来自账本 summary)
 ├ 风险概览        ← severity × 数量表 + 一句话业务影响
技术详情 (逐 finding)
 ├ 现象            ← Finding.detail
 ├ 证据            ← Finding.evidence 原始响应片段
 ├ 复现步骤        ← 该 finding 对应的请求 (从账本按 target 检索)
 ├ WSTG 映射
 └ 修复建议 + 验证方法   ← 修复后怎么确认真的修好了 (这是拉开档次的字段)
附录 A 完整审计账本摘要 + 链头哈希
附录 B 未覆盖项    ← 明确写出"本次测试没有覆盖什么", 比假装全覆盖更专业
```

**关键设计**：`remediation` 必须带**验证方法**。"下发 CSP" 是半句话；"下发 CSP 后重新执行 `ptpipeline probe`，确认 `HEADER-MISSING-CONTENT-SECURITY-POLICY` 不再出现"才是闭环。这个字段直接把 M4 和 M5 串起来。

模板：`str.replace()` 的极简 `{{ key }}` 替换即可。**不引入 Jinja2**——保持零依赖这条线，比多一个漂亮的模板语法重要得多。

### M5 复测引擎（W5）

复测是渗透测试里最枯燥、最容易被敷衍的环节，也正是自动化收益最大的地方。

```python
# retest/engine.py
@dataclass
class RetestResult:
    rule_id: str
    target: str
    before: str          # "open"
    after: str           # "open" / "fixed" / "changed" / "unreachable"
    evidence_before: dict
    evidence_after: dict | None
    delta: str | None    # changed 时的人话描述

def retest(evidence_pack: Path, manifest: Path, ledger_path: Path) -> list[RetestResult]
```

三态判定逻辑：

| 状态 | 判定条件 |
|------|----------|
| `fixed` | 该 `rule_id` 在新一轮探测中不再出现 |
| `still-open` | 该 `rule_id` 仍然出现，且触发条件相同 |
| `changed` | 该 `rule_id` 仍出现，但**证据变了**（如 `Server` 头版本号从 `PHP/7.4.3` 变成 `PHP/8.1.0`）→ 需要人工判断是"部分修复"还是"换了个新问题" |
| `unreachable` | 请求失败（服务下线/网络不通）→ **绝不能算作 fixed**，这是复测里最容易出的报告事故 |

`changed` 的检测方式：对 `Finding.evidence` 做 `canonical_json` 后比对哈希，不同则标 `changed` 并附上差异摘要。

### M6 流量归因（W6，差异化收尾）

把 pcap 里的 HTTP 请求与审计账本逐条对齐，实现"网络层证据 ↔ 应用层证据"的交叉验证。

```python
# trail/pcap.py  (纯标准库, 无 scapy 依赖)
def parse_pcap(path: Path) -> Iterator[Packet]        # 支持 classic pcap + pcapng
def extract_http(packets: Iterable[Packet]) -> Iterator[tuple[str, str, str]]  # ts, method, url
def correlate(http_events, ledger_path: Path, *, tolerance_s: float = 2.0) -> list[Match]
```

关联键：`(目标主机, 端口, 时间戳窗口 ±2s)`。输出三类结果：`matched`（账本里的动作在流量里找得到）、`ledger_only`（有记录无流量——可能是抓包没覆盖到）、`traffic_only`（有流量无记录——**这是最有价值的输出**：说明存在绕过管道的动作，直接暴露流程漏洞）。

这个模块把「用过 Wireshark」推进到「用标准库实现 pcap/pcapng 解析并与审计账本关联」，开源世界几乎无人做过。技术难点在 classic pcap 与 pcapng 两种格式、以及 TLS 加密流量的处理边界（只做 TCP 五元组与明文 HTTP，不解密）。**要明确写出"不解密 TLS"这条边界**，否则又是一个合规灰区。

---

## 5. 测试策略

| 层级 | 手段 | 当前状态 |
|------|------|----------|
| 单元 | 对 `Guard.check()` 喂构造的 manifest，覆盖判定顺序的每个分支 | 由 `doctor` 的 13 项断言覆盖（1 项 manifest 合法性 + 5 类拒绝 + 4 类放行 + 3 项账本行为） |
| 集成 | 起真实 socket 靶场跑完整 probe 链路 | `scripts/verify_pipeline.py` 的 33 项断言 |
| 篡改 | 写后改账本，断言断链行号精确 | 已覆盖（`broken_at` 精确到行） |
| 契约 | CLI 退出码：越界返回 1，成功返回 0 | 已覆盖 |
| 回归 | 每条规则在靶场里都有一个对应的触发点 | 已覆盖（8 条规则断言） |

**一个刻意的测试设计**：`doctor` 会**主动篡改自己刚写的账本**，然后断言篡改被检出。也就是说，"检测篡改的能力"本身是被持续验证的，而不是靠一次性人工确认。

---

## 6. 工程规范

- **行宽 100**，`ruff` 规则集 `E F W I UP B SIM`
- **Type hints 全覆盖**，`from __future__ import annotations`
- **零运行时依赖**是硬约束，新增依赖需要在 README 里给出充分理由
- 每个模块顶部必须有**范围声明**（这个模块能做什么、明确不做什么）
- 提交信息用 conventional commits：`feat: / fix: / docs: / test: / refactor:`
- **真实证据与账本永不入库**（`.gitignore` 已配置），库里只保留脱敏的 `sample-` 样例

---

## 7. 已知局限（主动披露清单）

写进 README，因为这些是最容易被质疑的地方：

1. **哈希链不防整链重写** —— 需要外部时间戳锚定，见 3.2 节。
2. **YAML 解析器是自研的极简版** —— 不支持锚点、多行块、流式映射。这是零依赖的代价，且解析失败会明确报错而非静默忽略。
3. **检测规则只有 16 条（6 组），且都是配置类** —— 不覆盖逻辑漏洞（越权、业务竞态）。逻辑漏洞本质上需要业务语义，无法用通用规则表达。
4. **TLS 检测只做协议版本与密钥强度** —— 不做证书链验证、不做完整密码套件枚举（那是 `testssl.sh` 的领域，本项目选择不重复造）。
5. **`confidence=low` 的结论不能直接写进交付报告** —— 必须经人工复验并在报告中标注，否则就是在制造误报。
