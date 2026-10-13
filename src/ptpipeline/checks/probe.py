"""受授权约束的 HTTP 安全配置检测 —— 只做"检查表", 不做"攻击"。

范围声明:
    本模块只发起 HEAD / GET / OPTIONS / TRACE 这类**非侵入式**请求,
    只读取响应头与响应体中的公开标记, 不发送任何注入载荷、不做爆破、
    不做越权尝试。所有目标必须先通过 core.scope.Guard 校验。

每条 finding 都携带:
    - wstg_id: 对应的 OWASP WSTG 测试项编号
    - confidence: 置信度 (high / medium / low) —— 用于报告中的"需人工确认"分级
    - severity: info / low / medium / high
    - evidence: 触发该结论的原始响应片段 (进证据包, 供复核)
"""

from __future__ import annotations

import json
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlsplit

__all__ = ["Finding", "SEVERITY_ORDER", "analyze", "probe_once"]

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_UA = "ptpipeline/0.1 (authorized-security-assessment; +local-lab-only)"


@dataclass(slots=True)
class Finding:
    """一条待人工复核的配置类发现。"""

    rule_id: str
    title: str
    severity: str
    confidence: str
    wstg_id: str
    target: str
    detail: str
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "wstg_id": self.wstg_id,
            "target": self.target,
            "detail": self.detail,
            "remediation": self.remediation,
            "evidence": self.evidence,
        }


# --------------------------------------------------------------------------- #
# 原始探测
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class RawResponse:
    """一次原始 HTTP 交互的结果, 直接落证据包。"""

    method: str
    url: str
    status: int
    headers: dict[str, str]
    body_excerpt: str
    tls: dict[str, Any] | None = None
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "headers": self.headers,
            "body_excerpt": self.body_excerpt,
            "tls": self.tls,
            "error": self.error,
        }


def _recv_until_headers_end(sock: socket.socket, limit: int = 65536) -> bytes:
    """读到 header 结束标记 (\r\n\r\n) 为止。

    注意: recv 可能一次就带回正文, 因此本函数返回的是**原样缓冲区**,
    调用方必须自行切分头部与正文 —— 早期版本把缓冲区整个丢掉并重新
    recv 正文, 导致正文已被消费、目录索引等基于正文的规则全部漏检。
    """
    buf = bytearray()
    while len(buf) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        if b"\r\n\r\n" in buf:
            break
    return bytes(buf)


def _read_body(sock: socket.socket, buffered: bytes, headers: dict[str, str],
               limit: int) -> bytes:
    """补齐正文: 先用已缓冲的部分, 不足则继续读。"""
    body = buffered
    expected = _content_length(headers)
    if expected:
        while len(body) < min(expected, limit):
            chunk = sock.recv(min(4096, min(expected, limit) - len(body)))
            if not chunk:
                break
            body += chunk
    return body[:limit]


def _split_head_body(raw: bytes) -> tuple[bytes, bytes]:
    head, sep, body = raw.partition(b"\r\n\r\n")
    return (head, body) if sep else (raw, b"")


def _read_exact(sock: socket.socket, size: int, limit: int) -> bytes:
    """从 socket 继续读取指定字节数 (仅用于没有已缓冲数据的场景)。"""
    buf = bytearray()
    while len(buf) < min(size, limit):
        chunk = sock.recv(min(4096, min(size, limit) - len(buf)))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def _parse_headers(head: bytes) -> tuple[int, dict[str, str], str]:
    """解析状态行与响应头。head 必须是**已切分出的头部字节**。"""
    text = head.decode("iso-8859-1", "replace")
    lines = text.split("\r\n")
    status = 0
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            key = name.strip().lower()
            val = value.strip()
            headers[key] = f"{headers[key]}, {val}" if key in headers else val
    return status, headers, text


def probe_once(
    url: str,
    *,
    method: str = "GET",
    path: str = "/",
    timeout: float = 6.0,
    body_limit: int = 8192,
    verify_tls: bool = False,
) -> RawResponse:
    """对一个已获授权的 URL 发起单次非侵入式请求并抓取原始响应。"""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host:
        return RawResponse(method, url, 0, {}, "", None, "malformed URL")

    scheme = (parts.scheme or "http").lower()
    port = parts.port or (443 if scheme == "https" else 80)
    target_path = path if path.startswith("/") else "/" + path
    tls_info: dict[str, Any] | None = None
    raw = b""

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if scheme == "https":
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE if not verify_tls else ssl.CERT_REQUIRED
                try:
                    context.set_ciphers("DEFAULT@SECLEVEL=1")
                except ssl.SSLError:
                    pass
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cipher = tls_sock.cipher() or ()
                    version = tls_sock.version() or ""
                    cert = tls_sock.getpeercert() or {}
                    tls_info = {
                        "version": version,
                        "cipher": cipher[0] if cipher else "",
                        "bits": cipher[2] if len(cipher) > 2 else None,
                        "subject": _name_tuple(cert.get("subject")),
                        "issuer": _name_tuple(cert.get("issuer")),
                        "notAfter": cert.get("notAfter", ""),
                        "legacy_protocol": version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"),
                    }
                    tls_sock.sendall(_build_request(method, target_path, host, port))
                    raw = _recv_until_headers_end(tls_sock)
                    head_bytes, buffered_body = _split_head_body(raw)
                    status, headers, _ = _parse_headers(head_bytes)
                    body = _read_body(tls_sock, buffered_body, headers, body_limit)
                    return _finish(method, f"{scheme}://{host}:{port}{target_path}",
                                   status, headers, body, tls_info)
            else:
                sock.sendall(_build_request(method, target_path, host, port))
                raw = _recv_until_headers_end(sock)
                head_bytes, buffered_body = _split_head_body(raw)
                status, headers, _ = _parse_headers(head_bytes)
                body = _read_body(sock, buffered_body, headers, body_limit)
                return _finish(method, f"{scheme}://{host}:{port}{target_path}",
                               status, headers, body, None)
    except (OSError, ssl.SSLError) as exc:
        return RawResponse(method, url, 0, {}, "", tls_info, f"{type(exc).__name__}: {exc}")


def _build_request(method: str, path: str, host: str, port: int) -> bytes:
    default_port = 80 if port == 80 else 443
    host_header = host if port == default_port else f"{host}:{port}"
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host_header}",
        f"User-Agent: {_UA}",
        "Accept: */*",
        "Accept-Encoding: identity",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("ascii", "replace")


def _content_length(headers: dict[str, str]) -> int:
    raw = headers.get("content-length", "")
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def _name_tuple(value: Any) -> str:
    if not value:
        return ""
    try:
        return "; ".join(f"{k}={v}" for pair in value for k, v in pair)
    except (TypeError, ValueError):
        return str(value)


def _finish(method: str, url: str, status: int, headers: dict[str, str],
            body: bytes, tls_info: dict[str, Any] | None) -> RawResponse:
    excerpt = body.decode("utf-8", "replace")[:2000]
    return RawResponse(method, url, status, headers, excerpt, tls_info, "")


# --------------------------------------------------------------------------- #
# 分析规则
# --------------------------------------------------------------------------- #

_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")
_DIR_LIST_RE = re.compile(r"<title>\s*Index of /|<h1>\s*Index of /", re.IGNORECASE)


def _rule_missing_headers(target: str, resp: RawResponse) -> list[Finding]:
    out: list[Finding] = []
    is_https = target.startswith("https://")
    checks = [
        ("X-Content-Type-Options", "medium",
         "缺少 X-Content-Type-Options: nosniff, 浏览器可能对响应做 MIME 嗅探",
         "在 Web 服务器或反向代理层统一追加 X-Content-Type-Options: nosniff"),
        ("Content-Security-Policy", "medium",
         "缺少内容安全策略 (CSP), 对 XSS 的纵深防御缺失",
         "按最小可用原则下发 CSP, 先以 Content-Security-Policy-Report-Only 观察再转正式"),
        ("Referrer-Policy", "low",
         "缺少 Referrer-Policy, 跨站跳转可能泄露完整 URL 及其中参数",
         "下发 Referrer-Policy: strict-origin-when-cross-origin"),
        ("Permissions-Policy", "info",
         "缺少 Permissions-Policy, 浏览器特性 (摄像头/定位等) 未做显式收敛",
         "下发 Permissions-Policy 显式关闭业务不需要的浏览器特性"),
    ]
    if is_https:
        checks.insert(1, ("Strict-Transport-Security", "medium",
                          "HTTPS 站点缺少 HSTS, 存在 SSL 剥离降级风险",
                          "下发 Strict-Transport-Security: max-age=31536000; includeSubDomains"))
    for header, severity, detail, fix in checks:
        if header.lower() not in resp.headers:
            out.append(Finding(
                rule_id=f"HEADER-MISSING-{header.upper()}",
                title=f"缺少安全响应头 {header}",
                severity=severity, confidence="high", wstg_id="WSTG-CONF-07",
                target=target, detail=detail, remediation=fix,
                evidence={"request": f"{resp.method} {resp.url}", "observed_headers": sorted(resp.headers)},
            ))
    return out


def _rule_server_disclosure(target: str, resp: RawResponse) -> list[Finding]:
    out: list[Finding] = []
    for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        value = resp.headers.get(header)
        if not value:
            continue
        if header == "server" and not _VERSION_RE.search(value):
            continue
        out.append(Finding(
            rule_id=f"BANNER-{header.upper()}",
            title=f"响应头泄露组件与版本信息 ({header})",
            severity="low", confidence="high", wstg_id="WSTG-CONF-02",
            target=target,
            detail=f"{header}: {value} —— 版本号可被用于检索该版本的已知漏洞",
            remediation=f"移除或泛化 {header} 头, 例如仅返回 'webserver' 而不带版本号",
            evidence={"header": header, "value": value},
        ))
    return out


def _rule_directory_listing(target: str, resp: RawResponse) -> list[Finding]:
    if _DIR_LIST_RE.search(resp.body_excerpt):
        return [Finding(
            rule_id="DIR-LISTING",
            title="目录启用了自动索引 (Directory Listing)",
            severity="medium", confidence="medium", wstg_id="WSTG-CONF-04",
            target=target,
            detail="响应体中出现 'Index of /' 标记, 目录内容可被直接枚举; 需人工确认是否含敏感文件",
            remediation="关闭 Web 服务器与反向代理的目录索引 (如 nginx autoindex off / Apache Options -Indexes)",
            evidence={"body_excerpt": resp.body_excerpt[:300]},
        )]
    return []


def _rule_cors_wildcard(target: str, resp: RawResponse) -> list[Finding]:
    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        return [Finding(
            rule_id="CORS-WILDCARD-CREDS",
            title="CORS 通配来源且允许携带凭据",
            severity="high", confidence="high", wstg_id="WSTG-CONF-12",
            target=target,
            detail="响应同时返回 Access-Control-Allow-Origin: * 与 Allow-Credentials: true, 浏览器虽会拒绝该组合, 但说明 CORS 逻辑存在缺陷, 常伴随来源反射",
            remediation="改为显式白名单来源回显, 并对 Origin 做严格校验; 避免在携带凭据的接口上使用通配符",
            evidence={"access-control-allow-origin": acao,
                      "access-control-allow-credentials": acac},
        )]
    if acao and acao != "*":
        return [Finding(
            rule_id="CORS-REFLECTED",
            title="CORS 来源被反射回显 (需人工验证)",
            severity="medium", confidence="low", wstg_id="WSTG-CONF-12",
            target=target,
            detail=f"Access-Control-Allow-Origin 返回了具体来源 {acao!r}; 单次请求无法区分'固定白名单'与'任意来源反射'",
            remediation="人工复核该端点对任意 Origin 的处理逻辑, 确认是否存在来源反射",
            evidence={"access-control-allow-origin": acao},
        )]
    return []


def _rule_tls(target: str, resp: RawResponse) -> list[Finding]:
    info = resp.tls
    if not info:
        return []
    out: list[Finding] = []
    if info.get("legacy_protocol"):
        out.append(Finding(
            rule_id="TLS-LEGACY-PROTOCOL",
            title=f"协商使用了过时的 TLS 协议版本 ({info.get('version')})",
            severity="high", confidence="high", wstg_id="WSTG-CRYP-01",
            target=target,
            detail="服务端接受了 TLS 1.0/1.1 或更早协议, 存在已知密码学弱点",
            remediation="在服务端禁用 TLS 1.2 以下协议, 优先启用 TLS 1.3",
            evidence=info,
        ))
    bits = info.get("bits")
    if isinstance(bits, int) and bits and bits < 128:
        out.append(Finding(
            rule_id="TLS-WEAK-CIPHER",
            title=f"协商出弱强度密码套件 ({bits} 位)",
            severity="medium", confidence="high", wstg_id="WSTG-CRYP-01",
            target=target,
            detail=f"当前会话使用 {info.get('cipher')} ({bits} 位), 强度不足",
            remediation="在服务端密码套件配置中移除 RC4/3DES/128 位以下套件",
            evidence=info,
        ))
    return out


def _rule_http_methods(target: str, trace_resp: RawResponse, options_resp: RawResponse) -> list[Finding]:
    out: list[Finding] = []
    if trace_resp.status and trace_resp.status < 400:
        out.append(Finding(
            rule_id="HTTP-TRACE-ENABLED",
            title="服务器响应了 TRACE 方法",
            severity="medium", confidence="high", wstg_id="WSTG-CONF-06",
            target=target,
            detail=f"TRACE 返回 {trace_resp.status}; 历史上与跨站追踪攻击 (XST) 相关, 现代浏览器已缓解但仍是攻击面",
            remediation="在 Web 服务器配置中显式禁用 TRACE (Apache: TraceEnable off)",
            evidence={"status": trace_resp.status, "headers": trace_resp.headers},
        ))
    allow = options_resp.headers.get("allow", "") or options_resp.headers.get("access-control-allow-methods", "")
    risky = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")
             if m in {token.strip().upper() for token in allow.split(",")}]
    if risky:
        out.append(Finding(
            rule_id="HTTP-RISKY-METHODS",
            title=f"OPTIONS 暴露了高风险方法: {', '.join(risky)}",
            severity="low", confidence="medium", wstg_id="WSTG-CONF-06",
            target=target,
            detail=f"Allow: {allow} —— 需人工确认这些方法是否真的可用以及鉴权是否正确",
            remediation="只保留业务必需的方法, 其余在网关层直接拒绝并返回 405",
            evidence={"allow": allow},
        ))
    return out


def analyze(target: str, responses: list[RawResponse]) -> list[Finding]:
    """把原始响应集合归约为去重后的 finding 列表。"""
    findings: list[Finding] = []
    ok_responses = [r for r in responses if not r.error]
    if not ok_responses:
        return findings

    primary = next((r for r in ok_responses if r.method == "GET"), ok_responses[0])
    findings.extend(_rule_missing_headers(target, primary))
    findings.extend(_rule_server_disclosure(target, primary))
    findings.extend(_rule_directory_listing(target, primary))
    findings.extend(_rule_cors_wildcard(target, primary))
    findings.extend(_rule_tls(target, primary))

    trace = next((r for r in ok_responses if r.method == "TRACE"), None)
    options = next((r for r in ok_responses if r.method == "OPTIONS"), None)
    if trace or options:
        findings.extend(_rule_http_methods(
            target,
            trace or RawResponse("TRACE", target, 0, {}, "", None),
            options or RawResponse("OPTIONS", target, 0, {}, "", None),
        ))

    deduped: dict[str, Finding] = {}
    for finding in findings:
        deduped.setdefault(finding.rule_id, finding)
    return sorted(deduped.values(), key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.rule_id))


def default_probe_plan(url: str) -> list[tuple[str, str]]:
    """默认探测计划: 方法枚举 + 一次根路径 GET。全部为非侵入式请求。"""
    return [("GET", "/"), ("OPTIONS", "/"), ("TRACE", "/")]


def run_probe_plan(url: str, *, timeout: float = 6.0,
                   executor: Callable[[str, str], RawResponse] | None = None) -> list[RawResponse]:
    """执行探测计划。executor 由调用方注入, 以便统一经过范围守卫与审计。"""
    run = executor or (lambda method, path: probe_once(url, method=method, path=path, timeout=timeout))
    results: list[RawResponse] = []
    for method, path in default_probe_plan(url):
        results.append(run(method, path))
    return results


def findings_to_json(findings: list[Finding]) -> str:
    return json.dumps([f.as_dict() for f in findings], indent=2, ensure_ascii=False)
