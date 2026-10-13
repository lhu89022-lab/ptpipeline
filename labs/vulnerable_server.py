"""故意配置错误的本地靶场 —— 只监听回环, 用于验证检测与证据链。

这些缺陷都是为了被检测出来而**故意**设置的:
    * 缺失全部安全响应头
    * Server 头暴露带版本号的组件信息
    * 根路径开启目录索引 (Index of /)
    * CORS 允许任意来源并携带凭据
    * 响应 TRACE 方法
    * OPTIONS 暴露 PUT / DELETE

启动: python labs/vulnerable_server.py --port 8080
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INDEX_BODY = b"""<!DOCTYPE html>
<html><head><title>Index of /</title></head>
<body>
<h1>Index of /</h1>
<hr>
<pre>
<a href="../">../</a>
<a href="backup/">backup/</a>
<a href="config.old">config.old</a>
<a href="notes.txt">notes.txt</a>
</pre>
<hr>
</body></html>
"""


class VulnerableHandler(BaseHTTPRequestHandler):
    """一个把常见配置错误演示到极致的处理器。"""

    server_version = "DemoHTTP/1.4.2"
    sys_version = ""

    def _emit_common_headers(self) -> None:
        # 刻意不发 X-Content-Type-Options / CSP / Referrer-Policy / Permissions-Policy
        self.send_header("Server", "DemoHTTP/1.4.2 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

    def _respond(self, body: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._emit_common_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self._respond(INDEX_BODY)

    def do_HEAD(self) -> None:  # noqa: N802
        self._respond(INDEX_BODY)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._respond(b"", 200)

    def do_TRACE(self) -> None:  # noqa: N802
        # 回显请求 —— TRACE 的教科书式（危险）实现
        echo = f"TRACE {self.path} HTTP/1.1\r\nHost: {self.headers.get('Host', '')}\r\n\r\n"
        self._respond(echo.encode("utf-8"), 200)

    def do_PUT(self) -> None:  # noqa: N802
        self._respond(b"method not really implemented, but advertised", 200)

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[lab] {self.address_string()} {fmt % args}")


def main() -> int:
    parser = argparse.ArgumentParser(description="本地故意配置错误的靶场 (仅监听回环)")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), VulnerableHandler)
    print(f"[lab] 靶场已启动: http://{args.host}:{args.port}/  (Ctrl+C 停止)")
    print("[lab] 提示: 这是故意配错的演示服务, 请勿对公网暴露。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[lab] 已停止")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
