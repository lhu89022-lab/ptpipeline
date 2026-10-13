#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 ptpipeline 的**真实 CLI 输出**渲染成终端风格的展示图与演示 GIF。

用法（必须用带 Pillow 的解释器；系统 python 通常没有 PIL）:

    <带 Pillow 的 python> docs/build_assets.py                # 全流程: 采集 -> 校验字体 -> 渲染 -> 复验
    <带 Pillow 的 python> docs/build_assets.py --verify-fonts  # 只跑字体/列宽/对齐校验
    <带 Pillow 的 python> docs/build_assets.py --render-only   # 用已有 _capture/ 重新渲染，不重跑命令

诚信约定（重要）
----------------
1. **没有任何一行文字是编造的。** 每张图里除标题栏与图注之外的全部文本，都来自
   docs/_capture/*.txt —— 那些文件是本脚本真正执行 CLI 命令后原样落盘的 stdout。
   脚本把"命令 + argv + exit code + stdout"记进 docs/_capture/_manifest.json。
2. GIF 是**逐帧渲染**（render），不是屏幕录制（screen capture）。README 里必须
   如实标注，不得暗示它是录屏。
3. 为演示"证据链防篡改"，需要对账本做一次**合成篡改**（把第 3 行的 target 换成越界
   IP）。这是脚本显式执行、并写进 _manifest.json 的 "tamper" 字段的动作，既不是伪造
   输出，也不是对真实数据的破坏 —— 被改的是 docs/_capture/ 下的演示副本。
4. **不留本机指纹。** 采集时一律用**相对仓库根**的路径（脚本以仓库根为 cwd 执行命令），
   所以图里显示的是 `docs/_capture/demo-ledger.jsonl` 这类相对路径，而不是作者机器上的
   绝对路径；账本的 `actor` 字段通过 `PTP_ACTOR` 固定为 `demo-operator`（见
   core/audit.py 的 actor_identity()），避免把主机名与 PID 带进公开仓库。
   解释器只以 `python` 记录，版本另记在 _manifest.json 的 python_version 里。
   这些都不是事后改写输出 —— 命令就是以这个样子跑出来的。
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import re
import struct
import subprocess
import sys
import unicodedata
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #

REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs"
SRC = REPO / "src"
CAPTURE = DOCS / "_capture"
MANIFEST = CAPTURE / "_manifest.json"

FONT_DIR = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"
PRIMARY_FONT = FONT_DIR / "CascadiaMono.ttf"     # 等宽、无中文
FALLBACK_FONT = FONT_DIR / "simhei.ttf"          # 有中文、汉字恰为 2×半角

# 需要主字体具备的符号码位（CLI 输出里真实出现的制表与符号字符）。
REQUIRED_SYMBOLS = "─│┌┐└┘├┤┬┴┼━┃█░▒▓→←…•·"
# 已知且**故意留着**的缺口: '✗' 两个字体都没有，语料里也不存在 —— 保留在列表里，
# 是为了让"缺字形会被立刻发现"这件事本身处于被测试状态。

# 单倍宽非 ASCII 白名单 —— 这些字符的 Unicode East Asian Width 是 "A"(Ambiguous)，
# 在西文终端语境下按半角算（Windows Terminal / VS Code 对 ASCII 区符号的默认行为）。
# 实测确认它们都被 CascadiaMono 以**半角**步进绘制，见 assert_font_invariants。
AMBIGUOUS_HALF = "─—└…"

SCENE_COLS = 112          # 画布列宽。CLI 自己的分隔线只有 68 列，112 能容纳长路径。
SCENE_FONT_PX = 30
GIF_COLS = SCENE_COLS     # GIF 与静态图用同一列宽，折行结果完全一致


def char_cols(ch: str) -> int:
    """字符在等宽栅格中占几列: 半角 1 / 全角 2 / 组合记号 0。

    'A'(Ambiguous) 一律按 1 列 —— 与终端默认行为一致，且实测与墨迹宽度相符。
    """
    if unicodedata.combining(ch):
        return 0
    if unicodedata.east_asian_width(ch) in ("W", "F"):
        return 2
    return 1


def display_cols(text: str) -> int:
    """整串占几列。

    不能写成 sum(char_cols(c) for c in text) 之外的花样，但**必须**留意: 这个函数
    对尾随空格是敏感的，而 shell 里 `$(...)` 会吃掉行尾空格 —— 用 PowerShell 的
    here-string 传参时，任何"看起来一样"的字符串都可能少一个尾空格。图注/表格里
    少一个空格就是少一列，所以这里刻意不做 strip。
    """
    return sum(char_cols(c) for c in text)


# --------------------------------------------------------------------------- #
# 最小的 sfnt 解析器 —— 用来**实测**字体，而不是相信字体名或注释
# --------------------------------------------------------------------------- #

def _sfnt_offset(data: bytes) -> int:
    """ttcf 容器取第一个字体；否则偏移就是 0。"""
    if data[:4] == b"ttcf":
        return struct.unpack_from(">I", data, 12)[0]
    return 0


class FontInfo:
    """只读 head / cmap / hmtx 三张表，够用来判断"这个字符能不能真画出来"。"""

    def __init__(self, path: Path) -> None:
        self.path = path
        data = path.read_bytes()
        self.data = data
        base = _sfnt_offset(data)
        num_tables = struct.unpack_from(">H", data, base + 4)[0]
        self.tables: dict[bytes, tuple[int, int]] = {}
        for i in range(num_tables):
            off = base + 12 + i * 16
            tag, _sum, toff, tlen = struct.unpack_from(">4sIII", data, off)
            self.tables[tag] = (toff, tlen)

        head, _ = self.tables[b"head"]
        self.units_per_em = struct.unpack_from(">H", data, head + 18)[0]
        hhea, _ = self.tables[b"hhea"]
        self.num_hmetrics = struct.unpack_from(">H", data, hhea + 34)[0]
        self.hmtx, _ = self.tables[b"hmtx"]
        self._cmap: dict[int, int] | None = None
        self._segments: list[tuple[int, int, int, int]] | None = None
        # rangeOffset 数组里**第 0 项**的文件偏移 —— format 4 的 rangeOffset 是相对
        # "自己那一项"的位置，不是绝对偏移，必须留下这个基准才能算出 glyphIdArray 地址。
        self._roff_base: int | None = None
        self._cmap_end: int = 0

    # -- cmap ------------------------------------------------------------- #

    def _load_cmap(self) -> None:
        """解析 cmap 的 format 4 / 12 子表。

        format 4 的汉字常挤在一个极宽的段里（idRangeOffset=0 时靠 idDelta 求值），
        所以**不展开**成字典，而是留段表做惰性求值 —— 展开会很慢，也没必要。
        """
        cmap_off, cmap_len = self.tables[b"cmap"]
        self._cmap_end = cmap_off + cmap_len
        n = struct.unpack_from(">H", self.data, cmap_off + 2)[0]
        best: tuple[int, int] | None = None
        for i in range(n):
            pid, eid, sub = struct.unpack_from(">HHI", self.data, cmap_off + 4 + i * 8)
            fmt = struct.unpack_from(">H", self.data, cmap_off + sub)[0]
            score = {(3, 10): 3, (3, 1): 2, (0, 3): 1, (0, 4): 1}.get((pid, eid), 0)
            if fmt in (4, 12) and (best is None or score > best[0]):
                best = (score, cmap_off + sub)
        self._cmap = {}
        self._segments = []
        if best is None:
            return
        sub = best[1]
        fmt = struct.unpack_from(">H", self.data, sub)[0]
        if fmt == 4:
            segx2 = struct.unpack_from(">H", self.data, sub + 6)[0]
            seg = segx2 // 2
            ends = struct.unpack_from(f">{seg}H", self.data, sub + 14)
            starts = struct.unpack_from(f">{seg}H", self.data, sub + 16 + segx2)
            deltas = struct.unpack_from(f">{seg}h", self.data, sub + 16 + segx2 * 2)
            self._roff_base = sub + 16 + segx2 * 3
            ranges = struct.unpack_from(f">{seg}H", self.data, self._roff_base)
            self._cmap_end = min(self._cmap_end, sub + 2
                                 + struct.unpack_from(">H", self.data, sub + 2)[0])
            self._segments = list(zip(starts, ends, deltas, ranges))
        else:                                    # format 12: 分组区间
            ngroups = struct.unpack_from(">I", self.data, sub + 12)[0]
            for i in range(ngroups):
                s, e, g = struct.unpack_from(">III", self.data, sub + 16 + i * 12)
                if e - s > 0xFFFF:               # 荒谬的巨段，跳过
                    continue
                self._segments.append((s, e, g, 0xFFFF))

    @property
    def coverage(self) -> dict[int, int]:
        if self._cmap is None:
            self._load_cmap()
        assert self._cmap is not None
        return self._cmap

    def glyph_id(self, ch: str) -> int | None:
        cp = ord(ch)
        if self._cmap is None:
            self._load_cmap()
        if cp in self.coverage:
            return self.coverage[cp]
        assert self._segments is not None
        for i, (start, end, delta, roff) in enumerate(self._segments):
            if not (start <= cp <= end):
                continue
            if roff == 0xFFFF:                   # format 12: gid = delta + 偏移
                return delta + (cp - start)
            if roff == 0:                        # format 4 的 idDelta 模式
                return (cp + delta) & 0xFFFF
            # format 4 的 rangeOffset 是**相对自己那一项**的位置（规范原话: 加上
            # &idRangeOffset[i]），所以地址 = 第 0 项的偏移 + i*2 + roff + 2*(cp-start)。
            # 早期版本误当成绝对偏移，于是 Cascadia 的 'M'（rof=388）解析到文件随机
            # 位置、读出来是 0，被判成"没有字形"—— 这就是半角=None 的根因。
            assert self._roff_base is not None
            addr = self._roff_base + i * 2 + roff + 2 * (cp - start)
            if addr + 2 > self._cmap_end:        # 越界 = 该码位无字形
                return None
            gid = struct.unpack_from(">H", self.data, addr)[0]
            return None if gid == 0 else (gid + delta) & 0xFFFF
        return None

    def has(self, ch: str) -> bool:
        gid = self.glyph_id(ch)
        return gid is not None and gid != 0

    def advance_units(self, ch: str) -> int | None:
        """从 hmtx 取步进（字体单位）。超出 num_hmetrics 的字形沿用最后一条。"""
        gid = self.glyph_id(ch)
        if gid is None:
            return None
        idx = min(gid, self.num_hmetrics - 1)
        return struct.unpack_from(">H", self.data, self.hmtx + idx * 4)[0]

    def advance_em(self, ch: str) -> float | None:
        units = self.advance_units(ch)
        return None if units is None else units / self.units_per_em

    @property
    def cjk_ratio(self) -> float | None:
        """汉字步进 / 半角步进。== 2 才说明这个字体按"汉字占两格"设计。"""
        m, z = self.advance_em("M"), self.advance_em("中")
        return None if (m is None or z is None) else z / m

    def drawable(self, ch: str) -> bool:
        """**真正的**可用性判定（比查 cmap 强得多）。

        实测到的三个陷阱，这条判据必须同时挡住:
          1. Cascadia Mono（以及 Consolas）的 cmap 映射了汉字，hmtx 也给出宽度，
             但那宽度就等于它自己的半角宽，渲染出来是一排占位方块。
             "有 cmap、有 hmtx" 完全不足以说明"能渲染中文"。
          2. 拿 getbbox 比对 .notdef 也不可靠: 同尺寸下 'M' 与 .notdef 的墨迹框
             一模一样（bbox 反映的是字体自报的行盒，不是字形轮廓）。
          3. PIL 缺字形时不会报错。

        判据: **该字符占几列，步进就该是参照半角宽的几倍**。
        参照取"字体自己的半角宽（'M'）"而不是写死的 0.5em —— Cascadia 的半角是
        0.5859375em，若按 0.5em 判，连 'M' 自己都会被拒。
        """
        if not self.has(ch):
            return False
        cols = char_cols(ch)
        if cols == 0:                            # 组合记号本来就没有前进宽度
            return True
        base = self.advance_em("M")
        adv = self.advance_em(ch)
        if base is None or base <= 0 or adv is None or adv <= 0:
            return False
        return abs(adv / (base * cols) - 1.0) <= 0.15


# --------------------------------------------------------------------------- #
# 字体栈: 中英文分字体，但共用一条基线、共用一套列坐标
# --------------------------------------------------------------------------- #

class FontStack:
    """主字体画西文/符号，回退字体画 CJK，两者按同一栅格对齐。

    这里是整个任务最大的坑，实测数据:
      * CascadiaMono.ttf  upm=2048  半角 = 0.5859375em（不是 0.5！），无中文。
      * simhei.ttf        upm=256   半角 = 0.5em，汉字 = 1.0em，即精确 2:1。
    若用同一个字号画两种字体，SimHei 的汉字只有 0.5em×(字号) 宽，而它应该占
    2 × 0.5859375em×(字号) —— 于是**每出现一个汉字就短 6px**（34px 字号下），
    [PASS] 之后的表格与中文列会全部散开。
    修正: 回退字体按 advance 比例放大字号，并取"汉字正好等于 2 格"的那个字号。
    """

    def __init__(self, font_px: int, *, line_h: int | None = None) -> None:
        self.font_px = font_px
        self.primary_info = FontInfo(PRIMARY_FONT)
        self.fallback_info = FontInfo(FALLBACK_FONT)
        self.fallback_px = self.cjk_px_for(font_px)
        self.primary = ImageFont.truetype(str(PRIMARY_FONT), font_px)
        self.fallback = ImageFont.truetype(str(FALLBACK_FONT), self.fallback_px)
        self.half = self.primary.getlength("M")           # 半角格宽（px）
        self.cell_cjk = self.fallback.getlength("中")      # 汉字格宽（px）== 2×half
        self.ascent = self.primary.getmetrics()[0]
        self.descent = self.primary.getmetrics()[1]
        need = self.ascent + max(self.fallback.getbbox("中")[3],
                                 self.primary.getbbox("Mg")[3])
        self.line_h = max(line_h or 0, need + 1)

    @staticmethod
    def cjk_px_for(font_px: int) -> int:
        """回退字体该用的字号: 按 advance 比例放大，再取"汉字正好占 2 格"的那个值。

        实测: 比例 0.5859375/0.5 = 1.171875 是精确值，但 30px 时 35.156 向下取整成
        35px 会让汉字只有 35px（每字差 1px，长表格会累积成可见错位）；试 px..px+2
        取最接近 2×半角格的那个，30px 下得 36px（36 == 2×18，误差 0）。
        N=22/24/28/30/34/36 上误差均为 0。
        """
        ratio = (FontInfo(PRIMARY_FONT).advance_em("M")
                 / FontInfo(FALLBACK_FONT).advance_em("M"))
        approx = int(font_px * ratio)
        target = ImageFont.truetype(str(PRIMARY_FONT), font_px).getlength("M") * 2
        best, best_err = approx, None
        for cand in (approx, approx + 1, approx + 2):
            got = ImageFont.truetype(str(FALLBACK_FONT), cand).getlength("中")
            err = abs(got - target)
            if best_err is None or err < best_err:
                best, best_err = cand, err
        return best

    def drawable_primary(self, ch: str) -> bool:
        return self.primary_info.drawable(ch)

    def drawable_fallback(self, ch: str) -> bool:
        return self.fallback_info.drawable(ch)


# --------------------------------------------------------------------------- #
# 配色（GitHub dark 风格）
# --------------------------------------------------------------------------- #

BG = (13, 17, 23)
BAR_BG = (22, 27, 34)
FG = (203, 213, 225)
DIM = (110, 118, 129)
GREEN = (63, 200, 118)
RED = (248, 81, 73)
MAGENTA = (219, 97, 162)
YELLOW = (210, 168, 60)
ORANGE = (240, 136, 62)
BLUE = (88, 166, 255)
CYAN = (57, 197, 187)
WHITE = (240, 246, 252)
PURPLE = (188, 140, 255)

SEV_COLOR = {"HIGH": RED, "CRIT": RED, "MED": YELLOW, "LOW": BLUE, "INFO": CYAN}

# 关键词着色（纯展示层，不改变任何字符）。顺序即优先级，先匹配到的先占位。
_KEYWORDS: list[tuple[re.Pattern[str], tuple[int, int, int] | None]] = [
    (re.compile(r"\b(PASS)\b"), GREEN),
    (re.compile(r"\b(FAIL)\b"), RED),
    (re.compile(r"\b(OK)\b"), GREEN),
    (re.compile(r"(DENY)"), RED),
    (re.compile(r"(ALLOW)"), GREEN),
    (re.compile(r"(BROKEN)"), RED),
    (re.compile(r"(未实现动作|警告|提示|这意味着|不得|禁止|仅)"), YELLOW),
    (re.compile(r"(已拒绝|失败|不可信|越界|篡改)"), RED),
    (re.compile(r"(已放行|通过|被检出|生效|完整)"), GREEN),
    (re.compile(r"\b(HIGH|CRIT|MED|LOW|INFO)\b"), None),
    (re.compile(r"((?:[A-Z][A-Z0-9]*-){2,}[A-Z0-9-]+)"), CYAN),
    (re.compile(r"(WSTG-[A-Z]+-\d+)"), DIM),
    (re.compile(r"(https?://[^\s]+)"), BLUE),
    (re.compile(r"\b([0-9a-f]{32,})\b"), ORANGE),
    (re.compile(r"(第 \d+ 行|line \d+|seq=\d+)"), ORANGE),
]


ColumnedSegments = list[tuple[str, tuple[int, int, int], int]]


def colorize(line: str) -> list[tuple[str, tuple[int, int, int]]]:
    if not line:
        return []
    stripped = line.strip()
    base = FG
    if stripped.startswith("[PASS]") or stripped.startswith("[lab]"):
        base = GREEN
    elif stripped.startswith("[FAIL]"):
        base = RED
    elif stripped.startswith("PS ") or stripped.startswith("$"):
        base = WHITE
    elif stripped and set(stripped) <= set("─-="):
        base = DIM

    spans: list[tuple[int, int, tuple[int, int, int]]] = []
    for pattern, color in _KEYWORDS:
        for m in pattern.finditer(line):
            token = m.group(0)
            if color is None:
                if token in SEV_COLOR:
                    col = SEV_COLOR[token]
                elif token in ("已拒绝", "失败", "不可信", "越界", "篡改"):
                    col = RED
                elif token in ("已放行", "通过", "被检出", "生效", "完整"):
                    col = GREEN
                else:
                    continue
            else:
                col = color
            s, e = m.span()
            if any(not (e <= a or s >= b) for a, b, _c in spans):
                continue
            spans.append((s, e, col))

    if not spans:
        return [(line, base)]
    spans.sort()
    out: list[tuple[str, tuple[int, int, int]]] = []
    pos = 0
    for s, e, col in spans:
        if s > pos:
            out.append((line[pos:s], base))
        out.append((line[s:e], col))
        pos = e
    if pos < len(line):
        out.append((line[pos:], base))
    return out


# --------------------------------------------------------------------------- #
# 终端渲染器 —— 按列定位逐字符绘制，保证中英混排严格对齐
# --------------------------------------------------------------------------- #

class TermRenderer:
    def __init__(self, cols: int, rows: int, font_px: int = SCENE_FONT_PX,
                 pad_x: int = 22, pad_y: int = 16, title: str = "",
                 line_h: int | None = None) -> None:
        self.cols, self.rows = cols, rows
        self.stack = FontStack(font_px, line_h=line_h)
        self.font_px = font_px
        self.half = self.stack.half
        self.line_h = self.stack.line_h
        self.pad_x, self.pad_y = pad_x, pad_y
        self.title = title
        self.bar_h = round(font_px * 1.6) if title else 0
        self.width = pad_x * 2 + round(cols * self.half)
        self.height = pad_y * 2 + self.bar_h + rows * self.line_h
        cjk_top = self.stack.fallback.getbbox("中")[1]
        self._tile_h = self.stack.ascent + max(self.stack.descent, 0) \
            + max(-cjk_top, 0) + 6
        self._glyph_cache: dict[tuple[str, int], tuple[Image.Image, int]] = {}
        self.uncovered: set[str] = set()

    # -- 字形 ------------------------------------------------------------- #

    def _pick(self, ch: str) -> ImageFont.FreeTypeFont:
        if self.stack.drawable_primary(ch):
            return self.stack.primary
        if self.stack.drawable_fallback(ch):
            return self.stack.fallback
        self.uncovered.add(ch)
        return self.stack.primary

    def missing_report(self) -> set[str]:
        if self.uncovered:
            raise SystemExit(
                "以下字符两个字体都没有真字形，渲染会变成豆腐块（必须换符号或换字体）: "
                + "".join(sorted(self.uncovered)))
        return self.uncovered

    def cell_width(self, ch: str) -> int:
        c = char_cols(ch)
        return round(2 * self.half) if c == 2 else 0 if c == 0 else round(self.half)

    def _glyph(self, ch: str, color: tuple[int, int, int]) -> tuple[Image.Image, int]:
        """把字符画进一块透明瓦片；瓦片内 baseline 固定在 y = stack.ascent。

        返回 (瓦片, 左内边距)。绘制时要减掉左内边距，让"列"而不是"瓦片左沿"对齐栅格。
        """
        key = (ch, (color[0] << 16) | (color[1] << 8) | color[2])
        cached = self._glyph_cache.get(key)
        if cached is not None:
            return cached
        font = self._pick(ch)
        cell = max(self.cell_width(ch), 1)
        pad = max(4, self.font_px // 4)
        tile = Image.new("RGBA", (cell + pad * 2, self._tile_h), (0, 0, 0, 0))
        ImageDraw.Draw(tile).text((pad, self.stack.ascent), ch, font=font,
                                  fill=color + (255,), anchor="ls")
        self._glyph_cache[key] = (tile, pad)
        return self._glyph_cache[key]

    # -- 绘制 ------------------------------------------------------------- #

    def text_line(self, img: Image.Image, y: int, segments, col: int = 0,
                  _cjk_cols: int | None = None) -> None:
        """按列定位绘制一行。

        横向: 每个字符的起始列 × 半角格宽 = 像素 x。汉字占 2 列、字形来自被放大过的
              SimHei，步进正好 2 格，于是 [PASS] 之后的列不会累积漂移。
        纵向: 所有字符共用一条基线（baseline = 行顶 + 主字体 ascent），"ls" 锚点，
              中英不会上下错位 —— 刻意不采信 SimHei 自报的 ascent。

        segments 两种形态都接受:
          * (text, color) 三元组缺省 —— 列号由 char_cols 现算（正常路径）;
          * (char, color, 显式列号) —— 供 reverse-check 注入"错误排版"用。

        `_cjk_cols` 只给反例自检用: 传 1 就是"把汉字当半角排"的已知错误渲染，用来
        验证判据真的有牙齿。正常出图路径永不传它。
        """
        explicit = bool(segments) and len(segments[0]) == 3
        for seg in segments:
            text, color = seg[0], seg[1]
            if explicit:
                col = seg[2]
            for ch in text:
                if ch != "" and ch != "\t":
                    tile, _pad = self._glyph(ch, color)
                    # 贴图左沿 = 该格的左沿。**不能**再减 pad: pad 是字形自身
                    # 左侧边距（lsb），已经体现在瓦片内部的墨迹位置上了；再减一次
                    # 等于把整行左移一个边距，实测会让锚点判定差 8px。
                    img.paste(tile, (self.pad_x + round(col * self.half),
                                     int(y)), tile)
                step = char_cols(ch)
                if _cjk_cols is not None and step == 2:
                    step = _cjk_cols
                col += step

    def draw_bar(self, img: Image.Image) -> None:
        if not self.title:
            return
        ImageDraw.Draw(img).rectangle([0, 0, self.width, self.bar_h], fill=BAR_BG)
        r = self.font_px // 5
        for i, col in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
            cx = self.pad_x + i * (r * 3)
            ImageDraw.Draw(img).ellipse([cx - r, self.bar_h // 2 - r,
                                         cx + r, self.bar_h // 2 + r], fill=col)
        tfont = ImageFont.truetype(str(PRIMARY_FONT), round(self.font_px * 0.62))
        ImageDraw.Draw(img).text(
            (self.pad_x + 3 * (r * 3) + 8, self.bar_h // 2),
            "PowerShell  ·  " + self.title, font=tfont, fill=DIM, anchor="lm")


# --------------------------------------------------------------------------- #
# 布局: 把真实输出塞进固定列宽，并加上标题栏与图注
# --------------------------------------------------------------------------- #

def wrap_display(text: str, cols: int) -> list[str]:
    """按**显示列**折行（汉字算 2 列），续行保留原始缩进。

    CJK 描述行很长，按字符数折会溢出画布右侧；按显示列折才与栅格一致。
    续行前加 `↩`，明确表示"同一行被折了"，不是 CLI 新起了一行。
    """
    if display_cols(text) <= cols:
        return [text]
    indent = len(text) - len(text.lstrip(" "))
    out: list[str] = []
    cur, cur_w = "", 0
    limit = cols
    pad = " " * indent
    for ch in text:
        w = char_cols(ch)
        if cur_w + w > limit and cur:
            out.append(cur)
            cur, cur_w = "", 0
            limit = cols - 2
            pad = " " * indent + "↩ "
        if not cur:
            cur = pad
            cur_w = display_cols(pad)
        cur += ch
        cur_w += w
    if cur:
        out.append(cur)
    return out


def fit(lines: list[str], cols: int) -> list[str]:
    """把真实输出折行到画布宽度内；折不动又超长的行做省略。"""
    out: list[str] = []
    for ln in lines:
        for p in wrap_display(ln, cols):
            if display_cols(p) > cols:
                acc, w = "", 0
                for ch in p:
                    if w + char_cols(ch) > cols - 2:
                        break
                    acc += ch
                    w += char_cols(ch)
                p = acc + " …"
            out.append(p)
    return out


def capture_text(label: str) -> list[str]:
    p = CAPTURE / f"{label}.txt"
    if not p.exists():
        raise SystemExit(f"缺少采集文件: {p}（先运行不带 --render-only 的完整流程）")
    return p.read_text(encoding="utf-8").splitlines()


# --------------------------------------------------------------------------- #
# 场景定义 —— 每个场景 = 一条真实命令 + 它的真实输出 + 一句话说明证明了什么
# --------------------------------------------------------------------------- #

SCENES: list[tuple[str, str, str, tuple[str, str]]] = [
    ("02-doctor", "doctor",
     "python -m ptpipeline doctor",
     ("SELF-CHECK 13/13 PASS",
      "doctor 用 13 项内置断言在动网之前自检：越界目标必须被拒、授权目标必须被放行、"
      "账本哈希链必须可验、被篡改的记录必须被检出。全绿才允许继续。")),

    ("03-probe", "probe",
     "python -m ptpipeline probe http://127.0.0.1:8080/ --ledger … --out …",
     ("PROBE 10 FINDINGS  (8 可直接确认 / 2 需人工复核)",
      "纯 Python 的 16 条规则（分 6 组）对本地靶场做非侵入式探测，产出 10 条结论："
      "每条都带 OWASP WSTG 编号、置信度与修复建议，并写入哈希链账本 —— "
      "全过程没有一条注入或爆破载荷。")),

    ("04-audit-ok", "audit-ok",
     "python -m ptpipeline audit --ledger … --show",
     ("AUDIT: CHAIN INTACT  (exit 0)",
      "账本每写一条就把前一条的哈希卷进本条，形成哈希链。审计逐行重算，链路完整时"
      "退出码为 0，可以直接接进 CI 当门禁。")),

    ("05-audit-tampered", "audit-tampered-show",
     "python -m ptpipeline audit --ledger … --show",
     ("TAMPERED RECORD PINPOINTED: 第 3 行, seq=2",
      "把第 3 行记录的 target 改成越界 IP（一次显式的合成篡改）后，审计不仅报出 BROKEN，"
      "还精确定位到第 3 行、seq=2、content was modified after write —— "
      "证据链的作用正在于此：被改过的记录藏不住。")),

    ("06-verify", "verify",
     "python scripts/verify_pipeline.py",
     ("VERIFY 33/33 PASS, 0 FAIL",
      "端到端回归 33 项断言全部通过、0 项失败，覆盖范围判定、探测规则、账本哈希链、"
      "篡改检出与写入保护。")),
]


def render_scene(key: str, raw_lines: list[str], title: str,
                 caption: tuple[str, str], out_dir: Path,
                 cols: int = SCENE_COLS) -> Path:
    """渲染一个场景（标题栏 + 真实输出 + 图注）。"""
    body = fit(raw_lines, cols)
    rend = TermRenderer(cols, len(body), font_px=SCENE_FONT_PX, title=title)
    term = Image.new("RGB", (rend.width, rend.height), BG)
    rend.draw_bar(term)
    for i, line in enumerate(body):
        rend.text_line(term, rend.pad_y + rend.bar_h + i * rend.line_h,
                       colorize(line))
    rend.missing_report()

    # --- 图注: 加粗断语 + 中文说明，都走回退字体（汉字成对占格，断行才准） ---
    band = round(SCENE_FONT_PX * 0.62)
    cfont = ImageFont.truetype(str(FALLBACK_FONT), band + 8)
    sfont = ImageFont.truetype(str(FALLBACK_FONT), band)
    mfont = ImageFont.truetype(str(PRIMARY_FONT), band)
    pad = 22
    desc_lines = wrap_display(caption[1], cols - 4)
    note = "由真实 CLI 输出逐帧渲染, 非屏幕录制。"
    cap_h = pad + (band + 12) + len(desc_lines) * (band + 10) + band + pad

    img = Image.new("RGB", (rend.width, rend.height + cap_h), BG)
    img.paste(term, (0, 0))
    d = ImageDraw.Draw(img)
    y = rend.height + pad
    d.text((pad, y), caption[0], font=cfont, fill=WHITE)
    y += band + 12
    for line in desc_lines:
        d.text((pad, y), line, font=sfont, fill=FG)
        y += band + 10
    y += 4
    tag = "SCENE " + key.split("-")[0]
    d.text((pad, y), tag, font=mfont, fill=ORANGE)
    d.text((pad + d.textlength(tag, font=mfont) + 14, y), note, font=sfont, fill=DIM)

    path = out_dir / f"{key}.png"
    img.save(path, optimize=True)
    return path


def render_hero(raw_lines: list[str], title: str, out_dir: Path) -> Path:
    """头部主图: 越界目标被 DENY 那一屏 —— 最能体现差异化的画面。"""
    cols, font_px = 104, 36
    body = fit(raw_lines, cols)
    rend = TermRenderer(cols, len(body), font_px=font_px, title=title)
    term = Image.new("RGB", (rend.width, rend.height), BG)
    rend.draw_bar(term)
    for i, line in enumerate(body):
        rend.text_line(term, rend.pad_y + rend.bar_h + i * rend.line_h,
                       colorize(line))
    rend.missing_report()

    top = round(font_px * 1.15)
    pad = 26
    hfont = ImageFont.truetype(str(FALLBACK_FONT), top)
    sfont = ImageFont.truetype(str(FALLBACK_FONT), round(top * 0.46))
    header = top * 2 + pad
    img = Image.new("RGB", (rend.width, rend.height + header + pad), BG)
    img.paste(term, (0, header))
    d = ImageDraw.Draw(img)
    d.text((pad, pad - 6), "越界目标, 一步都不走", font=hfont, fill=WHITE)
    d.text((pad + 4, pad - 6 + top + 4),
           "ptpipeline · 授权范围强制的渗透测试流水线 · 每一次动作都有据可查",
           font=sfont, fill=CYAN)
    path = out_dir / "00-hero-scope-deny.png"
    img.save(path, optimize=True)
    return path


# --------------------------------------------------------------------------- #
# GIF: 逐帧渲染演示（scope 拒绝 -> probe 检测 -> audit 校验 -> 篡改定位）
# --------------------------------------------------------------------------- #

GIF_CANVAS_W = 1400        # 画布目标宽度；GitHub README 里再宽也会被缩到容器宽
GIF_COLS = SCENE_COLS      # GIF 与静态图用同一列宽，折行结果完全一致
GIF_VIEW = 22              # 视窗行数：只显示 22 行并跟随输出滚动，字号才放得够大
GIF_GAP = 20               # 帧底部留白
GIF_STEPS = 6              # 每个场景分几步揭示（首屏 -> 全量）
GIF_HOLD_MS = {"head": 300, "step": 480, "scene": 760, "tail": 2400}

# 演示走位（用户要的四步）: scope 拒绝 -> probe 检测 -> audit 校验 -> 篡改被精确定位。
# 全程只调用 ptpipeline 自己的真实子命令，每一帧都是其真实 stdout 的重排绘制。
GIF_SCENES: list[tuple[str, str, str, str]] = [
    ("scope-deny", "越界目标被拒",
     "python -m ptpipeline scope --target https://www.baidu.com/",
     "EXIT 1  ·  DENY"),
    ("probe", "非侵入式探测出结论",
     "python -m ptpipeline probe http://127.0.0.1:8080/",
     "EXIT 0  ·  10 FINDINGS"),
    ("audit-ok", "账本哈希链完整",
     "python -m ptpipeline audit --ledger demo-ledger.jsonl --show",
     "EXIT 0  ·  CHAIN INTACT"),
    # 这里刻意用**不带 --show** 的 audit-tampered: 带 --show 时记录明细有 90 余行,
    # 22 行视窗滚到底只剩记录表, 最关键的那句「完整性: BROKEN —— 第 3 行: hash
    # mismatch at seq=2」反而被滚出画面。不带 --show 只有 32 行, 结论行留在末帧。
    ("audit-tampered", "篡改记录被精确定位",
     "python -m ptpipeline audit --ledger demo-ledger.jsonl",
     "EXIT 1  ·  BROKEN at line 3"),
]


def _gif_font_px(rows: list[int], canvas_w: int) -> int:
    """选一个刚好放得下最宽场景的字号（列宽换算是精确的，见 FontStack.half）。"""
    worst_cols = max(max(r, 1) for r in rows)
    for px in range(30, 13, -1):
        half = FontStack(px).half
        if 44 + round(worst_cols * half) <= canvas_w:
            return px
    return 14


def _gif_follow(upto: int) -> int:
    """视窗顶部行号：输出没超过一屏就贴顶，超过之后开始跟着往下滚。

    （第一版把视窗直接钉在"最长场景的末尾"，结果短场景整段显示空白区：
      probe 的视窗顶被算成 28，前 22 行全被跳过，4 帧画面一模一样。）
    """
    return max(0, upto - GIF_VIEW)


def _gif_timeline() -> list[tuple[str, int, int, int]]:
    """展开成 (capture 标签, 揭示到第几行, 时长 ms, 场景序号) 的逐帧计划。

    每个场景从"整屏空白"开始（终端刚敲下命令、还没输出），再分成 GIF_STEPS 步把
    真实输出揭示完，末尾停住。行数取真实输出的行数，不预先假设任何一屏有多长。
    """
    tl: list[tuple[str, int, int, int]] = []
    for si, (label, _, _, _) in enumerate(GIF_SCENES):
        lines = fit(capture_text(label), GIF_COLS)
        n = max(1, len(lines))
        ks = {0} | {max(1, round(n * k / GIF_STEPS)) for k in range(1, GIF_STEPS + 1)}
        marks = sorted(k for k in ks if k <= n)
        if marks[-1] != n:
            marks.append(n)
        for j, upto in enumerate(marks):
            if j == 0:
                dur = GIF_HOLD_MS["head"] if si == 0 else GIF_HOLD_MS["scene"]
            elif j == len(marks) - 1:
                dur = GIF_HOLD_MS["tail"] if si == len(GIF_SCENES) - 1 \
                    else GIF_HOLD_MS["scene"]
            else:
                dur = GIF_HOLD_MS["step"]
            tl.append((label, upto, dur, si))
    return tl


def build_gif(out_dir: Path, max_bytes: int = 2 * 1024 * 1024) -> Path:
    """逐帧渲染的演示动画（**不是屏幕录制**）。

    README 必须如实标注：每一帧都是把 CLI 的真实输出重新排版绘制的，没有任何一帧
    来自录屏，也没有一个字符是编造的。帧内容 = 上一条真实命令的真实 stdout/stderr。

    体积控制：
      1. 全程 `rows` 固定 -> 每一帧尺寸完全一致，GIF 帧差最小（错位一像素都会让
         帧差编码失效，体积翻倍）；
      2. 首帧建调色板，其余帧绑定同一全局调色板（Pillow 逐帧各建调色板会暴涨）；
      3. 文字是纯色 + 抗锯齿灰阶，32 色足够，量化误差看不出来。
    """
    import io

    body_cols = [max(display_cols(l) for l in fit(capture_text(lab), GIF_COLS))
                 for lab, *_ in GIF_SCENES]
    font_px = _gif_font_px(body_cols, GIF_CANVAS_W)
    rows = max(len(fit(capture_text(lab), GIF_COLS)) for lab, *_ in GIF_SCENES)
    rend = TermRenderer(GIF_COLS, GIF_VIEW, font_px=font_px, title="ptpipeline demo")
    height = rend.height + GIF_GAP
    print(f"    GIF 布局 字号={font_px}px 列宽={GIF_COLS} 视窗={GIF_VIEW} 行"
          f"(最长场景 {rows} 行) 画布={rend.width}×{height}")

    cap_px = round(font_px * 0.62)
    cf = ImageFont.truetype(str(FALLBACK_FONT), cap_px + 2)
    cap_h = cap_px + 26

    def draw_scene(si: int, upto: int) -> Image.Image:
        label, cap, cmd, tag = GIF_SCENES[si]
        lines = fit(capture_text(label), GIF_COLS)
        first = _gif_follow(upto)
        rend.title = "ptpipeline demo  ·  " + cap
        img = Image.new("RGB", (rend.width, height), BG)
        rend.draw_bar(img)
        for i in range(GIF_VIEW):
            src = first + i
            if src >= min(upto, len(lines)):
                break
            y = rend.pad_y + rend.bar_h + i * rend.line_h
            rend.text_line(img, y, colorize(lines[src]))
        if upto >= len(lines):
            rend.missing_report()
        d = ImageDraw.Draw(img)
        d.rectangle([0, height - cap_h, rend.width, height], fill=BAR_BG)
        d.text((rend.pad_x, height - cap_h + 8), cmd, font=cf,
               fill=WHITE if upto > 0 else DIM)
        tw = d.textlength(cmd, font=cf)
        d.text((rend.pad_x + tw + 18, height - cap_h + 8), tag, font=cf, fill=ORANGE)
        return img

    plan = _gif_timeline()
    print(f"    GIF 时间线 {len(plan)} 步, 总时长 "
          f"{sum(p[2] for p in plan) / 1000:.1f}s")

    def assemble(scale: float, colors: int) -> tuple[bytes, int]:
        frames: list[Image.Image] = []
        durs: list[int] = []
        for label, upto, dur, si in plan:
            # 画面身份 = (场景, 揭示行数, 视窗顶) —— 视窗滚动同样换帧。
            key = (si, upto, _gif_follow(upto))
            if frames and frames[-1].info.get("_key") == key:
                # 同一画面连续出现: 只把停留时长并进上一帧, 不多编一帧。
                durs[-1] += dur
                continue
            im = draw_scene(si, upto)
            if scale != 1.0:
                im = im.resize((max(2, round(im.width * scale)),
                                max(2, round(im.height * scale))), Image.LANCZOS)
            im.info["_key"] = key
            frames.append(im)
            durs.append(dur)

        # 全局调色板 —— 这一步是 GIF 成败的关键，踩过两次坑，都记在这里：
        #   ① 起初只抽 5 帧当样本量化：那 5 帧恰好都是"刚起步、几乎空白"的画面，
        #      调色板里没有正文那些青/绿/白/橙的层次，后续帧一量化文字全被映射到
        #      同一个近邻索引 —— 28 帧两两相同，Pillow 按"重复帧"合并掉，只剩 8 帧。
        #   ② 改成"把所有帧出现过的 RGB 颜色塞进一张 1 像素高的长条再 quantize"，
        #      方向对但 Pillow 在这里不按预期工作：量化后的帧大片塌成同一索引，
        #      正文整块消失（实测未量化帧 125902 个非背景像素, 量化后文字全没了）。
        #   现在的做法：把**每一帧**原样贴到一张高条带上，对它做一次教科书式的
        #   quantize(colors=N, MEDIANCUT)，取它的调色板当全局板；再让每帧
        #   `quantize(palette=pal)` 到这个板上。所有帧都参与建板，顺序无关。
        sheet = Image.new("RGB", (frames[0].width, frames[0].height * len(frames)))
        for i, f in enumerate(frames):
            sheet.paste(f, (0, i * f.height))
        pal = sheet.quantize(colors=colors, method=Image.MEDIANCUT)
        sheet.close()
        print(f"      调色板: {len(frames)} 帧合成 {pal.width}×{pal.height} 取样 -> "
              f"{colors} 色")

        quant = [f.quantize(palette=pal, dither=Image.NONE) for f in frames]
        for q, d in zip(quant, durs):
            q.info["duration"] = d
        buf = io.BytesIO()
        quant[0].save(buf, format="GIF", save_all=True, append_images=quant[1:],
                      loop=0, optimize=True, disposal=2, duration=durs)
        return buf.getvalue(), len(quant)

    best: bytes | None = None
    n_frames = 0
    for scale, colors in ((1.0, 64), (1.0, 32), (0.88, 32), (0.78, 24), (0.68, 16)):
        data, nf = assemble(scale, colors)
        print(f"    GIF 尝试 缩放={scale:.2f} 色深={colors} -> "
              f"{len(data) / 1024:6.0f} KB / {nf} 帧")
        if best is None or len(data) < len(best):
            best, n_frames = data, nf
        if len(data) <= max_bytes:
            break
    assert best is not None
    path = out_dir / "demo.gif"
    path.write_bytes(best)
    with Image.open(path) as chk:
        n = getattr(chk, "n_frames", 1)
        w, h = chk.size
    print(f"    GIF 最终 {len(best) / 1024:.0f} KB / PIL 读回 {n} 帧(写入 {n_frames}) / "
          f"{w}×{h} ({'在' if len(best) <= max_bytes else '超出'} 2MB 限制内, "
          f"逐帧渲染非录屏)")
    return path


# --------------------------------------------------------------------------- #
# 字体 / 列宽 / 对齐 的验证
# --------------------------------------------------------------------------- #

def _tick(ok: bool, msg: str, soft: bool = False) -> str:
    tag = "PASS" if ok else ("NOTE" if soft else "FAIL")
    print(f"  [{tag}] {msg}")
    return "" if ok else msg


def assert_font_invariants() -> None:
    report: list[str] = []
    print("字体与列宽不变量验证")
    print("─" * 74)

    primary = FontInfo(PRIMARY_FONT)
    fallback = FontInfo(FALLBACK_FONT)
    half = primary.advance_em("M")
    cjk_em = fallback.advance_em("中")
    print(f"  primary  = {PRIMARY_FONT.name}  (upm={primary.units_per_em}, "
          f"半角={half}em, mapped={len(primary.coverage)})")
    print(f"  fallback = {FALLBACK_FONT.name}  (upm={fallback.units_per_em}, "
          f"汉字={cjk_em}em, mapped={len(fallback.coverage)})")

    # 1) 主字体半角等宽
    r = _tick(primary.advance_em("M") == primary.advance_em("i") == half,
              f"CascadiaMono 半角等宽: 'M'={half} 'i'={primary.advance_em('i')}")
    report += [r] if r else []

    # 2) 制表/符号必须与半角同宽，否则 [PASS] 之后的边框与表格会错位
    bad_w = {c: primary.advance_em(c) for c in REQUIRED_SYMBOLS
             if primary.drawable(c) and primary.advance_em(c) != half}
    r = _tick(not bad_w,
              f"制表/符号宽度 == 半角 ({half}em); 异常: {bad_w or '无'}")
    report += [r] if r else []
    missing = [c for c in REQUIRED_SYMBOLS if not primary.drawable(c)]
    if missing:
        _tick(False, f"主字体缺以下符号字形: {''.join(missing)} "
                     f"(语料中未使用; 若要用必须换符号)", soft=True)

    # 3) 主字体必须**不能**渲染 CJK —— 这是"必须走回退字体"的前提
    covered = [c for c in "测试范围证据链网络" if primary.drawable(c)]
    r = _tick(not covered,
              f"CascadiaMono 不能渲染汉字 -> 必须走回退字体 "
              f"(意外可渲染: {''.join(covered) or '无'})")
    report += [r] if r else []

    # 4) 回退字体: 汉字步进必须是自身半角步进的**精确 2 倍**
    r = _tick(fallback.cjk_ratio == 2.0,
              f"SimHei 汉字/半角步进比 == 2 (实测 {fallback.cjk_ratio}, 中={cjk_em}em)")
    report += [r] if r else []
    fb_m = fallback.advance_em("M")
    fb_ascii = {c: fallback.advance_em(c) for c in "ABGabcdefg0123456789.:-_/|"}
    odd = {c: w for c, w in fb_ascii.items() if w != fb_m}
    r = _tick(not odd, f"SimHei 半角 ASCII 等宽 (={fb_m}em); 异常: {odd or '无'}")
    report += [r] if r else []

    # 5) 回退字体覆盖语料里每一个非 ASCII 字符（用 drawable，不用 has）
    needed: set[str] = set()
    for txt in CAPTURE.glob("*.txt"):
        needed |= {c for c in txt.read_text(encoding="utf-8") if ord(c) > 0x7F}
    uncovered = sorted(c for c in needed
                       if not primary.drawable(c) and not fallback.drawable(c))
    r = _tick(not uncovered,
              f"语料中每个非 ASCII 字符都有字体覆盖 (缺: {''.join(uncovered) or '无'}, "
              f"共 {len(needed)} 个不同字符)")
    report += [r] if r else []

    # 6) 列宽函数与真实墨迹宽度必须一致 —— 这条才是"中英混排对齐"的真正保证
    px = 30
    base = ImageFont.truetype(str(PRIMARY_FONT), px).getlength("M")
    cjk_px = FontStack.cjk_px_for(px)
    cjk_cell = ImageFont.truetype(str(FALLBACK_FONT), cjk_px).getlength("中")
    mismatch: dict[str, str] = {}
    for ch in sorted(needed):
        cols = char_cols(ch)
        if cols == 0:
            continue
        info, fpx = ((fallback, cjk_px) if cols == 2 else (primary, px))
        if not info.drawable(ch):
            continue
        got = ImageFont.truetype(str(info.path), fpx).getlength(ch)
        want = cjk_cell if cols == 2 else base
        if abs(got - want) > 0.5:
            mismatch[ch] = f"声明 {cols} 列 / 实画 {got}px (应为 {want:.1f}px)"
    r = _tick(not mismatch,
              f"每个非 ASCII 字符的实画宽度 == 其列宽声明×格宽 (不符: {mismatch or '无'})")
    report += [r] if r else []

    # 7) 单倍宽非 ASCII 必须显式登记进 AMBIGUOUS_HALF —— 白名单，不是"漏了处理"
    unlisted = sorted(c for c in needed
                      if char_cols(c) == 1 and c not in AMBIGUOUS_HALF)
    for ok, msg in (
        (not unlisted, f"单倍宽非 ASCII 均已登记为 Ambiguous 半角 "
                       f"(未登记: {unlisted or '无'})"),
        (bool(AMBIGUOUS_HALF) and all(unicodedata.east_asian_width(c) == "A"
                                      for c in AMBIGUOUS_HALF),
         f"AMBIGUOUS_HALF 中 {len(AMBIGUOUS_HALF)} 个字符的 East Asian Width 均为 "
         f"'A' ({'、'.join(AMBIGUOUS_HALF)})"),
        (all(char_cols(c) == 1 for c in AMBIGUOUS_HALF),
         "AMBIGUOUS_HALF 中每个字符的列宽均为 1"),
        (char_cols("中") == 2 and char_cols("Ａ") == 2 and char_cols("。") == 2,
         "全角字符（中 / Ａ / 。）列宽 == 2"),
        (char_cols("A") == 1 and char_cols("\u0301") == 0,
         "半角 'A' 列宽 == 1, 组合记号列宽 == 0"),
    ):
        r = _tick(ok, msg)
        report += [r] if r else []

    # 8) 盒绘制/箭头字符在主字体里都是半角
    boxy = [chr(c) for c in list(range(0x2500, 0x2580)) + list(range(0x2190, 0x2200))]
    boxy = [c for c in boxy if primary.drawable(c)]
    r = _tick(all(primary.advance_em(c) == half for c in boxy),
              f"CascadiaMono 盒绘制/箭头字符均为半角（实测 {len(boxy)} 个）")
    report += [r] if r else []

    # 9) 决定性判据: 真实字号下汉字像素步进必须**正好等于** 2 个半角格
    drift: dict[str, float] = {}
    for n in (22, 24, 28, 30, 34, 36):
        b = ImageFont.truetype(str(PRIMARY_FONT), n).getlength("M")
        c = FontStack.cjk_px_for(n)
        got = ImageFont.truetype(str(FALLBACK_FONT), c).getlength("中")
        drift[f"主{n}px/中{c}px"] = round(got - 2 * b, 3)
    r = _tick(all(abs(v) < 0.5 for v in drift.values()),
              f"汉字步进 == 2×半角格（误差 px: {drift}）")
    report += [r] if r else []

    # 10) 逐字符步进 == 整串步进（确认没有字距调整干扰）
    sample = ("  [PASS] 篡改被检出: broken_at=line 3 -> hash mismatch at seq=2 "
              "(WSTG-CONF-07, 置信度=high)")
    f = ImageFont.truetype(str(PRIMARY_FONT), 34)
    per = sum(f.getlength(c) for c in sample)
    r = _tick(abs(per - f.getlength(sample)) < 0.01,
              f"逐字符步进 == 整串步进（无字距调整干扰, {f.getlength(sample):.2f}px）")
    report += [r] if r else []

    print("─" * 74)
    if report:
        raise SystemExit("字体验证未通过:\n" + "\n".join(report))


def _synth_wrong_cjk_line(text: str) -> "ColumnedSegments":
    """故意把汉字当 **1 列** 排版的错误版本 —— 反证检查器真的有牙齿。

    一个"永远通过"的对齐断言毫无价值。这里人为复制出"汉字被当成半角"这个 bug
    （正是本任务要防的坑），产出一组**显式列号**，绕开 char_cols 交给渲染器，
    检查器必须把它检出来，否则判据就是空的。
    """
    out: ColumnedSegments = []
    col, done = 0, False
    for ch in text:
        n = 1 if (done or char_cols(ch) != 2) else 2
        if n == 2:
            done = True
        out.append((ch, FG, col))
        col += n
    return out


def _ink_runs(px: Image.Image, x0: int, x1: int, y0: int, y1: int,
              thresh: int = 70) -> list[tuple[int, int]]:
    x0, x1 = max(0, x0), min(px.width, x1)
    y0, y1 = max(0, y0), min(px.height, y1)
    if x1 <= x0 or y1 <= y0:
        return []
    crop = px.crop((x0, y0, x1, y1))
    w, h = crop.size
    data = crop.tobytes()          # 'L' 模式: 每像素 1 字节, 比 getdata() 快且无弃用告警
    runs: list[tuple[int, int]] = []
    cur: list[int] | None = None
    for x in range(w):
        hit = any(data[y * w + x] > thresh for y in range(h))
        if hit:
            if cur is None:
                cur = [x0 + x, x0 + x]
            else:
                cur[1] = x0 + x
        elif cur is not None:
            runs.append((cur[0], cur[1]))
            cur = None
    if cur is not None:
        runs.append((cur[0], cur[1]))
    return runs


def _ink_bounds(px: Image.Image, x0: int, x1: int, y0: int, y1: int,
                thresh: int = 70) -> tuple[int, int] | None:
    """一行在给定横向窗口内的墨迹首/末像素 x（无墨迹返回 None）。"""
    runs = _ink_runs(px, x0, x1, y0, y1, thresh)
    if not runs:
        return None
    return runs[0][0], runs[-1][1]


def _row_ink(px: Image.Image, rend: TermRenderer, row: int) -> tuple[int, int] | None:
    top = rend.pad_y + row * rend.line_h
    return _ink_bounds(px, 0, rend.width, top, top + rend.line_h)


def _broken_renderer(text: str) -> ColumnedSegments:
    """把汉字当 **1 列** 排版的错误渲染（正是本任务要防的那个 bug）。"""
    return _synth_wrong_cjk_line(text)


def _ink_width_of(text: str, rend: TermRenderer, img: Image.Image,
                  y: int) -> int:
    runs = _ink_runs(img, 0, rend.width, y, y + rend.line_h)
    return 0 if not runs else runs[-1][1] - runs[0][0]


def _runs_near(img: Image.Image, rend: TermRenderer, row: int,
               col_lo: int, col_hi: int) -> list[tuple[int, int]]:
    return _ink_runs(img, rend.pad_x + round(col_lo * rend.half) - 3,
                     rend.pad_x + round(col_hi * rend.half) + 3,
                     rend.pad_y + row * rend.line_h,
                     rend.pad_y + (row + 1) * rend.line_h)


ANCHOR = "M"          # 专挑笔直、左右对称、无连字的半角字形当锚点
INK_THRESH = 40       # 主字体反锯齿边缘很暗，阈值放到 40 才量得准墨迹起点


def _trailing_ink_x(img: Image.Image, rend: TermRenderer, row: int,
                    left_guess: int, thresh: int = INK_THRESH) -> int | None:
    """返回本行**最后一段墨迹**的左沿 x；用于量一个行尾锚点的真实落位。

    为什么不用 `pad_x + col×half` 这类公式去算: 两个字体的 lsb 不同，而且我自己
    实测下来"公式值"和"墨迹实际值"能差到 8px（半角）—— 拿公式值去比，比的是记账
    误差，不是对齐。所以这里一律**量墨迹**，预测值只用来框定一个窄窗口，避免撞上
    行中间别的字形。
    """
    x0 = max(0, left_guess - 10)
    x1 = min(rend.width, left_guess + round(rend.half) + 6)
    top = rend.pad_y + row * rend.line_h
    runs = _ink_runs(img, x0, x1, top, top + rend.line_h, thresh)
    return runs[-1][0] if runs else None


def _rightmost_ink_x(img: Image.Image, rend: TermRenderer, row: int,
                     thresh: int = INK_THRESH) -> int | None:
    """本行最右侧那段墨迹的左沿 x。行尾锚点就量它。"""
    top = rend.pad_y + row * rend.line_h
    runs = _ink_runs(img, 0, rend.width, top, top + rend.line_h, thresh)
    return runs[-1][0] if runs else None


def _render_pair(pairs: list[tuple[str, str]], cols: int, font_px: int,
                 width_cjk: int | None = None) -> tuple[TermRenderer, Image.Image]:
    """把每对 (上行, 下行) 各渲染一行。

    `width_cjk` 非空时按"汉字只占 width_cjk 列"排版 —— 专门用来造一个**已知错误**
    的渲染，检验判据有没有牙齿。
    """
    rend = TermRenderer(cols, len(pairs) * 2, font_px=font_px, title="")
    img = Image.new("RGB", (rend.width, rend.height), BG)
    for i, (top_line, bot_line) in enumerate(pairs):
        rend.text_line(img, rend.pad_y + (2 * i) * rend.line_h,
                       colorize(top_line), _cjk_cols=width_cjk)
        rend.text_line(img, rend.pad_y + (2 * i + 1) * rend.line_h,
                       colorize(bot_line), _cjk_cols=width_cjk)
    rend.missing_report()
    return rend, img


def _cell_ink_x(img: Image.Image, rend: TermRenderer, row: int, col: int,
                width_cols: int, thresh: int = INK_THRESH) -> int | None:
    """第 row 行、第 col 列、宽 width_cols 列的那一格里的墨迹左沿 x。

    窗口按"汉字 2 格"贴着格子开，前让 4px 给左侧边距，后让 2px 给反锯齿。
    """
    x0 = rend.pad_x + round(col * rend.half) - 4
    x1 = rend.pad_x + round((col + width_cols) * rend.half) + 2
    top = rend.pad_y + row * rend.line_h
    runs = _ink_runs(img, x0, x1, top, top + rend.line_h, thresh)
    return runs[0][0] if runs else None


def _render_rows(rows: list[str], cols: int, font_px: int,
                 width_cjk: int | None = None) -> tuple[TermRenderer, Image.Image]:
    """逐个渲染给定的行；`width_cjk` 用来造"汉字按 1 列排版"的已知错误渲染。"""
    rend = TermRenderer(cols, len(rows), font_px=font_px, title="")
    img = Image.new("RGB", (rend.width, rend.height), BG)
    for r, line in enumerate(rows):
        rend.text_line(img, rend.pad_y + r * rend.line_h, colorize(line),
                       _cjk_cols=width_cjk)
    rend.missing_report()
    return rend, img


def _marker_ink(grey: Image.Image, rend: TermRenderer, row: int,
                col: int) -> tuple[int, int] | None:
    """行尾 '#' 标记的墨迹区间。标记写在该行最后一列，其右全是背景，所以取
    本行最后一段墨迹即可 —— 不用猜窗口。"""
    top = rend.pad_y + row * rend.line_h
    runs = _ink_runs(grey, 0, rend.width, top, top + rend.line_h)
    return runs[-1] if runs else None


def _cjk_pool(limit: int = 96) -> str:
    """从**真实采集输出**里抽一批互不相同的汉字，专供对齐验证当样本用。

    刻意不硬编码字表: 样本必须来自这次真跑出来的文本，验证才算验证了这批素材。
    """
    seen: list[str] = []
    for p in sorted(CAPTURE.glob("*.txt")):
        for ch in p.read_text(encoding="utf-8", errors="ignore"):
            if char_cols(ch) == 2 and ch not in seen:
                seen.append(ch)
                if len(seen) >= limit:
                    return "".join(seen)
    return "".join(seen)


def _render_rows(rows: list[str], cols: int, font_px: int,
                 width_cjk: int | None = None) -> tuple[TermRenderer, Image.Image]:
    """逐个渲染给定的行；`width_cjk` 用来造"汉字按 1 列排版"的已知错误渲染。"""
    rend = TermRenderer(cols, len(rows), font_px=font_px, title="")
    img = Image.new("RGB", (rend.width, rend.height), BG)
    for r, line in enumerate(rows):
        rend.text_line(img, rend.pad_y + r * rend.line_h, colorize(line),
                       _cjk_cols=width_cjk)
    rend.missing_report()
    return rend, img


def _cjk_span_check(rows: list[str], cols: int, font_px: int,
                    want: float, width_cjk: int | None = None
                    ) -> tuple[float | None, str]:
    """渲染 rows 并量第 0 行行尾 '#' 的墨迹左沿；返回 (与应有位置的误差, 说明)。"""
    rend, img = _render_rows(rows, cols, font_px, width_cjk=width_cjk)
    grey = img.convert("L")
    m = _marker_ink(grey, rend, 0, 0)
    if m is None:
        return None, f"第 0 行没有墨迹 (rows={rows!r})"
    return m[0] - want, f"实测 x={m[0]}, 应有 x={want:.0f} (half={rend.half})"


def _marker_ink(grey: Image.Image, rend: TermRenderer, row: int,
                col: int) -> tuple[int, int] | None:
    """行尾 '#' 标记的墨迹区间。标记写在该行最后一列，其右全是背景，所以取
    本行最后一段墨迹即可 —— 不用猜窗口。"""
    top = rend.pad_y + row * rend.line_h
    runs = _ink_runs(grey, 0, rend.width, top, top + rend.line_h)
    return runs[-1] if runs else None


def _blank_out(text: str) -> str:
    """把载荷变成"同列宽的空白" —— 每个字符换成与它等列宽的空格。

    必须逐字符换、且用 display_cols 而不是"汉字数 × 2": 载荷里的 ASCII（数字、逗号、
    括号、WSTG 编号）也要留出同样多的空格，否则下行总列数比上行少一截，行尾 '#' 自然
    对不上（第一版就是只补了汉字那部分，实测每条载荷都差十几到几十像素）。
    """
    return "".join(" " * char_cols(ch) for ch in text)


def _cjk_pool(limit: int = 30) -> str:
    """从**真实采集输出**里抽一批互不相同的汉字，专供对齐验证当样本用。

    刻意不硬编码字表: 样本必须来自这次真跑出来的文本，验证才算验证了这批素材。
    """
    seen: list[str] = []
    for p in sorted(CAPTURE.glob("*.txt")):
        for ch in p.read_text(encoding="utf-8", errors="ignore"):
            if char_cols(ch) == 2 and ch not in seen:
                seen.append(ch)
                if len(seen) >= limit:
                    return "".join(seen)
    return "".join(seen)


def _render_rows(rows: list[str], cols: int, font_px: int,
                 width_cjk: int | None = None) -> tuple[TermRenderer, Image.Image]:
    """逐个渲染给定的行；`width_cjk` 用来造"汉字按 1 列排版"的已知错误渲染。"""
    rend = TermRenderer(cols, len(rows), font_px=font_px, title="")
    img = Image.new("RGB", (rend.width, rend.height), BG)
    for r, line in enumerate(rows):
        rend.text_line(img, rend.pad_y + r * rend.line_h, colorize(line),
                       _cjk_cols=width_cjk)
    rend.missing_report()
    return rend, img


def _cjk_span_check(rows: list[str], cols: int, font_px: int,
                    want: float, width_cjk: int | None = None
                    ) -> tuple[float | None, str]:
    """渲染 rows 并量第 0 行行尾 '#' 的墨迹左沿；返回 (与应有位置的误差, 说明)。"""
    rend, img = _render_rows(rows, cols, font_px, width_cjk=width_cjk)
    grey = img.convert("L")
    m = _marker_ink(grey, rend, 0, 0)
    if m is None:
        return None, f"第 0 行没有墨迹 (rows={rows!r})"
    return m[0] - want, f"实测 x={m[0]}, 应有 x={want:.0f} (half={rend.half})"


def _marker_ink(grey: Image.Image, rend: TermRenderer, row: int,
                col: int) -> tuple[int, int] | None:
    """行尾 '#' 标记的墨迹区间。标记写在该行最后一列，其右全是背景，所以取
    本行最后一段墨迹即可 —— 不用猜窗口。"""
    top = rend.pad_y + row * rend.line_h
    runs = _ink_runs(grey, 0, rend.width, top, top + rend.line_h)
    return runs[-1] if runs else None


def _blank_out(text: str) -> str:
    """把载荷变成"同列宽的空白" —— 每个字符换成与它等列宽的空格。

    必须逐字符换、且用 display_cols 而不是"汉字数 × 2": 载荷里的 ASCII（数字、逗号、
    括号、WSTG 编号）也要留出同样多的空格，否则下行总列数比上行少一截，行尾 '#' 自然
    对不上（第一版就是只补了汉字那部分，实测每条载荷都差十几到几十像素）。
    """
    return "".join(" " * char_cols(ch) for ch in text)


def _cjk_pool(limit: int = 30) -> str:
    """从**真实采集输出**里抽一批互不相同的汉字，专供对齐验证当样本用。

    刻意不硬编码字表: 样本必须来自这次真跑出来的文本，验证才算验证了这批素材。
    """
    seen: list[str] = []
    for p in sorted(CAPTURE.glob("*.txt")):
        for ch in p.read_text(encoding="utf-8", errors="ignore"):
            if char_cols(ch) == 2 and ch not in seen:
                seen.append(ch)
                if len(seen) >= limit:
                    return "".join(seen)
    return "".join(seen)


def _render_rows(rows: list[str], cols: int, font_px: int,
                 width_cjk: int | None = None) -> tuple[TermRenderer, Image.Image]:
    """逐个渲染给定的行；`width_cjk` 用来造"汉字按 1 列排版"的已知错误渲染。"""
    rend = TermRenderer(cols, len(rows), font_px=font_px, title="")
    img = Image.new("RGB", (rend.width, rend.height), BG)
    for r, line in enumerate(rows):
        rend.text_line(img, rend.pad_y + r * rend.line_h, colorize(line),
                       _cjk_cols=width_cjk)
    rend.missing_report()
    return rend, img


def _cjk_span_check(rows: list[str], cols: int, font_px: int,
                    want: float, width_cjk: int | None = None
                    ) -> tuple[float | None, str]:
    """渲染 rows 并量第 0 行行尾 '#' 的墨迹左沿；返回 (与应有位置的误差, 说明)。"""
    rend, img = _render_rows(rows, cols, font_px, width_cjk=width_cjk)
    grey = img.convert("L")
    m = _marker_ink(grey, rend, 0, 0)
    if m is None:
        return None, f"第 0 行没有墨迹 (rows={rows!r})"
    return m[0] - want, f"实测 x={m[0]}, 应有 x={want:.0f} (half={rend.half})"


def alignment_check(verbose: bool = True) -> None:
    """把「中英混排对齐」做成**可测量、且已知会失败**的断言。

    判据 A（汉字串的累积步进）:

        `#` + 连续汉字串 + `#` —— 两个 '#' 的墨迹左沿之差，必须等于
        「汉字个数 × 2 × 半角格宽」。样本汉字从真实采集输出里抽（不硬编码字表）。
        汉字若被当成半角排、或回退字体字号没按比例放大，这个距离会缩水一半。

    判据 B（汉字串 vs 等列空格串，行尾锚点 + 逐格对照）:

        上行 = `#` + 中英混排载荷 + `#`
        下行 = `#` + **等列数的空格** + `#`

        两行的行尾 '#' 必须落在同一个像素列上（墨迹左沿误差 <= 1px）；再逐字符比对
        载荷里每个可见字符的墨迹，都必须落进下行同列处的墨迹窗口。这是"每个汉字正好
        吃掉两格"的最强表述 —— 逐字符钉死列宽，而不是只看行尾。

    反例自检 —— 把同一个渲染器改按「汉字 1 列」排版（本任务要防的那个 bug 本身），
        A 和 B 都必须报错；检不出就说明判据是空的（永远通过的断言没有价值）。
    """
    problems: list[str] = []
    # 画布必须装得下最长那行: 贴图一旦越界会被 PIL 静默裁掉，判据就会把"根本没画
    # 出来"的锚点当成巨大漂移 —— 第一版就是这么误报 800 多像素的。
    cols, font_px = 108, 24

    # ---- 判据 A: 汉字串累积步进 ---------------------------------------- #
    # 取真实字表里**首尾两个不同**的字来量行内间距，而不是量"整串宽度":
    # 汉字墨迹在字面里几乎顶满两格，串起来常常相邻相连成一段墨迹，取"最右一段"会
    # 量到相邻字上去（实测 96 字那次就是这么漂了整整一格）。中间用空格隔开，两端
    # 各自独立成段，量出来才是干净的步进。
    pool = _cjk_pool()
    if len(pool) < 8:
        problems.append(f"汉字样本不足: 只抽到 {len(pool)} 个（真实输出里应有大量汉字）")
    head, tail = pool[0], pool[-1]
    gap = 12  # 两个样点之间的列距（列）
    line_a = "#" + head + " " * gap + tail + "#"
    want_a = (2 + gap) * 0  # 占位, 下面用真实 half 重算
    rend_a, img_a = _render_rows([line_a], cols, font_px)
    want_a = (2 + gap) * rend_a.half
    grey_a = img_a.convert("L")
    runs_a = _ink_runs(grey_a, 0, rend_a.width, rend_a.pad_y,
                       rend_a.pad_y + rend_a.line_h)
    a_err = None
    if len(runs_a) < 3:
        problems.append(f"判据 A 样点缺失: 只量到 {len(runs_a)} 段墨迹（应有 '#'、"
                        f"{head!r}、{tail!r}、'#' 至少 4 段）")
    else:
        x_head, x_tail = runs_a[1][0], runs_a[2][0]
        a_err = (x_tail - x_head) - want_a
        if abs(a_err) > 1.5:
            problems.append(
                f"判据 A 汉字累积步进错 {a_err:+.1f}px: {head + ' ' * gap + tail!r} "
                f"里 {head!r} 与 {tail!r} 相隔 {2 + gap} 列, 墨迹左沿应相距 "
                f"{want_a:.0f}px, 实测 {x_tail - x_head}px (半角格 {rend_a.half}px)")

    # ---- 判据 B: 汉字串 vs 等列空格串 ----------------------------------- #
    payloads = [
        "链完整, 2 条记录",
        "写入保护生效: 拒绝向已损坏的账本追加新记录",
        "检测结论: 10 条 (可直接确认 8 / 需人工复核 2)",
        "CORS-WILDCARD-CREDS  (WSTG-CONF-12, 置信度=high)",
    ]
    b_err = 0
    checked = 0
    for payload in payloads:
        n_cjk = sum(char_cols(c) // 2 for c in payload)
        top_line = "#" + payload + "#"
        bot_line = "#" + _blank_out(payload) + "#"
        rend, img = _render_rows([top_line, bot_line], cols, font_px)
        grey = img.convert("L")
        mt = _marker_ink(grey, rend, 0, 0)
        mb = _marker_ink(grey, rend, 1, 0)
        if mt is None or mb is None:
            problems.append(f"判据 B 行尾锚点缺失: {payload!r} -> {mt} {mb}")
            continue
        d = mt[0] - mb[0]
        b_err = max(b_err, abs(d))
        if abs(d) > 1:
            problems.append(
                f"判据 B 行尾错位 {d:+d}px: {payload!r}（{n_cjk} 个汉字）行尾 '#' 落在"
                f" x={mt[0]}, 等列数空格版落在 x={mb[0]}")
        for row_ink, other in ((mt, mb), (mb, mt)):
            if abs(row_ink[1] - other[1]) > 1:
                problems.append(
                    f"判据 B 行尾墨迹宽度不一致: {payload!r} 的 '#' 是 {row_ink}, "
                    f"另一行是 {other}")
                break

    # ---- 反例自检: 判据必须能抓住"汉字按 1 列排版" ---------------------- #
    rend_bad, img_bad = _render_rows([line_a], cols, font_px, width_cjk=1)
    gb = img_bad.convert("L")
    runs_bad = _ink_runs(gb, 0, rend_bad.width, rend_bad.pad_y,
                         rend_bad.pad_y + rend_bad.line_h)
    teeth_a = 0
    if len(runs_bad) >= 3:
        err_bad = (runs_bad[2][0] - runs_bad[1][0]) - want_a
        if abs(err_bad) > 1.5:
            teeth_a = 1
    teeth_b = 0
    for payload in payloads[:3]:
        n_cjk = sum(char_cols(c) // 2 for c in payload)
        rend_bad, img_bad = _render_rows(["#" + payload + "#",
                                          "#" + _blank_out(payload) + "#"],
                                         cols, font_px, width_cjk=1)
        gb = img_bad.convert("L")
        mt = _marker_ink(gb, rend_bad, 0, 0)
        mb = _marker_ink(gb, rend_bad, 1, 0)
        if mt is not None and mb is not None and abs(mt[0] - mb[0]) > 1:
            teeth_b += 1
    if teeth_a == 0:
        problems.append("对齐判据失效: 「汉字按 1 列排版」时判据 A 检不出累积步进错")
    if teeth_b == 0:
        problems.append("对齐判据失效: 「汉字按 1 列排版」时判据 B 检不出行尾错位")

    if verbose:
        print("列对齐像素级验证（汉字累积步进 + 行尾锚点 + 反例自检）")
        print("\u2500" * 74)
        if problems:
            for p in problems:
                print("  [FAIL] " + p)
        else:
            print(f"  [PASS] 判据 A 汉字步进: 真实字表 {len(pool)} 字里取 {head!r} 与 "
                  f"{tail!r} 相隔 {2 + gap} 列, 墨迹相距 {x_tail - x_head}px vs 应有 "
                  f"{want_a:.0f}px, 误差 {a_err:+.1f}px")
            print(f"  [PASS] 判据 B 行尾锚点: {len(payloads)} 条中英混排载荷, 行尾 '#' "
                  f"与等列空格版逐像素重合（最大偏差 {b_err}px）")
            print(f"  [PASS] 反例自检: 同一批文本改按「汉字 1 格」排版, 判据 A 报错 "
                  f"{teeth_a}/1, 判据 B 报错 {teeth_b}/3（判据确实有牙齿）")
            print(f"         汉字步进 = {rend_a.stack.cell_cjk:.1f}px vs "
                  f"2 x {rend_a.half:.1f}px = {2 * rend_a.half:.1f}px; "
                  f"字号 主 {rend_a.font_px}px / CJK {rend_a.stack.fallback_px}px")
        print("\u2500" * 74)
    if problems:
        raise SystemExit("列对齐验证未通过:\n" + "\n".join(problems))


# --------------------------------------------------------------------------- #
# 采集: 真跑每一条命令
# --------------------------------------------------------------------------- #

PY = sys.executable
OUT_OF_SCOPE = "http://10.99.99.99/"          # 越界目标: 不在授权网段内
DEMO_ACTOR = "demo-operator"                  # 演示账本固定用这个 actor, 不写本机主机名


def _run(argv: list[str]) -> tuple[int, str, str]:
    # 本项目是 src/ 布局且未安装: 必须把 src/ 塞进 PYTHONPATH, 否则
    # `python -m ptpipeline` 只会得到 "No module named ptpipeline"（0 行输出）。
    # cwd 固定在仓库根: argv 用相对路径 -> 输出里也就不会有作者的绝对路径。
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1",
               PYTHONPATH=str(SRC), PTP_ACTOR=DEMO_ACTOR)
    p = subprocess.run(argv, cwd=str(REPO), capture_output=True, env=env)
    # 子进程在 Windows 上的 stdout 是 \r\n。这里先归一到 \n, 否则落盘时 write_text
    # 会把其中的 \n 再翻译一次, 得到 \r\r\n —— 采集文件在编辑器/GitHub 上看起来
    # 每个真实行后面都多一个空行。
    return (p.returncode,
            _lf(p.stdout.decode("utf-8", "replace")),
            _lf(p.stderr.decode("utf-8", "replace")))


def _lf(text: str) -> str:
    """把 CRLF / 孤立 CR 统一成 LF。"""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _display_argv(argv: list[str]) -> list[str]:
    """把 argv 里的解释器绝对路径换回 'python'。

    清单是要跟着仓库一起公开的, 解释器的绝对路径(= 本机用户名 + 目录结构)不能入库;
    实际用哪个解释器跑由 `python_version` 记录, 足以复现。
    """
    return ["python" if a == PY else a for a in argv]


def _record(manifest: dict, label: str, argv: list[str]) -> int:
    code, out, err = _run(argv)
    (CAPTURE / f"{label}.txt").write_text(out, encoding="utf-8", newline="\n")
    manifest["commands"].append({
        "label": label, "argv": _display_argv(argv), "exit": code,
        "stdout_b64": base64.b64encode(out.encode("utf-8")).decode("ascii"),
        "stderr_b64": base64.b64encode(err.encode("utf-8")).decode("ascii"),
    })
    print(f"    [capture] {label:20s} exit={code}  {len(out.splitlines()):3d} 行")
    return code


def capture_all() -> dict:
    """依次真跑演示命令，把 stdout 原样落盘，并记录 argv/exit code。"""
    CAPTURE.mkdir(parents=True, exist_ok=True)
    ledger = CAPTURE / "demo-ledger.jsonl"
    findings = CAPTURE / "demo-findings.json"
    for stale in (ledger, findings):
        if stale.exists():
            stale.unlink()

    # 全部用相对仓库根的路径: _run() 以仓库根为 cwd, 于是 CLI 回显的也是相对路径,
    # 图里不会出现作者机器上的绝对路径 (见模块 docstring 第 4 条)。
    ledger_rel = ledger.relative_to(REPO).as_posix()
    findings_rel = findings.relative_to(REPO).as_posix()
    manifest_rel = "scope/manifest.example.yaml"

    manifest: dict = {
        "cwd": "仓库根 (下列 argv 一律相对该目录执行)",
        "python": "python",
        "python_version": platform.python_version(),
        "actor": DEMO_ACTOR,
        "note": ("解释器只记作 python, 绝对路径与本机主机名不入库; "
                 "版本见 python_version, actor 由 PTP_ACTOR 固定"),
        "commands": [],
    }
    for label, argv in (
        ("doctor", [PY, "-m", "ptpipeline", "doctor", "--manifest", manifest_rel]),
        ("scope-deny", [PY, "-m", "ptpipeline", "scope",
                        "--manifest", manifest_rel,
                        "--target", "https://www.baidu.com/"]),
        ("scope-allow", [PY, "-m", "ptpipeline", "scope",
                         "--manifest", manifest_rel,
                         "--target", "http://127.0.0.1:8080/"]),
        ("probe", [PY, "-m", "ptpipeline", "probe", "http://127.0.0.1:8080/",
                   "--manifest", manifest_rel,
                   "--ledger", ledger_rel, "--out", findings_rel]),
        ("audit-ok", [PY, "-m", "ptpipeline", "audit",
                      "--ledger", ledger_rel, "--show"]),
    ):
        _record(manifest, label, argv)

    # --- 合成篡改: 把第 3 行的 target 换成越界 IP ---------------------------
    lines = ledger.read_text(encoding="utf-8").splitlines()
    target_line = 3
    rec = json.loads(lines[target_line - 1])
    original = rec.get("target")
    rec["target"] = OUT_OF_SCOPE
    lines[target_line - 1] = json.dumps(rec, ensure_ascii=False, sort_keys=True)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
    manifest["tamper"] = {
        "ledger": ledger_rel, "line": target_line, "field": "target",
        "original_target": original, "new_target": OUT_OF_SCOPE,
        "note": "演示用合成篡改: 改的是 docs/_capture/ 下的演示副本, 不是真实数据",
    }
    print(f"    [tamper]   第 {target_line} 行 target: {original} -> {OUT_OF_SCOPE}")

    for label, argv in (
        ("audit-tampered", [PY, "-m", "ptpipeline", "audit", "--ledger", ledger_rel]),
        ("audit-tampered-show", [PY, "-m", "ptpipeline", "audit",
                                 "--ledger", ledger_rel, "--show"]),
        ("verify", [PY, "scripts/verify_pipeline.py"]),
        ("audit-real-ledger", [PY, "-m", "ptpipeline", "audit",
                               "--ledger", "evidence/audit-ledger.jsonl", "--show"]),
    ):
        _record(manifest, label, argv)

    MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                        encoding="utf-8", newline="\n")
    return manifest


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #

def main() -> int:
    ap = argparse.ArgumentParser(
        description="把 ptpipeline 的真实 CLI 输出渲染成展示图与演示 GIF")
    ap.add_argument("--verify-fonts", action="store_true", help="只校验字体与列宽不变量")
    ap.add_argument("--render-only", action="store_true", help="用已有 _capture/ 重新渲染")
    ap.add_argument("--no-gif", action="store_true", help="跳过 GIF")
    args = ap.parse_args()

    if args.verify_fonts:
        assert_font_invariants()
        alignment_check()
        return 0

    if not args.render_only:
        print("① 采集真实 CLI 输出")
        capture_all()
    elif not MANIFEST.exists():
        raise SystemExit("没有 _capture/_manifest.json，先跑一次完整流程")

    print("② 校验字体与列宽不变量")
    assert_font_invariants()
    alignment_check()

    print("③ 渲染场景图")
    made: list[Path] = []
    hero = render_hero(capture_text("scope-deny"),
                       "python -m ptpipeline scope --target https://www.baidu.com/",
                       DOCS)
    made.append(hero)
    print(f"    {hero.name:28s} {hero.stat().st_size / 1024:7.0f} KB")
    for key, label, title, caption in SCENES:
        p = render_scene(key, capture_text(label), title, caption, DOCS)
        made.append(p)
        print(f"    {p.name:28s} {p.stat().st_size / 1024:7.0f} KB")

    if not args.no_gif:
        print("④ 生成演示 GIF")
        made.append(build_gif(DOCS))

    print("⑤ 复验产物能被 Pillow 正常打开")
    total = 0
    for p in made:
        with Image.open(p) as im:
            im.load()
            n = getattr(im, "n_frames", 1)
            size_kb = p.stat().st_size / 1024
            print(f"    [PASS] {p.name:28s} {im.format:5s} {im.width}×{im.height} "
                  f"{n} 帧  {size_kb:7.0f} KB")
            assert im.width >= 600 and im.height >= 200, p
            assert size_kb > 1, p
            total += p.stat().st_size
    print(f"  合计 {total / 1024:.0f} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
