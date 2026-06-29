"""工具目录 —— 注册所有 CLS 测试工具模块。

- L1 全自动（12 个）：每个都有专用 parser（独立 *_tool.py），执行 + 解析 findings
- L2/L3：ManualTool 占位（用 generic(cls=ManualTool, ...) 快速登记，不代跑）

加新工具：写一个 Tool 子类（最简只需 command_template + requires + parse），
import 进来 append 到 ALL_TOOLS。纯人工/硬件步骤用 generic(cls=ManualTool, ...)。
"""
from __future__ import annotations

from typing import List

from .base import ManualTool, Tool
from .binwalk_tool import BinwalkTool
from .commix_tool import CommixTool
from .dirsearch_tool import DirsearchTool
from .feroxbuster_tool import FeroxbusterTool
from .firmwalker_tool import FirmwalkerTool
from .hydra_tool import HydraTool
from .netdiscover_tool import NetdiscoverTool
from .nmap_tool import NmapTool
from .routersploit_tool import RoutersploitTool
from .sqlmap_tool import SqlmapTool
from .testssl_tool import TestsslTool
from .xsser_tool import XsserTool


def generic(cls=Tool, **attrs) -> Tool:
    """快速造一个工具实例：generic(id="dirsearch", test="CP-1", ...)。"""
    tool = cls()
    for key, value in attrs.items():
        setattr(tool, key, value)
    return tool


ALL_TOOLS: List[Tool] = [
    # ---- L1 全自动（均带专用 parser）----
    NmapTool(),
    NetdiscoverTool(),
    RoutersploitTool(),
    HydraTool(),
    BinwalkTool(),
    FirmwalkerTool(),
    TestsslTool(),
    DirsearchTool(),
    FeroxbusterTool(),
    SqlmapTool(),
    CommixTool(),
    XsserTool(),

    # ---- L2 半自动（需人工抓包/上传产物）----
    generic(
        cls=ManualTool, id="tshark", test="CO-2/4/5/6", category="CO", level="L2",
        binary="tshark", description="人工抓包后用 tshark 解析 pcap（需先采集 capture.pcap）",
    ),
    generic(
        cls=ManualTool, id="mobsf", test="MA-2/3/4/5", category="MA", level="L2",
        description="MobSF 静态分析 APK（需起 MobSF server / REST API）",
    ),
    generic(
        cls=ManualTool, id="burpsuite", test="CP-5", category="CP", level="L2",
        description="Burp 抓改包验证会话劫持（人工代理流程 + 截图）",
    ),
    generic(
        cls=ManualTool, id="apk-extractor", test="MA-3/4/5", category="MA", level="L2",
        description="从 Android 实机导出 APK，再交给 MobSF",
    ),

    # ---- L3 人工/硬件（只列 checklist，不代跑）----
    generic(
        cls=ManualTool, id="firefox-manual", test="AU/CP/CO", category="AU", level="L3",
        description="Firefox 手动验证（默认密码、锁定策略、强密码策略等）",
    ),
    generic(
        cls=ManualTool, id="ghidra", test="FWU-5", category="FWU", level="L3",
        description="Ghidra/Binary Ninja 逆向固件更新逻辑（加密/签名验证）",
    ),
    generic(
        cls=ManualTool, id="airgeddon", test="AWR-1", category="AWR", level="L3",
        description="WPS PIN 暴力破解（需 Alfa AWUS036NH 监控网卡）",
    ),
    generic(
        cls=ManualTool, id="uart", test="AWR-5", category="HW", level="L3",
        description="UART/Attify Badge 硬件调试口检查（boot log / shell 暴露）",
    ),
]


def by_id(tool_id: str) -> Tool | None:
    for tool in ALL_TOOLS:
        if tool.id == tool_id:
            return tool
    return None


def select(ids: List[str]) -> tuple[List[Tool], List[str]]:
    """按给定顺序取工具；返回 (找到的工具, 未知 id 列表)。"""
    found, unknown = [], []
    for tool_id in ids:
        tool = by_id(tool_id)
        (found if tool else unknown).append(tool if tool else tool_id)
    return found, unknown
