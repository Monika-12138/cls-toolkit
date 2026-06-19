"""工具目录 —— 注册所有 CLS 测试工具模块。

- nmap / testssl：有专用 parser（独立文件）
- 其余 L1 工具：用 GenericTool（执行 + 存日志，findings 待后续加 parser）
- L2/L3：ManualTool 占位

加新工具：写一个 Tool 子类或 generic(...)，append 到 ALL_TOOLS。
"""
from __future__ import annotations

from typing import List

from .base import ManualTool, Tool
from .nmap_tool import NmapTool
from .testssl_tool import TestsslTool


def generic(cls=Tool, **attrs) -> Tool:
    """快速造一个工具实例：generic(id="dirsearch", test="CP-1", ...)。"""
    tool = cls()
    for key, value in attrs.items():
        setattr(tool, key, value)
    return tool


ALL_TOOLS: List[Tool] = [
    # ---- L1 全自动（有专用 parser）----
    NmapTool(),
    TestsslTool(),

    # ---- L1 全自动（通用执行，待加 parser）----
    generic(
        id="netdiscover", test="PS-1", category="PS", level="L1", binary="netdiscover",
        description="发现局域网内存活主机", requires=["lan_subnet"],
        command_template="netdiscover -P -r {lan_subnet}",
    ),
    generic(
        id="routersploit", test="PS-2", category="PS", level="L1", binary="routersploit",
        description="路由器/IoT 常见漏洞自动探测", requires=["ip"],
        command_template="routersploit --execute 'use scanners/autopwn; set target {ip}; run'",
    ),
    generic(
        id="hydra", test="AU-1", category="AU", level="L1", binary="hydra",
        description="登录接口抗暴力破解验证", requires=["ip", "users_file", "pass_file"],
        command_template="hydra -L {users_file} -P {pass_file} {ip} http-get /",
    ),
    generic(
        id="binwalk", test="FW-1", category="FW", level="L1", binary="binwalk",
        description="固件解包，提取文件系统", requires=["firmware_file"],
        command_template="binwalk -Me {firmware_file}",
    ),
    generic(
        id="firmwalker", test="FW-2", category="FW", level="L1", binary="firmwalker",
        description="扫描固件文件系统中的密钥/密码/隐藏账户", requires=["firmware_extract_dir"],
        command_template="firmwalker {firmware_extract_dir}",
    ),
    generic(
        id="dirsearch", test="CP-1", category="CP", level="L1", binary="dirsearch",
        description="配置门户隐藏路径/管理接口爆破", requires=["portal_url"],
        command_template="dirsearch -u {portal_url} --format plain -o {evidence}.txt",
    ),
    generic(
        id="feroxbuster", test="CP-1", category="CP", level="L1", binary="feroxbuster",
        description="高性能目录/文件枚举", requires=["portal_url"],
        command_template="feroxbuster -u {portal_url} -o {evidence}.txt",
    ),
    generic(
        id="sqlmap", test="CP-3", category="CP", level="L1", binary="sqlmap",
        description="配置门户参数 SQL 注入检测", requires=["portal_url"],
        command_template="sqlmap -u {portal_url} --batch --crawl=1 --risk=1 --level=2 --output-dir={evidence}",
    ),
    generic(
        id="commix", test="CP-4", category="CP", level="L1", binary="commix",
        description="命令注入检测", requires=["portal_url"],
        command_template="commix --url={portal_url} --batch",
    ),
    generic(
        id="xsser", test="CP-6", category="CP", level="L1", binary="xsser",
        description="跨站脚本 XSS 检测", requires=["portal_url"],
        command_template="xsser --url {portal_url}",
    ),

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
