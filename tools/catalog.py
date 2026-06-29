"""Tool catalog -- register every CLS test tool module.

- L1 fully automated (12): each has a dedicated parser (its own *_tool.py),
  execute + parse findings
- L2/L3: ManualTool placeholders (registered quickly via
  generic(cls=ManualTool, ...), not run for the user)

To add a tool: write a Tool subclass (minimally command_template + requires +
parse), import it and append to ALL_TOOLS. Pure manual/hardware steps use
generic(cls=ManualTool, ...).
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
    """Quickly build a tool instance: generic(id="dirsearch", test="CP-1", ...)."""
    tool = cls()
    for key, value in attrs.items():
        setattr(tool, key, value)
    return tool


ALL_TOOLS: List[Tool] = [
    # ---- L1 fully automated (all parser-backed) ----
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

    # ---- L2 semi-auto (needs manual capture / uploaded artifact) ----
    generic(
        cls=ManualTool, id="tshark", test="CO-2/4/5/6", category="CO", level="L2",
        binary="tshark", description="Parse pcap with tshark after manual capture (capture.pcap first)",
    ),
    generic(
        cls=ManualTool, id="mobsf", test="MA-2/3/4/5", category="MA", level="L2",
        description="MobSF static analysis of APK (needs MobSF server / REST API)",
    ),
    generic(
        cls=ManualTool, id="burpsuite", test="CP-5", category="CP", level="L2",
        description="Burp intercept/replay to verify session hijacking (manual proxy + screenshots)",
    ),
    generic(
        cls=ManualTool, id="apk-extractor", test="MA-3/4/5", category="MA", level="L2",
        description="Export APK from a physical Android device, then feed to MobSF",
    ),

    # ---- L3 manual/hardware (checklist only, not run for the user) ----
    generic(
        cls=ManualTool, id="firefox-manual", test="AU/CP/CO", category="AU", level="L3",
        description="Firefox manual checks (default password, lockout policy, strong-password policy, etc.)",
    ),
    generic(
        cls=ManualTool, id="ghidra", test="FWU-5", category="FWU", level="L3",
        description="Ghidra/Binary Ninja reverse-engineering of firmware update logic (encryption/signature)",
    ),
    generic(
        cls=ManualTool, id="airgeddon", test="AWR-1", category="AWR", level="L3",
        description="WPS PIN brute-force (needs Alfa AWUS036NH monitor-mode NIC)",
    ),
    generic(
        cls=ManualTool, id="uart", test="AWR-5", category="HW", level="L3",
        description="UART/Attify Badge hardware debug port check (boot log / shell exposure)",
    ),
]


def by_id(tool_id: str) -> Tool | None:
    for tool in ALL_TOOLS:
        if tool.id == tool_id:
            return tool
    return None


def select(ids: List[str]) -> tuple[List[Tool], List[str]]:
    """Pick tools in the given order; return (found tools, unknown ids)."""
    found, unknown = [], []
    for tool_id in ids:
        tool = by_id(tool_id)
        (found if tool else unknown).append(tool if tool else tool_id)
    return found, unknown
