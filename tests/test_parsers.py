#!/usr/bin/env python3
"""Parser 冒烟测试 —— 在没有真实二进制的机器（如 Windows）也能跑。

给每个 parser 喂一段真实形态的样例输出，断言解析出的 findings 数量 / 严重度符合预期。
直接 `python tests/test_parsers.py` 运行（零依赖，不需要 pytest）；
也兼容 pytest（函数名 test_*）。
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import report as report_mod  # noqa: E402
from tools.binwalk_tool import BinwalkTool  # noqa: E402
from tools.commix_tool import CommixTool  # noqa: E402
from tools.dirsearch_tool import DirsearchTool  # noqa: E402
from tools.feroxbuster_tool import FeroxbusterTool  # noqa: E402
from tools.firmwalker_tool import FirmwalkerTool  # noqa: E402
from tools.hydra_tool import HydraTool  # noqa: E402
from tools.netdiscover_tool import NetdiscoverTool  # noqa: E402
from tools.nmap_tool import NmapTool  # noqa: E402
from tools.routersploit_tool import RoutersploitTool  # noqa: E402
from tools.sqlmap_tool import SqlmapTool  # noqa: E402
from tools.testssl_tool import TestsslTool  # noqa: E402
from tools.xsser_tool import XsserTool  # noqa: E402


def _evidence(name: str) -> Path:
    d = Path(tempfile.mkdtemp(prefix="cls_test_"))
    return d / name


def _sev_counts(findings):
    out: dict[str, int] = {}
    for f in findings:
        out[f["severity"]] = out.get(f["severity"], 0) + 1
    return out


# ---------- 文件型 parser（companion 文件） ----------

def test_nmap():
    ev = _evidence("nmap_PS-1")
    Path(f"{ev}.xml").write_text(
        '<?xml version="1.0"?><nmaprun><host><ports>'
        '<port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http" product="nginx" version="1.18.0"/></port>'
        '<port protocol="tcp" portid="22"><state state="closed"/>'
        '<service name="ssh"/></port>'
        "</ports></host></nmaprun>",
        encoding="utf-8",
    )
    f = NmapTool().parse("", ev)
    assert len(f) == 1, f
    assert "80/tcp" in f[0]["title"]
    assert "nginx" in f[0]["detail"]


def test_testssl():
    ev = _evidence("testssl_CO-3")
    Path(f"{ev}.json").write_text(
        '[{"id":"BREACH","severity":"HIGH","finding":"vulnerable to BREACH"},'
        '{"id":"cipherlist","severity":"OK","finding":"fine"}]',
        encoding="utf-8",
    )
    f = TestsslTool().parse("", ev)
    assert len(f) == 1 and f[0]["severity"] == "high", f


def test_dirsearch():
    ev = _evidence("dirsearch_CP-1")
    Path(f"{ev}.json").write_text(
        '{"results":[{"url":"http://x/admin","status":200,"content-length":1024},'
        '{"url":"http://x/index.html","status":200,"content-length":500}]}',
        encoding="utf-8",
    )
    f = DirsearchTool().parse("", ev)
    c = _sev_counts(f)
    assert c.get("low") == 1 and c.get("info") == 1, f


def test_feroxbuster():
    ev = _evidence("feroxbuster_CP-1")
    Path(f"{ev}.json").write_text(
        '{"type":"response","url":"http://x/admin","status":200,"content_length":1024}\n'
        '{"type":"response","url":"http://x/images","status":301,"content_length":0}\n'
        '{"type":"statistics","requests":100}\n',
        encoding="utf-8",
    )
    f = FeroxbusterTool().parse("", ev)
    c = _sev_counts(f)
    assert c.get("low") == 1 and c.get("info") == 1, f  # statistics 行被忽略


def test_firmwalker():
    ev = _evidence("firmwalker_FW-2")
    Path(f"{ev}.txt").write_text(
        "***Search for password files***\n"
        "#####################################passwd\n"
        "/etc/passwd\n"
        "#####################################shadow\n"
        "/etc/shadow\n"
        "***Search for SSL related files***\n"
        "#####################################private\n"
        "/etc/ssl/private/server.key\n",
        encoding="utf-8",
    )
    f = FirmwalkerTool().parse("", ev)
    assert len(f) == 3 and all(x["severity"] == "high" for x in f), f


# ---------- stdout 型 parser（解析 raw） ----------

def test_sqlmap():
    raw = (
        "Parameter: id (GET)\n"
        "    Type: boolean-based blind\n"
        "    Type: time-based blind\n"
        "back-end DBMS: MySQL\n"
    )
    f = SqlmapTool().parse(raw, _evidence("sqlmap_CP-3"))
    c = _sev_counts(f)
    assert c.get("high") == 1 and c.get("info") == 1, f


def test_commix():
    raw = (
        "the (GET) 'id' parameter is vulnerable to results-based command injection\n"
        "the back-end operating system is Linux\n"
    )
    f = CommixTool().parse(raw, _evidence("commix_CP-4"))
    c = _sev_counts(f)
    assert c.get("high") == 1 and c.get("info") == 1, f


def test_netdiscover():
    raw = (
        " Currently scanning: Finished!   |   Screen View: Unique Hosts\n"
        " _____________________________________________________________\n"
        "   IP            At MAC Address     Count     Len  MAC Vendor\n"
        " -------------------------------------------------------------\n"
        " 192.168.1.1     aa:bb:cc:dd:ee:ff      2     120  Realtek Semiconductor\n"
        " 192.168.1.5     11:22:33:44:55:66      1      60  Unknown vendor\n"
    )
    f = NetdiscoverTool().parse(raw, _evidence("netdiscover_PS-1"))
    assert len(f) == 2, f
    assert all(x["severity"] == "info" for x in f)


def test_hydra():
    raw = (
        "[DATA] attacking http-get://192.168.1.1:80/\n"
        "[80][http-get] host: 192.168.1.1   login: admin   password: admin\n"
    )
    f = HydraTool().parse(raw, _evidence("hydra_AU-1"))
    assert len(f) == 1 and f[0]["severity"] == "high", f
    assert "admin" in f[0]["title"]


def test_xsser():
    raw = (
        "[*] Final Results:\n"
        "- Injections: 5\n"
        "- Failed: 4\n"
        "- Successful: 1\n"
        "- Accuracy: 20 %\n"
    )
    f = XsserTool().parse(raw, _evidence("xsser_CP-6"))
    assert len(f) == 1 and f[0]["severity"] == "high", f


def test_xsser_clean():
    raw = "- Successful: 0\n"
    f = XsserTool().parse(raw, _evidence("xsser_CP-6"))
    assert f == [], f


def test_binwalk():
    raw = (
        "DECIMAL       HEXADECIMAL     DESCRIPTION\n"
        "----------------------------------------------------\n"
        "0             0x0             uImage header, header size: 64 bytes\n"
        "112           0x70            LZMA compressed data\n"
        "1769472       0x1B0000        Squashfs filesystem, little endian\n"
    )
    f = BinwalkTool().parse(raw, _evidence("binwalk_FW-1"))
    c = _sev_counts(f)
    assert len(f) == 3, f
    assert c.get("low") == 2 and c.get("info") == 1, f  # uImage+Squashfs=low, LZMA=info


def test_routersploit():
    raw = (
        "[+] 192.168.1.1:80 http exploits/routers/test/rce is vulnerable\n"
        "[-] 192.168.1.1:80 http exploits/routers/other/x is not vulnerable\n"
    )
    f = RoutersploitTool().parse(raw, _evidence("routersploit_PS-2"))
    assert len(f) == 1 and f[0]["severity"] == "high", f


# ---------- report 聚合 ----------

def test_report_summary():
    report = {
        "generated_at": "2026-06-29T12:00:00",
        "dut": {"toe_name": "TestDUT", "model": "X1", "ip": "192.168.1.1"},
        "results": [
            {"tool": "nmap", "test": "PS-1", "category": "PS", "status": "done",
             "findings": [{"severity": "info", "title": "开放端口 80", "detail": "http"}]},
            {"tool": "hydra", "test": "AU-1", "category": "AU", "status": "done",
             "findings": [{"severity": "high", "title": "弱口令", "detail": "admin/admin"}]},
            {"tool": "mobsf", "test": "MA-2", "category": "MA", "status": "manual",
             "findings": [], "note": "需起 MobSF server"},
            {"tool": "testssl", "test": "CO-3", "category": "CO",
             "status": "skipped-no-binary", "findings": [], "note": "未装 testssl.sh"},
        ],
    }
    s = report_mod.build_summary(report)
    assert s["total_findings"] == 2, s
    assert s["sev_counts"]["high"] == 1 and s["sev_counts"]["info"] == 1, s
    assert s["status_counts"] == {"ran": 2, "skipped": 1, "manual": 1, "failed": 0}, s
    assert len(s["follow_up"]) == 2, s
    md = report_mod.render_markdown(report, s, "results/x.json")
    assert "# CLS 测试结果汇总" in md and "需人工跟进" in md
    assert "PS — Ports and Services" in md and "AU — Authentication" in md
    # category 缺失时从 test 前缀回退
    assert report_mod._category({"test": "CP-1"}) == "CP"


def _run_all() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL  {fn.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {fn.__name__}: {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
