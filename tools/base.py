"""Tool base classes for the CLS toolkit.

Each test tool = one Tool subclass. Shared interface:
  - command_template / build_command : inject DUT info into the command
  - run                              : execute + capture output + save evidence
  - parse                            : raw output -> structured findings
                                       (no parsing by default; subclasses override)
"""
from __future__ import annotations

import shlex
import shutil
import subprocess
from pathlib import Path
from typing import List

LEVELS = {
    "L1": "fully automated",
    "L2": "semi-auto (needs evidence)",
    "L3": "manual/hardware",
}


class _SafeDict(dict):
    """For str.format_map: render a missing placeholder as "" instead of raising."""

    def __missing__(self, key):  # noqa: D401
        return ""


class Tool:
    id: str = ""                    # unique id, e.g. "nmap"
    test: str = ""                  # CLS test code, e.g. "PS-1"
    category: str = ""              # PS / FW / CO / CP / MA / AU / AWR / HW
    level: str = "L1"               # L1 auto / L2 semi-auto / L3 manual
    binary: str = ""                # required binary (PATH check); empty = no check
    description: str = ""
    requires: List[str] = []        # required DUT fields; skip run if missing
    command_template: str = ""      # placeholders {field} + {evidence}
    timeout: int = 600              # seconds
    auto: bool = True               # False = manual/hardware, not run for the user

    # ---- capability check ----
    def available(self) -> bool:
        if not self.binary:
            return True
        return shutil.which(self.binary) is not None

    def missing_fields(self, dut: dict) -> List[str]:
        return [f for f in self.requires if not str(dut.get(f, "")).strip()]

    # ---- command building ----
    def build_command(self, dut: dict, evidence: Path) -> List[str]:
        ctx = _SafeDict(dut)
        ctx["evidence"] = str(evidence)
        rendered = self.command_template.format_map(ctx)
        return shlex.split(rendered)

    # ---- execution ----
    def run(self, dut: dict, evidence_dir: Path) -> dict:
        safe = f"{self.id}_{self.test}".replace("/", "-")
        evidence = evidence_dir / safe
        argv = self.build_command(dut, evidence)
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=self.timeout
            )
            raw = proc.stdout
            if proc.stderr:
                raw += "\n[stderr]\n" + proc.stderr
            exit_code = proc.returncode
            status = "done" if exit_code == 0 else "error"
        except subprocess.TimeoutExpired:
            raw, exit_code, status = f"[timeout {self.timeout}s]", -1, "timeout"
        except FileNotFoundError:
            raw, exit_code, status = f"[binary not found: {self.binary}]", -2, "missing-binary"

        log_path = evidence_dir / f"{safe}.log"
        log_path.write_text(raw, encoding="utf-8", errors="replace")

        findings = []
        if status == "done":
            try:
                findings = self.parse(raw, evidence)
            except Exception as exc:  # noqa: BLE001  a parse error must not break the pipeline
                findings = [{"severity": "info", "title": "parse failed", "detail": str(exc)}]

        return {
            "tool": self.id,
            "test": self.test,
            "category": self.category,
            "level": self.level,
            "command": " ".join(argv),
            "exit_code": exit_code,
            "status": status,
            "evidence_log": str(log_path),
            "findings": findings,
        }

    def parse(self, raw: str, evidence: Path) -> List[dict]:
        """No structured parsing by default (raw output is already saved to .log).
        Subclasses override this to extract findings."""
        return []


class ManualTool(Tool):
    """L2/L3: manual or hardware steps; the platform only records a placeholder."""

    auto = False

    def run(self, dut: dict, evidence_dir: Path) -> dict:
        return {
            "tool": self.id,
            "test": self.test,
            "category": self.category,
            "level": self.level,
            "command": self.command_template or "(manual step)",
            "exit_code": None,
            "status": "manual",
            "evidence_log": None,
            "findings": [],
            "note": self.description or "Manual/hardware step; the assessor must run it and upload evidence.",
        }
