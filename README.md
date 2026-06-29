# CLS Toolkit

A command-line tool that runs on **Kali Linux** to help a colleague complete CLS
(Cybersecurity Labelling Scheme) testing more easily:

1. Fill the DUT pre-flight info **once** in `dut.yaml` (model, IP, config portal,
   firmware package, APK, ...)
2. Pick the tools to run and order them (`plan.yaml` or `--tools`)
3. **Run them together** -> tools run in order, output is captured, evidence is
   saved, and results are parsed into structured findings
4. Results land in `results/`, raw evidence in `evidence/`, ready for manual review
   + AI report writing

> Design principle: the offensive tools (nmap / sqlmap / hydra / MobSF ...) must run
> on the tester's Kali machine -- it sits on the same isolated lab segment as the DUT.
> So this tool **runs locally on Kali**, not as a website backend.

## Install (on Kali)

```bash
git clone https://github.com/Monika-12138/cls-toolkit.git
cd cls-toolkit
```

The only Python dependency is PyYAML. On modern Kali, install it with apt (do NOT
use `pip` -- it is blocked by PEP 668 and may not even be present):

```bash
sudo apt install -y python3-yaml
```

Most test tools (nmap, testssl.sh, dirsearch, sqlmap, ...) ship with Kali or install
via `apt`. See `KALI_RUNBOOK.md` for the full one-shot install line.

## Usage

```bash
# 1. List the tool modules
python3 cls.py list

# 2. Check which tool binaries are installed
python3 cls.py check

# 3. Copy the DUT template and fill it in
cp dut.example.yaml dut.yaml
$EDITOR dut.yaml

# 4. Run specific tools (in the given order)
python3 cls.py run --dut dut.yaml --tools nmap,testssl,dirsearch

# or use a plan file to define the pipeline
cp plan.example.yaml plan.yaml
python3 cls.py run --dut dut.yaml --plan plan.yaml

# 5. Summarize the latest run (by CLS category + severity), export Markdown
python3 cls.py report
```

After running:

- `evidence/` -- each tool's raw output (nmap XML, testssl JSON, per-tool .log)
- `results/` -- a `results_<timestamp>.json` with each tool's command, exit code,
  and structured findings
- `report` then produces `results/summary_<timestamp>.md`: grouped by category
  (PS/FW/CO/CP/...), a severity tally, and a "manual follow-up" checklist -- this
  Markdown is the input for AI report writing (Part 2)

## Automation tiers

| Tier | Meaning | What this tool does |
|------|---------|---------------------|
| **L1** fully automated | CLI + structured output | run + parse findings |
| **L2** semi-auto | needs manual capture / uploaded artifact | placeholder, prompts for the evidence file |
| **L3** manual/hardware | reverse-engineering, Wi-Fi NIC, UART | checklist only, not run for you |

## Adding a new tool

Add a `Tool` subclass under `tools/` (minimally `command_template` + required
fields), then register it in `tools/catalog.py`. For structured parsing (like
nmap/testssl) override `parse()`.

```python
class DirsearchTool(Tool):
    id = "dirsearch"; test = "CP-1"; category = "CP"; level = "L1"
    binary = "dirsearch"; requires = ["portal_url"]
    command_template = "dirsearch -u {portal_url} --format json -o {evidence}.json"
```

## Tests

Zero-dependency smoke tests (runnable on a machine without the real binaries, e.g.
Windows) -- feed each parser a sample of tool output and assert the findings:

```bash
python3 tests/test_parsers.py     # 12 parsers + report aggregation
```

## Roadmap

- [x] Part 1: tool collection + real execution + structured results
- [x] All 12 L1 tools have dedicated parsers (nmap / netdiscover / routersploit /
      hydra / binwalk / firmwalker / testssl / dirsearch / feroxbuster / sqlmap /
      commix / xsser)
- [x] `cls.py report`: aggregate by CLS category + severity, export Markdown
- [ ] **End-to-end test on Kali** (real binaries, validate each parser)
- [ ] L2 evidence parsing (tshark reads pcap, MobSF REST API)
- [ ] Part 2: AI reads `summary_*.md` + CLS template -> draft report -> export .docx
