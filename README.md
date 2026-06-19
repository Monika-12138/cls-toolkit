# CLS Toolkit

一个跑在 **Kali Linux** 上的命令行工具，帮同事更轻松地完成 CLS（Cybersecurity Labelling Scheme）测试：

1. 在 `dut.yaml` 里**填一次** DUT 前置信息（型号、IP、配置门户、固件包、APK……）
2. 选好要跑的工具、排好顺序（`plan.yaml` 或 `--tools`）
3. **统一执行** → 顺序跑工具、抓取输出、存证据、解析成结构化 findings
4. 结果落到 `results/`、原始证据落到 `evidence/`，供后续人工复核 + AI 写报告

> 设计原则：攻击性工具（nmap / sqlmap / hydra / MobSF…）必须跑在测试员的 Kali 机器上——它和 DUT 在同一隔离实验网段里。所以本工具**就在 Kali 本地执行**，不做网站后端。

## 安装（在 Kali 上）

```bash
git clone <your-repo-url> cls-toolkit
cd cls-toolkit
pip install -r requirements.txt
```

绝大多数测试工具（nmap、testssl.sh、dirsearch、sqlmap…）Kali 自带或 `apt install` 即可。

## 用法

```bash
# 1. 看有哪些工具模块
python3 cls.py list

# 2. 检查本机装了哪些工具二进制
python3 cls.py check

# 3. 复制 DUT 模板并填写
cp dut.example.yaml dut.yaml
$EDITOR dut.yaml

# 4. 跑指定工具（按给定顺序）
python3 cls.py run --dut dut.yaml --tools nmap,testssl,dirsearch

# 或用 plan 文件排流水线
cp plan.example.yaml plan.yaml
python3 cls.py run --dut dut.yaml --plan plan.yaml
```

执行后：

- `evidence/` — 每个工具的原始输出（nmap XML、testssl JSON、各工具 .log）
- `results/` — 一份 `results_<时间戳>.json`，含每个工具的命令、退出码、结构化 findings

## 工具自动化分层

| 等级 | 含义 | 本工具行为 |
|------|------|-----------|
| **L1** 全自动 | CLI + 结构化输出 | 直接执行 + 解析 findings |
| **L2** 半自动 | 需人工抓包/上传产物 | 占位，提示需要的证据文件 |
| **L3** 人工/硬件 | 逆向、WiFi 网卡、UART | 只列 checklist，不代跑 |

## 加一个新工具

在 `tools/` 下加一个 `Tool` 子类（最简只需 `command_template` + 必填字段），然后在 `tools/catalog.py` 注册。带结构化解析的（如 nmap/testssl）再重写 `parse()`。

```python
class DirsearchTool(Tool):
    id = "dirsearch"; test = "CP-1"; category = "CP"; level = "L1"
    binary = "dirsearch"; requires = ["portal_url"]
    command_template = "dirsearch -u {portal_url} --format plain -o {evidence}.txt"
```

## 路线图

- [x] Part 1：工具合集 + 真实执行 + 结构化结果（当前）
- [ ] 给更多 L1 工具写专用 parser（dirsearch / sqlmap / firmwalker…）
- [ ] L2 证据解析（tshark 读 pcap、MobSF REST API）
- [ ] Part 2：AI 读 findings + CLS 模板 → 生成报告草稿 → 导出 .docx
