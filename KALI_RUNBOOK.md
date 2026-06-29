# Kali 实测手册 —— cls-toolkit L1 工具

> 在 Kali 机器上跑这份就行。每个代码块都可整段复制粘贴进终端。
> 目标：验证 12 个 L1（全自动）工具能不能在真二进制下跑起来 + 出结构化结果。

⚠️ **只对你有授权的 DUT（实验室那台路由器）或你自己的设备跑攻击类工具。** 别对随便的网址跑 sqlmap/commix/xsser/hydra。

---

## 0. 一次性安装（在 Kali 上做一遍）

### 0.1 装依赖 + L1 工具二进制

Kali 现在用 PEP 668，**不要 `pip install`**（会被拦），Python 依赖走 apt：

```bash
sudo apt update
sudo apt install -y \
  git python3-yaml \
  nmap netdiscover hydra binwalk sqlmap commix \
  dirsearch feroxbuster xsser testssl.sh \
  dirb seclists
```

- `python3-yaml` = 工具唯一的 Python 依赖（apt 装的，`sudo python3` 也能用）。
- `dirb` 提供 feroxbuster 默认字典 `/usr/share/wordlists/dirb/common.txt`。
- 大部分工具 Kali 可能已自带，这行只是补齐缺的。

### 0.2 装 firmwalker（不在 apt 里，单独装）

```bash
git clone https://github.com/craigz28/firmwalker.git ~/tools/firmwalker
chmod +x ~/tools/firmwalker/firmwalker.sh
sudo ln -sf ~/tools/firmwalker/firmwalker.sh /usr/local/bin/firmwalker
```

### 0.3 解压 rockyou 字典（hydra 要用）

```bash
sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
ls -la /usr/share/wordlists/rockyou.txt   # 确认在了
```

### 0.4 拉工具仓库

```bash
git clone https://github.com/Monika-12138/cls-toolkit.git ~/cls-toolkit
cd ~/cls-toolkit
```

### 0.5 确认工具二进制都被识别

```bash
python3 cls.py check
```

- 每个 L1 工具应显示 `✓ 已安装`。
- 若 `testssl` 显示 `✗`：Kali 有时把命令装成 `testssl` 而不是 `testssl.sh`。修：
  ```bash
  which testssl testssl.sh
  # 如果只有 testssl，没有 testssl.sh，就建个软链：
  sudo ln -sf "$(which testssl)" /usr/local/bin/testssl.sh
  ```
- `routersploit` 显示 `✗` 正常 —— 见 §2 末尾说明，第一轮先跳过它。

---

## 1. 填设备信息（DUT）

工具的核心逻辑：**填一次 `dut.yaml`，所有命令自动注入。** 每个工具只有在它「需要的字段」都填了才会跑，否则打印 `跳过：DUT 缺字段`。

### 1.1 复制模板并编辑

```bash
cd ~/cls-toolkit
cp dut.example.yaml dut.yaml
nano dut.yaml        # 或 vim / mousepad
```

### 1.2 哪个字段喂哪个工具（关键对照表）

| 你填的字段 | 长什么样 | 喂给哪些 L1 工具 |
|---|---|---|
| `ip` | `192.168.1.1`（DUT 的 IP） | nmap、routersploit、hydra |
| `lan_subnet` | `192.168.1.0/24`（DUT 所在网段） | netdiscover |
| `portal_url` | `https://192.168.1.1`（配置门户网址） | testssl、dirsearch、feroxbuster、sqlmap、commix、xsser |
| `firmware_file` | `/home/kali/dut/fw.bin`（固件包绝对路径） | binwalk |
| `firmware_extract_dir` | binwalk 解包后那个目录（见 §2 Stage D） | firmwalker |
| `users_file` | `/usr/share/wordlists/metasploit/unix_users.txt` | hydra |
| `pass_file` | `/usr/share/wordlists/rockyou.txt` | hydra |

> 其余字段（`toe_name`/`model`/`vendor`/`tester`…）只是写进结果给报告用，不影响能不能跑。

### 1.3 一个最小可跑的例子（以参考机 ASKEY 路由器为例）

```yaml
toe_name: ASKEY RTM7230T
model: RTM7230T-D171
vendor: ASKEY
ip: 192.168.1.1
lan_subnet: 192.168.1.0/24
portal_url: https://192.168.1.1
default_user: admin
default_pass: admin
# 固件相关：有固件文件再填，没有就留空（binwalk/firmwalker 会自动跳过）
firmware_file: ""
firmware_extract_dir: ""
users_file: /usr/share/wordlists/metasploit/unix_users.txt
pass_file: /usr/share/wordlists/rockyou.txt
tester: zicheng
```

把 `ip` / `lan_subnet` / `portal_url` 改成你实验网里 DUT 的真实值即可。

---

## 2. 分阶段测试

`dut.yaml`（含真实 IP/凭据）不会进 git，放心填。结果落在 `evidence/`（原始输出）和 `results/`（结构化 JSON）。

> **关于 sudo**：`nmap -O`（OS 识别）和 `netdiscover` 需要 root。含这两个的流水线用 `sudo python3 cls.py run ...`。因为依赖是 apt 装的，`sudo python3` 一样能用。

### Stage A — 不需要 DUT，先确认工具本身没问题

```bash
python3 cls.py list      # 应列出 20 个模块，12 个 L1
python3 cls.py check     # 二进制识别
```

### Stage B — 安全侦察类（需要 DUT 在线 + 填好 ip / lan_subnet / portal_url）

逐个单独验证（`--tools` 后跟一个 id，方便看单个工具行不行）：

```bash
sudo python3 cls.py run --dut dut.yaml --tools nmap
sudo python3 cls.py run --dut dut.yaml --tools netdiscover
python3 cls.py run --dut dut.yaml --tools testssl
python3 cls.py run --dut dut.yaml --tools dirsearch
python3 cls.py run --dut dut.yaml --tools feroxbuster
```

或一次跑完这组：

```bash
sudo python3 cls.py run --dut dut.yaml --tools nmap,netdiscover,testssl,dirsearch,feroxbuster
```

### Stage C — 主动/攻击类（⚠️ 仅对授权 DUT）

```bash
python3 cls.py run --dut dut.yaml --tools sqlmap
python3 cls.py run --dut dut.yaml --tools commix
python3 cls.py run --dut dut.yaml --tools xsser
# hydra：会拿 rockyou 爆破，很慢；测「能不能跑起来」可先 Ctrl-C
python3 cls.py run --dut dut.yaml --tools hydra
```

### Stage D — 固件类（需要一个固件 .bin 文件）

binwalk 先解包，再把它生成的 `*.extracted` 目录填进 `firmware_extract_dir`，然后跑 firmwalker：

```bash
# 1) 填好 dut.yaml 里的 firmware_file，再跑 binwalk
python3 cls.py run --dut dut.yaml --tools binwalk

# 2) 看 binwalk 解包出的目录名（通常在固件文件同级，形如 _fw.bin.extracted）
ls -d ~/dut/*.extracted

# 3) 把那个目录路径填进 dut.yaml 的 firmware_extract_dir，再跑 firmwalker
python3 cls.py run --dut dut.yaml --tools firmwalker
```

### Stage E — 一把梭（填好哪些字段就跑哪些工具，缺字段的自动跳过）

```bash
sudo python3 cls.py run --dut dut.yaml --plan plan.example.yaml
# 或自己列：
sudo python3 cls.py run --dut dut.yaml --tools nmap,netdiscover,testssl,dirsearch,feroxbuster,sqlmap,commix,xsser
```

### ⚠️ routersploit —— 第一轮先跳过

它的命令模板（`routersploit --execute '...'`）还没在真机验证过，routersploit 本体是交互式的，这条可能跑不通或卡住。**第一轮测试别带它**；想单独试再 `--tools routersploit`，跑不通正常，回来告诉我，我改命令模板。

---

## 3. 出汇总报告

任意 `run` 之后：

```bash
python3 cls.py report
```

- 终端打印：按 CLS 类别（PS/FW/CO/CP/MA/AU…）+ 严重度的统计。
- 同时生成 `results/summary_<时间戳>.md` —— 这份就是以后喂 AI 写报告的输入。

```bash
cat results/summary_*.md | less    # 看最新那份
```

---

## 4. 把结果带回 Windows（可选）

`results/` 和 `evidence/` 在 Kali 上。要带回来看：

```bash
# 在 Kali 上打包
cd ~/cls-toolkit && tar czf /tmp/cls-results.tgz results evidence
```

然后用 U 盘 / 共享文件夹 / `scp` 拷到 Windows。（这些目录不进 git，所以不会自动同步。）

---

## 5. 测完反馈给我

逐个工具记一下：`✓ 跑通且 findings 合理` / `跑通但 findings 不对` / `报错（贴报错）`。重点关注：

- `feroxbuster` 字典路径对不对（没装 dirb 会报字典找不到）。
- `testssl` 二进制名（§0.5 的软链有没有需要）。
- `hydra` 的 http 模块对不对路（路由器登录可能是 form 而非 http-get）。
- `routersploit` 命令模板（预期要改）。

我据此调命令模板 / parser。
