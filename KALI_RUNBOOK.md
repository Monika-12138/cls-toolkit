# Kali Test Runbook -- cls-toolkit L1 tools

> Run this on the Kali machine. Every code block can be copy-pasted whole into the terminal.
> Goal: verify the 12 L1 (fully automated) tools actually run with real binaries and
> produce structured results.

WARNING: only run the offensive tools against a DUT you are authorized to test (the lab
router) or your own device. Do not run sqlmap/commix/xsser/hydra against random hosts.

> If you are logged in as **root** (prompt ends in `#`), you can drop every `sudo` below.

---

## 0. One-time install (do once on Kali)

### 0.1 Dependencies + L1 tool binaries

Modern Kali uses PEP 668, so **do not `pip install`** (it is blocked). The only Python
dependency goes through apt:

```bash
sudo apt update
sudo apt install -y \
  git python3-yaml \
  nmap netdiscover hydra binwalk sqlmap commix \
  dirsearch feroxbuster xsser testssl.sh \
  dirb seclists
```

- `python3-yaml` = the tool's only Python dependency (apt-installed, so `sudo python3`
  can use it too). It is often already installed.
- `dirb` provides feroxbuster's default wordlist `/usr/share/wordlists/dirb/common.txt`.
- Most tools may already ship with Kali; this line just fills in what's missing.
- If you hit a `404 Not Found` during install, your package index is stale -- run
  `sudo apt update` first, then re-run the install.

### 0.2 Install firmwalker (not in apt, install separately)

```bash
git clone https://github.com/craigz28/firmwalker.git ~/tools/firmwalker
chmod +x ~/tools/firmwalker/firmwalker.sh
sudo ln -sf ~/tools/firmwalker/firmwalker.sh /usr/local/bin/firmwalker
```

### 0.3 Unzip the rockyou wordlist (needed by hydra)

```bash
sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
ls -la /usr/share/wordlists/rockyou.txt   # confirm it's there
```

### 0.4 Clone the toolkit

```bash
git clone https://github.com/Monika-12138/cls-toolkit.git ~/cls-toolkit
cd ~/cls-toolkit
```

### 0.5 Confirm the binaries are detected

```bash
python3 cls.py check
```

- Each L1 tool should show `[+] installed`.
- If `testssl` shows `[-] missing`: Kali sometimes installs the command as `testssl`
  rather than `testssl.sh`. Fix:
  ```bash
  which testssl testssl.sh
  # if only testssl exists, symlink it:
  sudo ln -sf "$(which testssl)" /usr/local/bin/testssl.sh
  ```
- `routersploit` showing `[-] missing` is fine -- see the note at the end of section 2;
  skip it in the first round.

---

## 1. Fill in the device info (DUT)

Core idea: **fill `dut.yaml` once, and every command auto-injects from it.** A tool only
runs if all of its required fields are filled, otherwise it prints `skipped: DUT missing
fields`.

### 1.1 Copy the template and edit

```bash
cd ~/cls-toolkit
cp dut.example.yaml dut.yaml
nano dut.yaml        # or vim / mousepad
```

### 1.2 Which field feeds which tool (key mapping)

| Field you fill | Looks like | Feeds these L1 tools |
|---|---|---|
| `ip` | `192.168.1.1` (DUT IP) | nmap, routersploit, hydra |
| `lan_subnet` | `192.168.1.0/24` (DUT subnet) | netdiscover |
| `portal_url` | `https://192.168.1.1` (config portal URL) | testssl, dirsearch, feroxbuster, sqlmap, commix, xsser |
| `firmware_file` | `/home/kali/dut/fw.bin` (absolute path) | binwalk |
| `firmware_extract_dir` | the dir binwalk extracted to (see section 2, Stage D) | firmwalker |
| `users_file` | `/usr/share/wordlists/metasploit/unix_users.txt` | hydra |
| `pass_file` | `/usr/share/wordlists/rockyou.txt` | hydra |

> Other fields (`toe_name`/`model`/`vendor`/`tester`...) are just written into the
> results for the report; they don't affect whether a tool runs.

### 1.3 A minimal working example (reference router: ASKEY)

```yaml
toe_name: ASKEY RTM7230T
model: RTM7230T-D171
vendor: ASKEY
ip: 192.168.1.1
lan_subnet: 192.168.1.0/24
portal_url: https://192.168.1.1
default_user: admin
default_pass: admin
# firmware: fill only if you have a firmware file, otherwise leave empty
# (binwalk/firmwalker auto-skip when empty)
firmware_file: ""
firmware_extract_dir: ""
users_file: /usr/share/wordlists/metasploit/unix_users.txt
pass_file: /usr/share/wordlists/rockyou.txt
tester: zicheng
```

Change `ip` / `lan_subnet` / `portal_url` to your lab DUT's real values.

---

## 2. Staged testing

`dut.yaml` (with real IP/creds) is gitignored, so fill it freely. Results land in
`evidence/` (raw output) and `results/` (structured JSON).

> **About sudo**: `nmap -O` (OS detection) and `netdiscover` need root. Run pipelines
> that include those with `sudo python3 cls.py run ...`. Since the dependency is
> apt-installed, `sudo python3` still finds it. (If you are root, no sudo needed.)

### Stage A -- no DUT needed, confirm the tool itself is fine

```bash
python3 cls.py list      # should list 20 modules, 12 of them L1
python3 cls.py check     # binary detection
```

### Stage B -- safe recon (needs DUT online + ip / lan_subnet / portal_url filled)

Verify one at a time (`--tools` with a single id, so you can see each tool individually):

```bash
sudo python3 cls.py run --dut dut.yaml --tools nmap
sudo python3 cls.py run --dut dut.yaml --tools netdiscover
python3 cls.py run --dut dut.yaml --tools testssl
python3 cls.py run --dut dut.yaml --tools dirsearch
python3 cls.py run --dut dut.yaml --tools feroxbuster
```

Or run the whole group at once:

```bash
sudo python3 cls.py run --dut dut.yaml --tools nmap,netdiscover,testssl,dirsearch,feroxbuster
```

### Stage C -- active/offensive (WARNING: authorized DUT only)

```bash
python3 cls.py run --dut dut.yaml --tools sqlmap
python3 cls.py run --dut dut.yaml --tools commix
python3 cls.py run --dut dut.yaml --tools xsser
# hydra: brute-forces with rockyou, very slow; to just test "does it start", Ctrl-C early
python3 cls.py run --dut dut.yaml --tools hydra
```

### Stage D -- firmware (needs a firmware .bin file)

binwalk extracts first; then put the `*.extracted` directory it creates into
`firmware_extract_dir`, and run firmwalker:

```bash
# 1) fill firmware_file in dut.yaml, then run binwalk
python3 cls.py run --dut dut.yaml --tools binwalk

# 2) find the directory binwalk extracted to (usually next to the firmware file,
#    named like _fw.bin.extracted)
ls -d ~/dut/*.extracted

# 3) put that path into dut.yaml's firmware_extract_dir, then run firmwalker
python3 cls.py run --dut dut.yaml --tools firmwalker
```

### Stage E -- all at once (runs whatever fields are filled; the rest auto-skip)

```bash
sudo python3 cls.py run --dut dut.yaml --plan plan.example.yaml
# or list your own:
sudo python3 cls.py run --dut dut.yaml --tools nmap,netdiscover,testssl,dirsearch,feroxbuster,sqlmap,commix,xsser
```

### WARNING: routersploit -- skip it in round 1

Its command template (`routersploit --execute '...'`) is not yet verified on a real
box, and routersploit itself is interactive, so this one may fail or hang. **Leave it
out of the first test run.** If you want to try it separately, `--tools routersploit`;
a failure is expected -- report back and I'll fix the command template.

---

## 3. Produce the summary report

After any `run`:

```bash
python3 cls.py report
```

- Terminal prints: stats by CLS category (PS/FW/CO/CP/MA/AU...) + severity.
- Also writes `results/summary_<timestamp>.md` -- this is the input for AI report
  writing later.

```bash
cat results/summary_*.md | less    # view the newest one
```

---

## 4. Bring results back to Windows (optional)

`results/` and `evidence/` live on Kali. To take them back:

```bash
# pack on Kali
cd ~/cls-toolkit && tar czf /tmp/cls-results.tgz results evidence
```

Then copy to Windows via USB / shared folder / `scp`. (These dirs are gitignored, so
they don't sync automatically.)

---

## 5. Report back to me

For each tool, note: `OK ran and findings look right` / `ran but findings wrong` /
`error (paste it)`. Watch especially:

- `feroxbuster` wordlist path (missing dirb -> "wordlist not found" error).
- `testssl` binary name (whether the section 0.5 symlink was needed).
- `hydra` http module (a router login may be a form, not http-get).
- `routersploit` command template (expected to need a fix).

I'll adjust the command templates / parsers from there.
