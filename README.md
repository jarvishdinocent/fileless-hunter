# **Memory Hunter — Automated Fileless Threat Detection**

**Repository:** `memory-hunter`
**Author:** Smruti Ranjan Pradhan
**Purpose:** Blue-team threat hunting, memory forensics, and fileless attack detection.

---

## 🔍 Overview

**Memory Hunter** is an automated memory forensics pipeline that helps defenders detect **fileless attacks** — threats that live only in RAM and never touch the disk.

Traditional security tools (antivirus and EDR) focus on files. This tool focuses on **memory**, where modern attackers often hide.

Memory Hunter:

* Takes a RAM dump as input
* Runs **YARA** to detect malicious patterns in memory
* Runs **Volatility3** to reconstruct processes and network activity
* Correlates evidence automatically
* Produces **structured JSON + human-readable Markdown reports**

It is designed for:

* SOC analysts
* Incident responders
* Threat hunters
* Digital forensics practitioners

---

## 🧠 How It Works (High-Level Pipeline)

The tool follows a five-phase workflow:

1. **Memory Capture**
   A full snapshot of system RAM is taken using a tool like **WinPmem**.

2. **Volatility Parsing (Phase 1)**
   Volatility reconstructs processes, parents, and network connections.

3. **YARA Hunting**
   Custom YARA rules scan the memory dump for in-memory beacons, loaders, or malicious artifacts.

4. **Volatility Pivoting (Phase 2)**
   Suspicious YARA hits are mapped back to real processes and network IOCs.

5. **Python Orchestration**
   Everything is automated via one command and results are correlated into a case folder.

---

## 🚀 Installation

### Prerequisites

You must have these installed on your system:

```bash
pip install yara-python
pip install volatility3
```

(You also need Volatility3 available as `vol` in your PATH.)

Clone the repository:

```bash
git clone https://github.com/YourUsername/memory-hunter.git
cd memory-hunter
```

(Optional) Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🛠️ Usage

### Basic Command

```bash
python3 memory_hunter.py \
  --dump memory.raw \
  --rules ./rules \
  --out ./cases/case-001
```

### Arguments

| Flag      | Meaning                         |
| --------- | ------------------------------- |
| `--dump`  | Path to RAM dump file           |
| `--rules` | Directory containing YARA rules |
| `--out`   | Output case folder              |

---

## 📁 Output Structure

After execution, your case folder will look like this:

```
case-001/
│── yara_hits.json
│── pslist.txt
│── netscan.txt
│── cmdline.txt
│── final_report.json
└── report.md
```

### What each file means:

* **yara_hits.json** – All in-memory detections
* **pslist.txt** – Process list from Volatility
* **netscan.txt** – Network connections from memory
* **cmdline.txt** – How processes were launched
* **final_report.json** – Machine-readable case summary
* **report.md** – Human-readable incident report

---

## 🧩 Example YARA Rule (included in repo)

Example rule for in-memory beacon detection:

```yara
rule fileless_malware_catcher_v1
{
    meta:
        author = "Smruti ranjan"
        description = "Detects in-memory beacon artifacts"

    strings:
        $s1 = "SMRUTI_FILELESS_BEACON"
        $hl = { 53 4D 52 55 54 49 5F 46 49 4C 45 4C 45 53 53 5F 42 45 41 43 4F 4E }

    condition:
        any of them
}
```

---

## 🔗 Integration with SOC / CTI Platforms

Outputs can be:

* Attached to incident tickets
* Uploaded to **OpenCTI**
* Fed into SIEM dashboards
* Shared with SOC analysts

The structured JSON makes automation easy.

---

## ⚠️ Security & Ethics Notice

This tool is meant **only for defensive, forensic, and authorized use**.

Do **not** use it to:

* Spy on systems
* Hack networks
* Bypass security
* Analyze machines you don’t own

The author is not responsible for misuse.

---

## 📜 License

This project is licensed under the **MIT License** — you are free to use, modify, and distribute it with attribution.

---

## ✍️ About the Author

**Smruti Ranjan Pradhan**
Threat Intelligence Analyst
Focused on memory forensics, fileless threats, and automated detection pipelines.

---

## ⭐ Contribute

Pull requests are welcome!

To contribute:

1. Fork the repo
2. Create a feature branch
3. Commit changes
4. Open a PR

---

## 📧 Contact

If you want to collaborate or discuss research, reach out via GitHub issues.
