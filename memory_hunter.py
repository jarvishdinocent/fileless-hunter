#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import datetime

def run_yara(dump_path, rules_dir, out_dir):
    """Run YARA against the memory dump and save structured results."""
    yara_out = os.path.join(out_dir, "yara_hits.json")

    cmd = [
        "yara",
        "-w",
        "-j",                     # JSON output
        rules_dir,
        dump_path
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    with open(yara_out, "w") as f:
        f.write(result.stdout)

    return yara_out


def run_volatility(dump_path, out_dir):
    """Run key Volatility plugins and store outputs as JSON-like text."""
    plugins = {
        "pslist": "windows.pslist",
        "netscan": "windows.netscan",
        "cmdline": "windows.cmdline"
    }

    outputs = {}

    for name, plugin in plugins.items():
        out_file = os.path.join(out_dir, f"{name}.txt")

        cmd = [
            "vol",
            "-f", dump_path,
            plugin
        ]

        with open(out_file, "w") as f:
            subprocess.run(cmd, stdout=f)

        outputs[name] = out_file

    return outputs


def correlate_results(yara_file, vol_outputs, out_dir):
    """
    Very high-level correlation:
    - If YARA finds hits, mark case as 'suspicious'
    - Attach context from pslist and netscan
    """

    report = {
        "case_time": str(datetime.datetime.utcnow()),
        "status": "clean",
        "yara_hits": [],
        "suspicious_processes": []
    }

    # Load YARA results
    if os.path.exists(yara_file):
        with open(yara_file) as f:
            yara_data = f.read()

        if yara_data.strip():
            report["status"] = "suspicious"
            report["yara_hits"] = yara_data.splitlines()

    # Attach Volatility context (simplified)
    report["volatility_files"] = vol_outputs

    # Save final structured report
    final_json = os.path.join(out_dir, "final_report.json")
    with open(final_json, "w") as f:
        json.dump(report, f, indent=2)

    # Also create human-readable report
    md_report = os.path.join(out_dir, "report.md")
    with open(md_report, "w") as f:
        f.write("# Memory Hunt Report\n\n")
        f.write(f"**Case Time:** {report['case_time']}\n\n")
        f.write(f"**Status:** {report['status']}\n\n")
        f.write("## Files Generated:\n")
        for k, v in vol_outputs.items():
            f.write(f"- `{k}` → `{v}`\n")
        f.write("\nSee `yara_hits.json` for detections.\n")

    return final_json, md_report


def main():
    parser = argparse.ArgumentParser(description="Automated Memory Hunting Tool")
    parser.add_argument("--dump", required=True, help="Path to memory dump")
    parser.add_argument("--rules", required=True, help="Path to YARA rules directory")
    parser.add_argument("--out", required=True, help="Output case directory")

    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)

    print("[+] Running YARA...")
    yara_file = run_yara(args.dump, args.rules, args.out)

    print("[+] Running Volatility plugins...")
    vol_outputs = run_volatility(args.dump, args.out)

    print("[+] Correlating results and building report...")
    final_json, md_report = correlate_results(yara_file, vol_outputs, args.out)

    print("\n[+] Done!")
    print(f"Results saved in: {args.out}")
    print(f"- {final_json}")
    print(f"- {md_report}")


if __name__ == "__main__":
    main()
