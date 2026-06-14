#!/usr/bin/env python3
"""
demo.py - one command to see the whole story:

    1. craft malicious + benign sample model files (make_samples.py)
    2. statically scan them with ModelHawk (no execution)
    3. print the verdicts, then disassemble one malicious sample's opcodes

Run:
    python demo.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import make_samples
import modelhawk

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "samples")


def main():
    use_color = sys.stdout.isatty()
    if use_color:
        modelhawk._enable_windows_ansi()

    print(">> [1/3] crafting sample model files ...")
    files = make_samples.build_samples(SAMPLES)
    print(f"   wrote {len(files)} files to {SAMPLES}\n")

    print(">> [2/3] scanning them statically (ModelHawk never loads a model) ...\n")
    reports = [modelhawk.scan_file(p) for p in modelhawk.gather_paths([SAMPLES])]
    modelhawk.print_reports(reports, use_color=use_color)
    modelhawk._summary(reports, use_color)

    print("\n>> [3/3] opcode disassembly of one malicious sample (the smoking gun):\n")
    target = os.path.join(SAMPLES, "malicious_os_system.p2.pkl")
    one = [r for r in reports if r.path == target] or [r for r in reports
                                                       if r.verdict == "CRITICAL"]
    modelhawk.print_reports(one[:1], use_color=use_color, disasm=True)

    print("Read the GLOBAL/STACK_GLOBAL -> REDUCE chain above: that is os.system "
          "being called at load time.\nThe scanner saw it without ever running it.")


if __name__ == "__main__":
    main()
