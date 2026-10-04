#!/usr/bin/env python3
"""Convenience entry point; the skill owns the sole workbench implementation."""
from pathlib import Path
import runpy

if __name__ == "__main__":
    runpy.run_path(str(Path(__file__).resolve().parents[1]/".agents/skills/direct-pe-x64/scripts/pe_workbench.py"), run_name="__main__")
