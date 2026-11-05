#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "matplotlib>=3.8,<4",
#   "openpyxl>=3.1,<4",
# ]
# ///
"""Generate an Excel report and bar chart for CVEs grouped by CWE.

Run from anywhere with:
    uv run doc/2026-11-2/generate_cve_cwe_report.py
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt
from openpyxl import Workbook
from openpyxl.drawing.image import Image
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
DEFAULT_CVE_FILE = REPO_ROOT / "data" / "cve_bak.txt"
DEFAULT_PROJECT_INFO = REPO_ROOT / "data" / "project_info.csv"
DEFAULT_EXCEL = SCRIPT_DIR / "cve_by_cwe.xlsx"
DEFAULT_CHART = SCRIPT_DIR / "cve_count_by_cwe.png"


def normalize_cwe(cwe: str) -> str:
    """Normalize equivalent values such as CWE-94 and CWE-094."""
    match = re.fullmatch(r"CWE-(\d+)", cwe.strip(), flags=re.IGNORECASE)
    if not match:
        return cwe.strip().upper()
    number = int(match.group(1))
    return f"CWE-{number:03d}" if number < 1000 else f"CWE-{number}"


def cwe_sort_key(cwe: str) -> tuple[int, str]:
    match = re.search(r"(\d+)$", cwe)
    return (int(match.group(1)) if match else 10**9, cwe)


def load_rows(cve_file: Path, project_info: Path) -> list[tuple[str, str]]:
    cves = [line.strip() for line in cve_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    requested = set(cves)

    mapping: dict[str, str] = {}
    with project_info.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            cve = row["cve_id"].strip()
            if cve in requested:
                mapping[cve] = normalize_cwe(row["cwe_id"])

    missing = sorted(requested - mapping.keys())
    if missing:
        raise ValueError("CWE mapping not found for: " + ", ".join(missing))

    # Deduplicate CVEs and place CVEs with the same CWE together.
    return sorted(
        ((mapping[cve], cve) for cve in requested),
        key=lambda item: (cwe_sort_key(item[0]), item[1]),
    )


def draw_chart(rows: list[tuple[str, str]], chart_path: Path) -> Counter[str]:
    counts = Counter(cwe for cwe, _ in rows)
    cwes = sorted(counts, key=cwe_sort_key)
    values = [counts[cwe] for cwe in cwes]

    fig, ax = plt.subplots(figsize=(14, 7))
    bars = ax.bar(cwes, values, color="#4472C4", edgecolor="#2F5597")
    ax.set_title("CVE Count by CWE", fontsize=16, pad=16)
    ax.set_xlabel("CWE")
    ax.set_ylabel("CVE Count")
    ax.set_ylim(0, max(values) + 1)
    ax.grid(axis="y", linestyle="--", alpha=0.35)
    ax.set_axisbelow(True)
    ax.tick_params(axis="x", rotation=55)
    ax.bar_label(bars, padding=3, fontsize=9)

    fig.tight_layout()
    chart_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(chart_path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    return counts


def style_header(sheet, row: int = 1) -> None:
    fill = PatternFill("solid", fgColor="4472C4")
    for cell in sheet[row]:
        cell.fill = fill
        cell.font = Font(color="FFFFFF", bold=True)
        cell.alignment = Alignment(horizontal="center")


def autosize(sheet) -> None:
    for column in sheet.columns:
        width = max(len(str(cell.value or "")) for cell in column) + 2
        sheet.column_dimensions[get_column_letter(column[0].column)].width = min(width, 40)


def write_excel(
    rows: list[tuple[str, str]], counts: Counter[str], excel_path: Path, chart_path: Path
) -> None:
    workbook = Workbook()

    details = workbook.active
    details.title = "CVE by CWE"
    details.append(["CWE", "CVE"])
    for row in rows:
        details.append(row)
    style_header(details)
    details.freeze_panes = "A2"
    details.auto_filter.ref = details.dimensions
    autosize(details)

    summary = workbook.create_sheet("CWE Summary")
    summary.append(["CWE", "CVE Count"])
    for cwe in sorted(counts, key=cwe_sort_key):
        summary.append([cwe, counts[cwe]])
    style_header(summary)
    summary.freeze_panes = "A2"
    summary.auto_filter.ref = summary.dimensions
    autosize(summary)

    chart_sheet = workbook.create_sheet("Chart")
    chart_sheet.add_image(Image(str(chart_path)), "A1")

    excel_path.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(excel_path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cve-file", type=Path, default=DEFAULT_CVE_FILE)
    parser.add_argument("--project-info", type=Path, default=DEFAULT_PROJECT_INFO)
    parser.add_argument("--excel", type=Path, default=DEFAULT_EXCEL)
    parser.add_argument("--chart", type=Path, default=DEFAULT_CHART)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows = load_rows(args.cve_file.resolve(), args.project_info.resolve())
    counts = draw_chart(rows, args.chart.resolve())
    write_excel(rows, counts, args.excel.resolve(), args.chart.resolve())
    print(f"Created Excel: {args.excel.resolve()}")
    print(f"Created chart: {args.chart.resolve()}")
    print(f"Processed {len(rows)} CVEs across {len(counts)} CWEs")


if __name__ == "__main__":
    main()
