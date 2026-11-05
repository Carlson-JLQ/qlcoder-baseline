#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["openpyxl>=3.1,<4"]
# ///
"""Build an Excel report for successful QLCoder CVE runs."""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime
from pathlib import Path

from openpyxl import Workbook, load_workbook
from openpyxl.comments import Comment
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.worksheet.table import Table, TableStyleInfo


ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = ROOT / "output"
FAILURE_REPORT = Path(__file__).resolve().parent / "qlcoder_failed_cves.xlsx"
PROJECT_INFO = ROOT / "data" / "project_info.csv"
CVE_LIST = ROOT / "data" / "cve_bak.txt"
REPORT_PATH = Path(__file__).resolve().parent / "qlcoder_successful_cve_results.xlsx"


def load_failed_cves() -> set[str]:
    workbook = load_workbook(FAILURE_REPORT, read_only=True, data_only=True)
    sheet = workbook["失败 CVE 明细"]
    failed = {
        row[1]
        for row in sheet.iter_rows(min_row=2, values_only=True)
        if row[1]
    }
    workbook.close()
    return failed


def load_cwe_map() -> dict[str, str]:
    mapping: dict[str, str] = {}
    with PROJECT_INFO.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            cve = row.get("cve_id", "").strip()
            cwe = row.get("cwe_id", "").strip()
            if cve and cwe:
                mapping.setdefault(cve, cwe)
    return mapping


def load_cve_list() -> list[str]:
    cves = []
    for line in CVE_LIST.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            cves.append(value.split()[0])
    return cves


def extract_agent_turns(results_dir: Path) -> int:
    turns = 0
    agent_outputs = [results_dir / "phase1_output.txt"]
    agent_outputs.extend(sorted(results_dir.glob("phase3_iter_*_output.txt")))
    for output_path in agent_outputs:
        if not output_path.exists():
            continue
        with output_path.open(encoding="utf-8") as stream:
            payload = json.load(stream)
        messages = payload if isinstance(payload, list) else [payload]
        result_messages = [
            item
            for item in messages
            if isinstance(item, dict)
            and item.get("type") == "result"
            and isinstance(item.get("num_turns"), int)
        ]
        if not result_messages:
            raise ValueError(f"No agent num_turns found in {output_path}")
        turns += result_messages[-1]["num_turns"]
    return turns


def summarize_metrics(results_dir: Path) -> dict:
    totals = {
        "total_effective_tokens": 0,
        "total_cost": 0.0,
    }
    for metrics_path in results_dir.glob("*_metrics.json"):
        with metrics_path.open(encoding="utf-8") as stream:
            usage = json.load(stream).get("api_usage", {})
        totals["total_effective_tokens"] += sum(
            int(usage.get(key, 0))
            for key in (
                "total_input_tokens",
                "total_cache_creation_tokens",
                "total_cache_read_tokens",
                "total_output_tokens",
            )
        )
        totals["total_cost"] += float(usage.get("total_cost_usd", 0))
    return totals


def runtime_from_log(results_dir: Path) -> float:
    timestamps: list[datetime] = []
    pattern = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})")
    for log_path in results_dir.glob("iterative_vuln_analysis_*.log"):
        for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
            match = pattern.match(line)
            if match:
                timestamps.append(datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S,%f"))
    if len(timestamps) < 2:
        raise ValueError(f"Cannot derive runtime from logs in {results_dir}")
    return (max(timestamps) - min(timestamps)).total_seconds()


def collect_rows() -> tuple[list[dict], int, int]:
    failed = load_failed_cves()
    cwe_map = load_cwe_map()
    requested_cves = load_cve_list()
    successful_cves = set(requested_cves) - failed
    rows: list[dict] = []
    run_dirs = sorted(path for path in OUTPUT_DIR.glob("ql_agent_CVE-*") if path.is_dir())
    run_by_cve = {
        path.name.removeprefix("ql_agent_").split("_", 1)[0]: path for path in run_dirs
    }

    for cve in successful_cves:
        if cve not in run_by_cve:
            raise ValueError(f"No output directory found for {cve}")
        run_dir = run_by_cve[cve]
        results_dir = run_dir / "results"
        metadata_path = results_dir / "iterative_metadata.json"
        if cve not in cwe_map:
            raise ValueError(f"CWE not found for {cve}")

        if metadata_path.exists():
            with metadata_path.open(encoding="utf-8") as stream:
                analysis = json.load(stream)["analysis_metadata"]
            usage = analysis["api_usage_summary"]
            total_tokens = int(usage["total_effective_tokens"])
            total_cost = float(usage["total_cost_usd"])
            duration_seconds = float(analysis["duration_seconds"])
            total_iterations = int(analysis["total_iterations"])
        else:
            usage = summarize_metrics(results_dir)
            total_tokens = int(usage["total_effective_tokens"])
            total_cost = float(usage["total_cost"])
            duration_seconds = runtime_from_log(results_dir)
            total_iterations = len(list(results_dir.glob("phase3_iter_*_metrics.json")))

        rows.append(
            {
                "CWE": cwe_map[cve],
                "CVE": cve,
                "Total Tokens": total_tokens,
                "Runtime": duration_seconds / 86400,
                "Query Iterations": total_iterations,
                "agent trun": extract_agent_turns(results_dir),
                # Per the experiment owner's clarification, this batch's
                # deepseek-v4.1-flash pricing-table value is denominated in CNY.
                "Cost (CNY)": total_cost,
            }
        )

    rows.sort(key=lambda row: (int(row["CWE"].split("-")[1]), row["CVE"]))
    return rows, len(requested_cves), len(failed)


def style_main_sheet(sheet, row_count: int) -> None:
    navy = "1F4E78"
    pale_blue = "D9EAF7"
    grid = Side(style="thin", color="D9E2F3")

    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = f"A1:G{row_count + 1}"
    sheet.sheet_view.showGridLines = False
    sheet.row_dimensions[1].height = 28
    sheet.column_dimensions["A"].width = 13
    sheet.column_dimensions["B"].width = 20
    sheet.column_dimensions["C"].width = 18
    sheet.column_dimensions["D"].width = 16
    sheet.column_dimensions["E"].width = 18
    sheet.column_dimensions["F"].width = 14
    sheet.column_dimensions["G"].width = 16

    for cell in sheet[1]:
        cell.fill = PatternFill("solid", fgColor=navy)
        cell.font = Font(color="FFFFFF", bold=True)
        cell.alignment = Alignment(horizontal="center", vertical="center")

    for row in sheet.iter_rows(min_row=2, max_row=row_count + 1):
        for cell in row:
            cell.border = Border(bottom=grid)
            cell.alignment = Alignment(horizontal="center", vertical="center")
        if row[0].row % 2 == 1:
            for cell in row:
                cell.fill = PatternFill("solid", fgColor=pale_blue)

    for cell in sheet["C"][1:]:
        cell.number_format = "#,##0"
    for cell in sheet["D"][1:]:
        cell.number_format = "[h]:mm:ss"
    for cell in sheet["E"][1:]:
        cell.number_format = "0"
    for cell in sheet["F"][1:]:
        cell.number_format = "0"
    for cell in sheet["G"][1:]:
        cell.number_format = "¥0.000000"

    table = Table(displayName="SuccessfulCVEResults", ref=f"A1:G{row_count + 1}")
    table.tableStyleInfo = TableStyleInfo(
        name="TableStyleMedium2",
        showFirstColumn=False,
        showLastColumn=False,
        showRowStripes=False,
        showColumnStripes=False,
    )
    sheet.add_table(table)

    sheet["C1"].comment = Comment(
        "Effective tokens = input + cache creation + cache read + output tokens.",
        "Codex",
    )
    sheet["D1"].comment = Comment(
        "整次运行 duration_seconds，显示格式为 [h]:mm:ss。", "Codex"
    )
    sheet["F1"].comment = Comment(
        "Phase 1 与全部 Phase 3 agent 会话 num_turns 的合计。", "Codex"
    )
    sheet["G1"].comment = Comment(
        "直接使用 output 中 pricing_table 计算值；按实验方说明，该批次以人民币计费，不做汇率换算。",
        "Codex",
    )


def add_notes_sheet(
    workbook: Workbook,
    run_count: int,
    listed_failed_count: int,
    success_count: int,
) -> None:
    sheet = workbook.create_sheet("口径说明")
    sheet.sheet_view.showGridLines = False
    sheet.column_dimensions["A"].width = 23
    sheet.column_dimensions["B"].width = 92
    sheet.append(["项目", "说明"])
    notes = [
        ("运行总数", run_count),
        ("失败清单排除", listed_failed_count),
        ("成功 CVE", success_count),
        ("筛选口径", "data/cve_bak.txt 的 32 个 CVE 减去失败 Excel 中的 CVE。"),
        ("失败筛选依据", "doc/2026-11-2/qlcoder_failed_cves.xlsx 的“失败 CVE 明细”。"),
        ("CWE 来源", "data/project_info.csv 的 cwe_id。"),
        ("Total Tokens", "output 中 total_effective_tokens：input + cache creation + cache read + output。"),
        ("Runtime", "iterative_metadata.json 的 duration_seconds；主表显示为 [h]:mm:ss。"),
        ("Query Iterations", "iterative_metadata.json 的 total_iterations。"),
        ("agent trun", "Phase 1 与全部 Phase 3 输出中 num_turns 的合计；列名按需求原样保留。"),
        ("Cost (CNY)", "deepseek-v4.1-flash pricing_table 计算值；按实验方说明以人民币计费，未做汇率换算。"),
    ]
    for item in notes:
        sheet.append(item)

    for cell in sheet[1]:
        cell.fill = PatternFill("solid", fgColor="1F4E78")
        cell.font = Font(color="FFFFFF", bold=True)
        cell.alignment = Alignment(horizontal="center", vertical="center")
    for row in sheet.iter_rows(min_row=2):
        row[0].font = Font(bold=True, color="1F4E78")
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions


def main() -> None:
    rows, run_count, failed_count = collect_rows()
    if run_count != 32:
        raise ValueError(f"Expected 32 run directories, found {run_count}")
    if len(rows) + failed_count != run_count:
        raise ValueError(
            f"Count mismatch: {len(rows)} successful + {failed_count} failed != {run_count}"
        )

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "成功 CVE 数据"
    headers = ["CWE", "CVE", "Total Tokens", "Runtime", "Query Iterations", "agent trun", "Cost (CNY)"]
    sheet.append(headers)
    for row in rows:
        sheet.append([row[header] for header in headers])
    style_main_sheet(sheet, len(rows))
    add_notes_sheet(workbook, run_count, failed_count, len(rows))

    workbook.calculation.fullCalcOnLoad = True
    workbook.calculation.forceFullCalc = True
    workbook.save(REPORT_PATH)
    print(f"Created: {REPORT_PATH}")
    print(
        f"Runs: {run_count}; failure-sheet excluded: {failed_count}; "
        f"successful rows: {len(rows)}"
    )


if __name__ == "__main__":
    main()
