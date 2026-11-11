#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["openpyxl>=3.1,<4"]
# ///
"""Generate the Phase 1 metrics workbook for the 14 retained CVEs."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from openpyxl import Workbook, load_workbook
from openpyxl.comments import Comment
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.worksheet.table import Table, TableStyleInfo


ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = ROOT / "output"
CVE_LIST = ROOT / "data" / "cve_bak.txt"
PROJECT_INFO = ROOT / "data" / "project_info.csv"
FAILURE_REPORT = ROOT / "doc" / "2026-11-2" / "qlcoder_failed_cves.xlsx"
REPORT_PATH = Path(__file__).resolve().parent / "phase1_successful_cve_metrics.xlsx"


def load_cve_list() -> list[str]:
    return [
        line.strip().split()[0]
        for line in CVE_LIST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def load_failed_cves() -> set[str]:
    workbook = load_workbook(FAILURE_REPORT, read_only=True, data_only=True)
    sheet = workbook["失败 CVE 明细"]
    failed = {
        str(row[1]).strip()
        for row in sheet.iter_rows(min_row=2, values_only=True)
        if row[1]
    }
    workbook.close()
    return failed


def load_cwe_map() -> dict[str, str]:
    result: dict[str, str] = {}
    with PROJECT_INFO.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            cve = row.get("cve_id", "").strip()
            cwe = row.get("cwe_id", "").strip()
            if cve and cwe:
                result.setdefault(cve, cwe)
    return result


def find_run_dir(cve: str) -> Path:
    matches = sorted(OUTPUT_DIR.glob(f"ql_agent_{cve}_*"))
    if len(matches) != 1:
        raise ValueError(f"Expected one output directory for {cve}, found {len(matches)}")
    return matches[0]


def read_phase1_result(output_path: Path) -> dict:
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    messages = payload if isinstance(payload, list) else [payload]
    results = [
        item
        for item in messages
        if isinstance(item, dict) and item.get("type") == "result"
    ]
    if not results:
        raise ValueError(f"No result event found in {output_path}")
    return results[-1]


def collect_rows() -> tuple[list[dict], int, int]:
    requested = load_cve_list()
    failed = load_failed_cves()
    retained = [cve for cve in requested if cve not in failed]
    cwe_map = load_cwe_map()

    if len(requested) != 32:
        raise ValueError(f"Expected 32 CVEs in {CVE_LIST}, found {len(requested)}")
    if len(failed) != 18:
        raise ValueError(f"Expected 18 CVEs in the existing failure list, found {len(failed)}")
    if len(retained) != 14:
        raise ValueError(f"Expected 14 retained CVEs, found {len(retained)}")

    rows: list[dict] = []
    for cve in retained:
        run_dir = find_run_dir(cve)
        results_dir = run_dir / "results"
        metrics_path = results_dir / "phase1_metrics.json"
        output_path = results_dir / "phase1_output.txt"
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))

        if metrics.get("phase_name") != "phase1":
            raise ValueError(f"Unexpected phase in {metrics_path}")
        if metrics.get("success") is not True or metrics.get("return_code") != 0:
            raise ValueError(f"Phase 1 is not successful for {cve}")
        if cve not in cwe_map:
            raise ValueError(f"Missing CWE for {cve}")

        usage = metrics.get("api_usage", {})
        total_tokens = sum(
            int(usage.get(key, 0))
            for key in (
                "total_input_tokens",
                "total_cache_creation_tokens",
                "total_cache_read_tokens",
                "total_output_tokens",
            )
        )
        result = read_phase1_result(output_path)
        duration_ms = result.get("duration_ms")
        llm_calls = result.get("num_turns")
        if not isinstance(duration_ms, (int, float)):
            raise ValueError(f"Missing duration_ms for {cve}")
        if not isinstance(llm_calls, int):
            raise ValueError(f"Missing num_turns for {cve}")

        rows.append(
            {
                "CWE": cwe_map[cve],
                "CVE": cve,
                "Total Tokens": total_tokens,
                "Runtime": float(duration_ms) / 1000 / 86400,
                "LLM Calls": llm_calls,
                "Cost (CNY)": float(usage.get("total_cost_usd", 0.0)),
            }
        )

    return rows, len(requested), len(failed)


def style_metrics_sheet(sheet, row_count: int) -> None:
    navy = "1F4E78"
    pale_blue = "D9EAF7"
    grid = Side(style="thin", color="D9E2F3")

    sheet.freeze_panes = "A2"
    sheet.sheet_view.showGridLines = False
    sheet.auto_filter.ref = f"A1:F{row_count + 1}"
    sheet.row_dimensions[1].height = 28

    widths = {"A": 13, "B": 20, "C": 18, "D": 16, "E": 14, "F": 16}
    for column, width in widths.items():
        sheet.column_dimensions[column].width = width

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
        cell.number_format = "¥0.000000"

    table = Table(displayName="Phase1SuccessfulCVEMetrics", ref=f"A1:F{row_count + 1}")
    table.tableStyleInfo = TableStyleInfo(
        name="TableStyleMedium2",
        showFirstColumn=False,
        showLastColumn=False,
        showRowStripes=False,
        showColumnStripes=False,
    )
    sheet.add_table(table)

    sheet["C1"].comment = Comment(
        "Total Tokens = input + cache creation + cache read + output tokens，仅统计 Phase 1。",
        "Codex",
    )
    sheet["D1"].comment = Comment(
        "来自 phase1_output.txt 最终 result 的 duration_ms，显示为 [h]:mm:ss。",
        "Codex",
    )
    sheet["E1"].comment = Comment(
        "来自 Phase 1 最终 result 的 num_turns，作为 LLM 调用轮次代理。",
        "Codex",
    )
    sheet["F1"].comment = Comment(
        "使用 phase1_metrics.json 中 pricing_table 重算的 total_cost_usd 数值；按实验说明以人民币计费，不做汇率换算。",
        "Codex",
    )


def add_summary_sheet(workbook: Workbook, rows: list[dict], total: int, excluded: int) -> None:
    sheet = workbook.create_sheet("汇总与口径")
    sheet.sheet_view.showGridLines = False
    sheet.column_dimensions["A"].width = 25
    sheet.column_dimensions["B"].width = 92
    sheet.append(["项目", "数值或说明"])

    runtime_days = sum(row["Runtime"] for row in rows)
    items = [
        ("data/cve_bak.txt CVE 总数", total),
        ("按既有失败清单排除", excluded),
        ("本表 CVE 数", len(rows)),
        ("Phase 1 Total Tokens 合计", sum(row["Total Tokens"] for row in rows)),
        ("Phase 1 Runtime 合计", runtime_days),
        ("Phase 1 LLM Calls 合计", sum(row["LLM Calls"] for row in rows)),
        ("Phase 1 Cost (CNY) 合计", sum(row["Cost (CNY)"] for row in rows)),
        ("筛选口径", "data/cve_bak.txt 的 32 个 CVE，排除 doc/2026-11-2/qlcoder_failed_cves.xlsx 中既有的 18 个失败 CVE。"),
        ("数据范围", "只读取 phase1_metrics.json 和 phase1_output.txt；不包含 Phase 2、Phase 3 或整次运行指标。"),
        ("CWE 来源", "data/project_info.csv 的 cwe_id。"),
        ("Total Tokens", "input + cache creation + cache read + output tokens。"),
        ("Runtime", "Phase 1 最终 result 的 duration_ms；包括该 agent 会话中的工具等待时间。"),
        ("LLM Calls", "以 Phase 1 最终 result 的 num_turns 作为模型调用轮次代理；不是 sessions_count，也不是工具调用次数。"),
        ("Cost (CNY)", "使用 pricing_table 重算值 total_cost_usd；字段名为历史命名，按实验说明币种视为人民币。"),
    ]
    for item in items:
        sheet.append(item)

    for cell in sheet[1]:
        cell.fill = PatternFill("solid", fgColor="1F4E78")
        cell.font = Font(color="FFFFFF", bold=True)
        cell.alignment = Alignment(horizontal="center", vertical="center")
    for row in sheet.iter_rows(min_row=2):
        row[0].font = Font(bold=True, color="1F4E78")
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)

    sheet["B5"].number_format = "#,##0"
    sheet["B6"].number_format = "[h]:mm:ss"
    sheet["B7"].number_format = "0"
    sheet["B8"].number_format = "¥0.000000"
    sheet.freeze_panes = "A2"


def main() -> None:
    rows, total, excluded = collect_rows()
    headers = ["CWE", "CVE", "Total Tokens", "Runtime", "LLM Calls", "Cost (CNY)"]

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Phase 1 成功 CVE"
    sheet.append(headers)
    for row in rows:
        sheet.append([row[header] for header in headers])
    style_metrics_sheet(sheet, len(rows))
    add_summary_sheet(workbook, rows, total, excluded)

    workbook.calculation.fullCalcOnLoad = True
    workbook.calculation.forceFullCalc = True
    workbook.save(REPORT_PATH)
    print(f"Created: {REPORT_PATH}")
    print(f"Total={total}, excluded={excluded}, rows={len(rows)}")


if __name__ == "__main__":
    main()
