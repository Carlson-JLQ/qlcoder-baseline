#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["openpyxl>=3.1,<4"]
# ///
"""Generate the Excel summary for failed CVEs in batch 20261103_082810."""

from collections import Counter
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter


OUTPUT = Path(__file__).resolve().parent / "qlcoder_failed_cves.xlsx"

# CWE values are normalized so CWE-94 and CWE-094 are grouped together.
ROWS = [
    ("CWE-079", "CVE-2022-1274", "Phase 1 Agent 执行失败", "Phase 1", "Phase 1 metrics 标记 success=false、return_code=1；后续仅完成 AST 提取，未进入 Query Iteration，也未生成最终 metadata。"),
    ("CWE-094", "CVE-2021-30181", "Phase 1 输入超过 10 MB", "Phase 1", "Phase 1 prompt 为 16.8 MB；stdin 超过后端 10 MB 限制，未发生有效 LLM 调用。"),
    ("CWE-094", "CVE-2023-34468", "Phase 1 输入超过 10 MB", "Phase 1", "Phase 1 prompt 为 13.6 MB；stdin 超过后端 10 MB 限制；随后仍执行了耗时的 Phase 2。"),
    ("CWE-094", "CVE-2025-30067", "Agent 达到 50-turn 上限", "Phase 1", "Phase 1 在 50 个 agent 回合内未完成，终止为 error_max_turns。"),
    ("CWE-200", "CVE-2025-22227", "Agent 达到 50-turn 上限", "Phase 1", "Phase 1 在 50 个 agent 回合内未完成，终止为 error_max_turns。"),
    ("CWE-200", "CVE-2025-54380", "Agent 达到 50-turn 上限", "Phase 1", "Phase 1 在 50 个 agent 回合内未完成，终止为 error_max_turns。"),
    ("CWE-264", "CVE-2014-3576", "Agent 达到 50-turn 上限", "Phase 1", "Phase 1 在 50 个 agent 回合内未完成，终止为 error_max_turns。"),
    ("CWE-276", "CVE-2025-24790", "Agent 达到 50-turn 上限", "Phase 1", "Phase 1 在 50 个 agent 回合内未完成，终止为 error_max_turns。"),
    ("CWE-287", "CVE-2025-3910", "Agent 达到 50-turn 上限", "Phase 1", "Phase 1 在 50 个 agent 回合内未完成，终止为 error_max_turns。"),
    ("CWE-287", "CVE-2023-51982", "10 轮内未成功", "Phase 3", "共执行 10 轮，整体 success=false；仅第 3、6 轮生成并执行查询但未命中目标方法，第 10 轮 Context execution failed。"),
    ("CWE-312", "CVE-2025-53103", "Agent 达到 50-turn 上限", "Phase 1", "Phase 1 在 50 个 agent 回合内未完成，终止为 error_max_turns。"),
    ("CWE-327", "CVE-2025-27508", "10 轮内未命中目标方法", "Phase 3", "Vulnerable 有 2/4 个结果、Fixed 为 0，文件覆盖 1/1，但方法覆盖 0/1；部分迭代达到 50-turn 上限，最后一轮编译失败。"),
    ("CWE-346", "CVE-2025-7365", "Agent 达到 50-turn 上限", "Phase 1", "Phase 1 在 50 个 agent 回合内未完成，终止为 error_max_turns。"),
    ("CWE-426", "CVE-2025-24789", "10 轮内未命中目标方法", "Phase 3", "Vulnerable 有 1 个结果、Fixed 为 0，文件覆盖 1/1，但方法覆盖 0/2；实际命中内部类方法，与目标方法键不一致。"),
    ("CWE-862", "CVE-2025-31720", "Agent 达到 50-turn 上限", "Phase 1", "Phase 1 在 50 个 agent 回合内未完成，终止为 error_max_turns。"),
    ("CWE-862", "CVE-2025-31721", "Agent 达到 50-turn 上限", "Phase 1", "Phase 1 在 50 个 agent 回合内未完成，终止为 error_max_turns。"),
    ("CWE-918", "CVE-2023-51441", "Agent 达到 50-turn 上限", "Phase 1", "Phase 1 在 50 个 agent 回合内未完成，终止为 error_max_turns。"),
    ("CWE-918", "CVE-2024-48944", "Agent 达到 50-turn 上限", "Phase 1", "Phase 1 在 50 个 agent 回合内未完成，终止为 error_max_turns。"),
]


def cwe_key(row):
    return (int(row[0].split("-")[1]), row[1])


def style_sheet(sheet, widths=None):
    header_fill = PatternFill("solid", fgColor="4472C4")
    for cell in sheet[1]:
        cell.fill = header_fill
        cell.font = Font(color="FFFFFF", bold=True)
        cell.alignment = Alignment(horizontal="center", vertical="center")
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions
    for row in sheet.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)
    if widths:
        for index, width in enumerate(widths, start=1):
            sheet.column_dimensions[get_column_letter(index)].width = width


def main():
    rows = sorted(ROWS, key=cwe_key)
    wb = Workbook()

    details = wb.active
    details.title = "失败 CVE 明细"
    details.append(["CWE", "CVE", "失败类型", "失败阶段", "详细说明"])
    for row in rows:
        details.append(row)
    style_sheet(details, [13, 20, 27, 14, 86])
    for row in range(2, details.max_row + 1):
        details.row_dimensions[row].height = 34

    type_summary = wb.create_sheet("失败类型汇总")
    type_summary.append(["失败类型", "CVE Count"])
    for failure_type, count in Counter(row[2] for row in rows).most_common():
        type_summary.append([failure_type, count])
    style_sheet(type_summary, [32, 15])

    cwe_summary = wb.create_sheet("CWE 汇总")
    cwe_summary.append(["CWE", "失败 CVE Count"])
    counts = Counter(row[0] for row in rows)
    for cwe in sorted(counts, key=lambda value: int(value.split("-")[1])):
        cwe_summary.append([cwe, counts[cwe]])
    style_sheet(cwe_summary, [15, 20])

    wb.save(OUTPUT)
    print(f"Created: {OUTPUT}")
    print(f"Rows: {len(rows)}")


if __name__ == "__main__":
    main()
