#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["openpyxl>=3.1,<4", "matplotlib>=3.8,<4"]
# ///
"""Compare AutoQL analysis and QLCoder Phase 1 on their common successful CVEs."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from openpyxl import Workbook, load_workbook
from openpyxl.comments import Comment
from openpyxl.drawing.image import Image
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.worksheet.table import Table, TableStyleInfo


HERE = Path(__file__).resolve().parent
AUTOQL_PATH = HERE / "autoql_analysis_success_metrics.xlsx"
QLCODER_PATH = HERE / "phase1_successful_cve_metrics.xlsx"
REPORT_PATH = HERE / "autoql_vs_qlcoder_analysis_comparison.xlsx"
CHART_DIR = HERE / "autoql_vs_qlcoder_charts"

AUTO_COLOR = "#4C78A8"
QL_COLOR = "#F58518"


def seconds(value) -> float:
    if isinstance(value, timedelta):
        return value.total_seconds()
    return float(value)


def load_data() -> tuple[dict[str, dict], dict[str, dict], list[str], list[str]]:
    auto_wb = load_workbook(AUTOQL_PATH, read_only=True, data_only=True)
    ql_wb = load_workbook(QLCODER_PATH, read_only=True, data_only=True)

    auto: dict[str, dict] = {}
    auto_order: list[str] = []
    for row in auto_wb["成功CVE指标"].iter_rows(min_row=2, values_only=True):
        cve = row[1]
        if not cve:
            continue
        auto_order.append(cve)
        auto[cve] = {
            "CWE": row[2],
            "Total Tokens": int(row[5]),
            "Runtime (seconds)": float(row[10]),
            "LLM Calls": int(row[12]),
            "Cost (CNY)": float(row[13]),
        }

    ql: dict[str, dict] = {}
    ql_order: list[str] = []
    for row in ql_wb["Phase 1 成功 CVE"].iter_rows(min_row=2, values_only=True):
        cve = row[1]
        if not cve:
            continue
        ql_order.append(cve)
        ql[cve] = {
            "CWE": row[0],
            "Total Tokens": int(row[2]),
            "Runtime (seconds)": seconds(row[3]),
            "LLM Calls": int(row[4]),
            "Cost (CNY)": float(row[5]),
        }

    auto_wb.close()
    ql_wb.close()
    return auto, ql, auto_order, ql_order


def collect_rows(auto: dict[str, dict], ql: dict[str, dict], ql_order: list[str]) -> list[dict]:
    common = [cve for cve in ql_order if cve in auto]
    rows: list[dict] = []
    for cve in common:
        a = auto[cve]
        q = ql[cve]
        if a["CWE"] != q["CWE"]:
            raise ValueError(f"CWE mismatch for {cve}: AutoQL={a['CWE']}, QLCoder={q['CWE']}")
        row = {"CWE": q["CWE"], "CVE": cve}
        for metric in ("Total Tokens", "Runtime (seconds)", "LLM Calls", "Cost (CNY)"):
            row[f"AutoQL {metric}"] = a[metric]
            row[f"QLCoder {metric}"] = q[metric]
            row[f"QLCoder/AutoQL {metric}"] = q[metric] / a[metric]
        rows.append(row)
    return rows


def configure_plot() -> None:
    plt.rcParams.update(
        {
            "font.size": 10,
            "axes.titlesize": 14,
            "axes.labelsize": 11,
            "legend.fontsize": 10,
            "figure.dpi": 150,
        }
    )


def grouped_horizontal_chart(
    rows: list[dict], metric: str, title: str, filename: str, *, log_scale: bool = False
) -> Path:
    labels = [row["CVE"] for row in rows]
    auto_values = [row[f"AutoQL {metric}"] for row in rows]
    ql_values = [row[f"QLCoder {metric}"] for row in rows]
    y = np.arange(len(labels))
    height = 0.36

    fig, ax = plt.subplots(figsize=(12, 7.2))
    ax.barh(y - height / 2, auto_values, height, label="AutoQL Analysis", color=AUTO_COLOR)
    ax.barh(y + height / 2, ql_values, height, label="QLCoder Phase 1", color=QL_COLOR)
    ax.set_yticks(y, labels)
    ax.invert_yaxis()
    ax.set_title(title)
    ax.set_xlabel(metric)
    if log_scale:
        ax.set_xscale("log")
        ax.set_xlabel(f"{metric} (log scale)")
    ax.grid(axis="x", linestyle="--", alpha=0.35)
    ax.legend(loc="lower right")
    fig.tight_layout()
    path = CHART_DIR / filename
    fig.savefig(path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    return path


def ratio_chart(rows: list[dict]) -> Path:
    metrics = ["Total Tokens", "Runtime (seconds)", "LLM Calls", "Cost (CNY)"]
    ratios = []
    for metric in metrics:
        auto_total = sum(row[f"AutoQL {metric}"] for row in rows)
        ql_total = sum(row[f"QLCoder {metric}"] for row in rows)
        ratios.append(ql_total / auto_total)

    fig, ax = plt.subplots(figsize=(9, 5.2))
    bars = ax.bar(metrics, ratios, color=[AUTO_COLOR, "#72B7B2", "#54A24B", QL_COLOR])
    ax.axhline(1.0, color="#555555", linestyle="--", linewidth=1)
    ax.set_ylabel("QLCoder / AutoQL ratio")
    ax.set_title("Aggregate Efficiency Ratio on Common CVEs")
    ax.grid(axis="y", linestyle="--", alpha=0.35)
    for bar, value in zip(bars, ratios):
        ax.text(bar.get_x() + bar.get_width() / 2, value, f"{value:.2f}x", ha="center", va="bottom")
    fig.tight_layout()
    path = CHART_DIR / "aggregate_ratio.png"
    fig.savefig(path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    return path


def create_charts(rows: list[dict]) -> list[Path]:
    CHART_DIR.mkdir(parents=True, exist_ok=True)
    configure_plot()
    charts = [
        grouped_horizontal_chart(
            rows,
            "Total Tokens",
            "Total Tokens by CVE",
            "total_tokens_comparison.png",
            log_scale=True,
        ),
        grouped_horizontal_chart(
            rows,
            "Runtime (seconds)",
            "Analysis Runtime by CVE",
            "runtime_comparison.png",
        ),
        grouped_horizontal_chart(
            rows,
            "LLM Calls",
            "LLM Calls by CVE",
            "llm_calls_comparison.png",
        ),
        grouped_horizontal_chart(
            rows,
            "Cost (CNY)",
            "Analysis Cost by CVE",
            "cost_comparison.png",
        ),
        ratio_chart(rows),
    ]
    return charts


def style_header(sheet, max_column: int) -> None:
    for row in sheet.iter_rows(min_row=1, max_row=1, max_col=max_column):
        for cell in row:
            cell.fill = PatternFill("solid", fgColor="1F4E78")
            cell.font = Font(color="FFFFFF", bold=True)
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)


def add_comparison_sheet(workbook: Workbook, rows: list[dict]) -> None:
    sheet = workbook.active
    sheet.title = "共同CVE逐项对比"
    headers = [
        "CWE",
        "CVE",
        "AutoQL Total Tokens",
        "QLCoder Total Tokens",
        "Tokens Ratio (QL/A)",
        "AutoQL Runtime (s)",
        "QLCoder Runtime (s)",
        "Runtime Ratio (QL/A)",
        "AutoQL LLM Calls",
        "QLCoder LLM Calls",
        "Calls Ratio (QL/A)",
        "AutoQL Cost (CNY)",
        "QLCoder Cost (CNY)",
        "Cost Ratio (QL/A)",
    ]
    sheet.append(headers)
    for row in rows:
        sheet.append(
            [
                row["CWE"],
                row["CVE"],
                row["AutoQL Total Tokens"],
                row["QLCoder Total Tokens"],
                row["QLCoder/AutoQL Total Tokens"],
                row["AutoQL Runtime (seconds)"],
                row["QLCoder Runtime (seconds)"],
                row["QLCoder/AutoQL Runtime (seconds)"],
                row["AutoQL LLM Calls"],
                row["QLCoder LLM Calls"],
                row["QLCoder/AutoQL LLM Calls"],
                row["AutoQL Cost (CNY)"],
                row["QLCoder Cost (CNY)"],
                row["QLCoder/AutoQL Cost (CNY)"],
            ]
        )

    style_header(sheet, len(headers))
    sheet.freeze_panes = "A2"
    sheet.sheet_view.showGridLines = False
    sheet.auto_filter.ref = f"A1:N{len(rows) + 1}"
    sheet.row_dimensions[1].height = 42
    widths = [12, 20, 19, 20, 18, 19, 20, 19, 18, 19, 17, 19, 20, 17]
    for index, width in enumerate(widths, start=1):
        sheet.column_dimensions[chr(64 + index)].width = width

    grid = Side(style="thin", color="D9E2F3")
    for row_cells in sheet.iter_rows(min_row=2, max_row=len(rows) + 1):
        for cell in row_cells:
            cell.border = Border(bottom=grid)
            cell.alignment = Alignment(horizontal="center", vertical="center")
        if row_cells[0].row % 2 == 1:
            for cell in row_cells:
                cell.fill = PatternFill("solid", fgColor="D9EAF7")

    for column in ("C", "D", "I", "J"):
        for cell in sheet[column][1:]:
            cell.number_format = "#,##0"
    for column in ("F", "G"):
        for cell in sheet[column][1:]:
            cell.number_format = "0.000"
    for column in ("E", "H", "K", "N"):
        for cell in sheet[column][1:]:
            cell.number_format = "0.00x"
    for column in ("L", "M"):
        for cell in sheet[column][1:]:
            cell.number_format = "¥0.000000"

    table = Table(displayName="AutoQLQLCoderCommonComparison", ref=f"A1:N{len(rows) + 1}")
    table.tableStyleInfo = TableStyleInfo(name="TableStyleMedium2", showRowStripes=False)
    sheet.add_table(table)
    sheet["E1"].comment = Comment("QLCoder / AutoQL；大于 1 表示 QLCoder 消耗更多。", "Codex")


def add_summary_sheet(workbook: Workbook, rows: list[dict]) -> None:
    sheet = workbook.create_sheet("汇总对比")
    headers = [
        "Metric",
        "AutoQL Total",
        "QLCoder Total",
        "QLCoder/AutoQL",
        "AutoQL Reduction vs QLCoder",
        "AutoQL Average",
        "QLCoder Average",
    ]
    sheet.append(headers)
    metrics = ["Total Tokens", "Runtime (seconds)", "LLM Calls", "Cost (CNY)"]
    for metric in metrics:
        auto_total = sum(row[f"AutoQL {metric}"] for row in rows)
        ql_total = sum(row[f"QLCoder {metric}"] for row in rows)
        ratio = ql_total / auto_total
        reduction = 1 - auto_total / ql_total
        sheet.append(
            [metric, auto_total, ql_total, ratio, reduction, auto_total / len(rows), ql_total / len(rows)]
        )

    style_header(sheet, len(headers))
    sheet.freeze_panes = "A2"
    sheet.sheet_view.showGridLines = False
    widths = [23, 20, 20, 20, 28, 20, 20]
    for index, width in enumerate(widths, start=1):
        sheet.column_dimensions[chr(64 + index)].width = width
    for row in sheet.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(horizontal="center", vertical="center")
    for cell in sheet["D"][1:]:
        cell.number_format = "0.00x"
    for cell in sheet["E"][1:]:
        cell.number_format = "0.0%"
    for row_index in (2, 4):
        for column in ("B", "C", "F", "G"):
            sheet[f"{column}{row_index}"].number_format = "#,##0.00"
    for row_index in (3, 5):
        for column in ("B", "C", "F", "G"):
            sheet[f"{column}{row_index}"].number_format = "0.000000"

    table = Table(displayName="AggregateComparison", ref="A1:G5")
    table.tableStyleInfo = TableStyleInfo(name="TableStyleMedium2", showRowStripes=True)
    sheet.add_table(table)


def add_set_difference_sheet(
    workbook: Workbook,
    auto: dict[str, dict],
    ql: dict[str, dict],
    auto_order: list[str],
    ql_order: list[str],
) -> None:
    sheet = workbook.create_sheet("CVE集合差异")
    sheet.append(["集合", "CVE", "CWE", "说明"])
    common = set(auto) & set(ql)
    for cve in [item for item in ql_order if item in common]:
        sheet.append(["共同成功", cve, ql[cve]["CWE"], "纳入主表和图表"])
    for cve in [item for item in auto_order if item not in ql]:
        sheet.append(["仅AutoQL成功表", cve, auto[cve]["CWE"], "未纳入配对比较"])
    for cve in [item for item in ql_order if item not in auto]:
        sheet.append(["仅QLCoder成功表", cve, ql[cve]["CWE"], "未纳入配对比较"])

    style_header(sheet, 4)
    sheet.freeze_panes = "A2"
    sheet.sheet_view.showGridLines = False
    sheet.auto_filter.ref = sheet.dimensions
    for column, width in zip(("A", "B", "C", "D"), (22, 20, 13, 28)):
        sheet.column_dimensions[column].width = width
    for row in sheet.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(horizontal="center", vertical="center")


def add_notes_sheet(workbook: Workbook, common_count: int, auto_count: int, ql_count: int) -> None:
    sheet = workbook.create_sheet("口径说明")
    sheet.append(["项目", "说明"])
    notes = [
        ("主比较样本", f"两份成功表的交集，共 {common_count} 个 CVE。"),
        ("AutoQL 成功表", f"{auto_count} 个 CVE。"),
        ("QLCoder 成功表", f"{ql_count} 个 CVE。"),
        ("Total Tokens", "直接使用两份源表的 Total Tokens。AutoQL 中 cached token 已包含在 input token，不重复相加；QLCoder cache read 单列计费并已包含在其 Total Tokens。"),
        ("Runtime", "AutoQL 使用 analysis stage runtime；QLCoder 使用 Phase 1 duration_ms。两者均转为秒。"),
        ("LLM Calls", "AutoQL 使用 physical_requests；QLCoder 源表使用 num_turns 作为模型调用轮次代理。该列适合趋势比较，但不是完全相同的底层遥测口径。"),
        ("Cost", "两份源表均按 CNY 使用，不做汇率换算。"),
        ("Ratio", "QLCoder / AutoQL；大于 1 表示 QLCoder 的该项消耗更高。"),
        ("Tokens 图", "采用对数横轴，避免两种方法数量级差异导致 AutoQL 柱不可见。"),
    ]
    for row in notes:
        sheet.append(row)
    style_header(sheet, 2)
    sheet.freeze_panes = "A2"
    sheet.sheet_view.showGridLines = False
    sheet.column_dimensions["A"].width = 24
    sheet.column_dimensions["B"].width = 110
    for row in sheet.iter_rows(min_row=2):
        row[0].font = Font(bold=True, color="1F4E78")
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)


def add_chart_sheet(workbook: Workbook, charts: list[Path]) -> None:
    sheet = workbook.create_sheet("图表")
    sheet.sheet_view.showGridLines = False
    sheet.column_dimensions["A"].width = 2
    positions = ["B2", "B40", "B78", "B116", "B154"]
    for path, position in zip(charts, positions):
        image = Image(path)
        image.width = 960
        image.height = 576 if "aggregate" not in path.name else 500
        sheet.add_image(image, position)


def main() -> None:
    auto, ql, auto_order, ql_order = load_data()
    rows = collect_rows(auto, ql, ql_order)
    if not rows:
        raise ValueError("The two workbooks have no common CVEs")

    charts = create_charts(rows)
    workbook = Workbook()
    add_comparison_sheet(workbook, rows)
    add_summary_sheet(workbook, rows)
    add_set_difference_sheet(workbook, auto, ql, auto_order, ql_order)
    add_notes_sheet(workbook, len(rows), len(auto), len(ql))
    add_chart_sheet(workbook, charts)
    workbook.calculation.fullCalcOnLoad = True
    workbook.calculation.forceFullCalc = True
    workbook.save(REPORT_PATH)

    print(f"Created: {REPORT_PATH}")
    print(f"Common CVEs: {len(rows)}; AutoQL: {len(auto)}; QLCoder: {len(ql)}")
    for path in charts:
        print(f"Chart: {path}")


if __name__ == "__main__":
    main()
