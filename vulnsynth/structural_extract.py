#!/usr/bin/env python3

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

try:
    import tree_sitter_ql as tsql
    from tree_sitter import Language, Parser
except ImportError:  # pragma: no cover - handled at runtime
    tsql = None
    Language = None
    Parser = None

def resolve_default_codeql_path() -> str:
    codeql_home = os.environ.get("CODEQL_HOME", "/path/to/codeql")
    fallback = os.environ.get("CODEQL_PATH", f"{codeql_home}/codeql")

    try:
        from .config import CODEQL_PATH as configured_codeql_path

        return configured_codeql_path
    except Exception:
        pass

    try:
        from config import CODEQL_PATH as configured_codeql_path

        return configured_codeql_path
    except Exception:
        return fallback


CODEQL_PATH = resolve_default_codeql_path()


LOGGER = logging.getLogger(__name__)

MODULE_CONFIG_RE = re.compile(
    r"\bmodule\s+(?P<name>[A-Za-z_]\w*)\s+implements\s+(?P<sig>[A-Za-z0-9_:]+)"
)
CLASS_CONFIG_RE = re.compile(
    r"\bclass\s+(?P<name>[A-Za-z_]\w*)\s+extends\s+(?P<sig>[A-Za-z0-9_:]+)"
)
PREDICATE_HEAD_RE = re.compile(
    r"(?m)^[ \t]*(?:(?:private|cached|override|final|deprecated)\s+)*predicate\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*\("
)

ROLE_NAME_TO_KIND = {
    "isSource": "source",
    "isSink": "sink",
    "isBarrier": "barrier",
    "isSanitizer": "barrier",
    "isAdditionalFlowStep": "flow",
}

ROLE_DEFAULT_QUERY_KIND = {
    "source": "problem",
    "sink": "problem",
    "barrier": "table",
    "flow": "table",
}
PROBE_KIND_MODES = ("hybrid", "all-table", "all-problem")


def resolve_repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def ensure_output_qlpack(output_dir: Path) -> None:
    qlpack_source = resolve_repo_root() / "qlpack.yml"
    if qlpack_source.exists():
        shutil.copy2(qlpack_source, output_dir / "qlpack.yml")


@dataclass
class ParseErrorInfo:
    node_type: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    snippet: str


@dataclass
class ParameterInfo:
    raw_text: str
    type_text: str
    name: str


@dataclass
class PredicateInfo:
    name: str
    role: str
    parameters: list[ParameterInfo]
    full_text: str
    body_text: str
    start_line: int
    end_line: int


@dataclass
class ConfigInfo:
    style: str
    name: str
    signature: str
    full_text: str
    start_line: int
    end_line: int
    predicates: list[PredicateInfo] = field(default_factory=list)


@dataclass
class GeneratedComponent:
    role: str
    source_predicate: str
    output_path: str
    generation_mode: str
    query_kind: str
    success: Optional[bool] = None
    return_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""


def require_tree_sitter() -> tuple[Any, Any]:
    if tsql is None or Language is None or Parser is None:
        raise RuntimeError(
            "Missing dependencies: tree_sitter and tree_sitter_ql are required. "
            "Please run this script inside the environment that has them installed."
        )

    language = Language(tsql.language())
    parser = Parser(language)
    return language, parser


def read_query_input(query_path: Optional[Path], query_text: Optional[str]) -> tuple[str, str]:
    if query_path is None and query_text is None:
        raise ValueError("Either query_path or query_text must be provided.")

    if query_path is not None:
        return query_path.read_text(encoding="utf-8"), query_path.stem

    assert query_text is not None
    return query_text, "inline-query"


def get_node_text(node: Any, source: str) -> str:
    return source[node.start_byte:node.end_byte]


def iter_named_nodes(node: Any) -> Iterable[Any]:
    yield node
    for child in getattr(node, "named_children", []):
        yield from iter_named_nodes(child)


def collect_parse_errors(root: Any, source: str) -> list[ParseErrorInfo]:
    errors: list[ParseErrorInfo] = []
    for node in iter_named_nodes(root):
        if node.type != "ERROR":
            continue
        snippet = get_node_text(node, source).strip().splitlines()
        errors.append(
            ParseErrorInfo(
                node_type=node.type,
                start_line=node.start_point.row + 1,
                start_column=node.start_point.column + 1,
                end_line=node.end_point.row + 1,
                end_column=node.end_point.column + 1,
                snippet=snippet[0][:200] if snippet else "",
            )
        )
    return errors


def split_top_level(text: str, delimiter: str = ",") -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    paren = 0
    bracket = 0
    brace = 0
    angle = 0
    in_string = False
    string_char = ""
    escaped = False

    for char in text:
        if in_string:
            current.append(char)
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
            elif char == string_char:
                in_string = False
            continue

        if char in {"'", '"'}:
            current.append(char)
            in_string = True
            string_char = char
            continue

        if char == "(":
            paren += 1
        elif char == ")":
            paren = max(0, paren - 1)
        elif char == "[":
            bracket += 1
        elif char == "]":
            bracket = max(0, bracket - 1)
        elif char == "{":
            brace += 1
        elif char == "}":
            brace = max(0, brace - 1)
        elif char == "<":
            angle += 1
        elif char == ">":
            angle = max(0, angle - 1)

        if (
            char == delimiter
            and paren == 0
            and bracket == 0
            and brace == 0
            and angle == 0
        ):
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue

        current.append(char)

    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def parse_parameters(parameter_text: str) -> list[ParameterInfo]:
    parameters: list[ParameterInfo] = []
    for raw_param in split_top_level(parameter_text):
        match = re.match(r"(?P<type>.+?)\s+(?P<name>[A-Za-z_]\w*)$", raw_param.strip())
        if match:
            parameters.append(
                ParameterInfo(
                    raw_text=raw_param.strip(),
                    type_text=match.group("type").strip(),
                    name=match.group("name").strip(),
                )
            )
        else:
            fallback_name = f"arg{len(parameters) + 1}"
            parameters.append(
                ParameterInfo(
                    raw_text=raw_param.strip(),
                    type_text="",
                    name=fallback_name,
                )
            )
    return parameters


def find_matching_delimiter(text: str, start_index: int, opening: str, closing: str) -> int:
    depth = 0
    i = start_index
    in_string = False
    string_char = ""
    escaped = False

    while i < len(text):
        char = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == string_char:
                in_string = False
            i += 1
            continue

        if char == "/" and nxt == "/":
            i += 2
            while i < len(text) and text[i] != "\n":
                i += 1
            continue

        if char == "/" and nxt == "*":
            i += 2
            while i + 1 < len(text) and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue

        if char in {"'", '"'}:
            in_string = True
            string_char = char
            i += 1
            continue

        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return i
        i += 1

    raise ValueError(f"Could not find matching {closing!r} for index {start_index}.")


def extract_predicates_from_config_text(config_text: str, base_line: int) -> list[PredicateInfo]:
    predicates: list[PredicateInfo] = []
    for match in PREDICATE_HEAD_RE.finditer(config_text):
        name = match.group("name")
        paren_index = config_text.find("(", match.end() - 1)
        if paren_index < 0:
            continue
        paren_end = find_matching_delimiter(config_text, paren_index, "(", ")")
        body_open = config_text.find("{", paren_end)
        if body_open < 0:
            continue
        body_close = find_matching_delimiter(config_text, body_open, "{", "}")
        full_text = config_text[match.start():body_close + 1].strip()
        body_text = config_text[body_open + 1:body_close].strip()
        parameter_text = config_text[paren_index + 1:paren_end].strip()
        start_line = base_line + config_text[:match.start()].count("\n")
        end_line = base_line + config_text[:body_close].count("\n")
        predicates.append(
            PredicateInfo(
                name=name,
                role=ROLE_NAME_TO_KIND.get(name, "helper"),
                parameters=parse_parameters(parameter_text),
                full_text=full_text,
                body_text=body_text,
                start_line=start_line,
                end_line=end_line,
            )
        )
    return predicates


def classify_top_level_member(text: str, config_name: Optional[str]) -> str:
    stripped = text.strip()
    if not stripped:
        return "empty"
    if stripped.startswith("/**") or stripped.startswith("/*"):
        return "doc"
    if stripped.startswith("import "):
        return "import"
    if re.match(r"^from(?:\s|\n|$)", stripped):
        return "query"
    if MODULE_CONFIG_RE.search(stripped):
        return "config_module"
    class_match = CLASS_CONFIG_RE.search(stripped)
    if class_match and class_match.group("sig").endswith("Configuration"):
        return "config_class"
    if stripped.startswith("module ") and "=" in stripped.splitlines()[0]:
        if config_name and config_name in stripped:
            return "flow_alias"
        return "module_alias"
    return "support"


def find_config(root: Any, source: str) -> ConfigInfo:
    for member in getattr(root, "named_children", []):
        member_text = get_node_text(member, source)
        inner = member.named_children[0] if getattr(member, "named_children", None) else member

        module_match = MODULE_CONFIG_RE.search(member_text)
        if inner.type == "module" and module_match and module_match.group("sig").endswith("ConfigSig"):
            predicates = extract_predicates_from_config_text(
                member_text,
                member.start_point.row + 1,
            )
            return ConfigInfo(
                style="configsig_module",
                name=module_match.group("name"),
                signature=module_match.group("sig"),
                full_text=member_text,
                start_line=member.start_point.row + 1,
                end_line=member.end_point.row + 1,
                predicates=predicates,
            )

        class_match = CLASS_CONFIG_RE.search(member_text)
        if inner.type == "dataclass" and class_match and class_match.group("sig").endswith("Configuration"):
            predicates = extract_predicates_from_config_text(
                member_text,
                member.start_point.row + 1,
            )
            return ConfigInfo(
                style="configuration_class",
                name=class_match.group("name"),
                signature=class_match.group("sig"),
                full_text=member_text,
                start_line=member.start_point.row + 1,
                end_line=member.end_point.row + 1,
                predicates=predicates,
            )

    raise ValueError("Could not locate a supported CodeQL dataflow configuration block.")


def collect_top_level_texts(root: Any, source: str, config_name: Optional[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {
        "doc": [],
        "import": [],
        "support": [],
        "query": [],
        "flow_alias": [],
        "config_module": [],
        "config_class": [],
        "module_alias": [],
    }

    for member in getattr(root, "named_children", []):
        text = get_node_text(member, source).rstrip()
        kind = classify_top_level_member(text, config_name)
        grouped.setdefault(kind, []).append(text)

    return grouped


def sanitize_id_fragment(text: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()
    return value or "query"


def resolve_query_kind(role: str, probe_kind_mode: str) -> str:
    if probe_kind_mode == "hybrid":
        return ROLE_DEFAULT_QUERY_KIND[role]
    if probe_kind_mode == "all-table":
        return "table"
    if probe_kind_mode == "all-problem":
        return "problem"
    raise ValueError(f"Unsupported probe_kind_mode: {probe_kind_mode}")


def generate_probe_query(
    role: str,
    query_id_base: str,
    imports: list[str],
    support_blocks: list[str],
    predicate_text: str,
    parameter_names: list[str],
    parameter_types: list[str],
    query_kind: str,
) -> str:
    probe_predicate_name = {
        "source": "sourceProbe",
        "sink": "sinkProbe",
        "barrier": "barrierProbe",
        "flow": "additionalFlowStepProbe",
    }[role]

    id_suffix = {
        "source": "source-probe",
        "sink": "sink-probe",
        "barrier": "barrier-probe",
        "flow": "flow-probe",
    }[role]

    query_name = {
        "source": "Debug Source Probe",
        "sink": "Debug Sink Probe",
        "barrier": "Debug Barrier Probe",
        "flow": "Debug Additional Flow Probe",
    }[role]

    description = {
        "source": "Probes which nodes are recognized as sources by the query.",
        "sink": "Probes which nodes are recognized as sinks by the query.",
        "barrier": "Probes which nodes are recognized as barriers by the query.",
        "flow": "Probes which node pairs are recognized as additional flow steps by the query.",
    }[role]

    select_clause = ""
    if role == "flow":
        if query_kind == "problem":
            select_clause = (
                f"from {parameter_types[0]} {parameter_names[0]}, {parameter_types[1]} {parameter_names[1]}\n"
                f"where {probe_predicate_name}({parameter_names[0]}, {parameter_names[1]})\n"
                f'select {parameter_names[0]}, "FLOWSTEP matched by {probe_predicate_name}"'
            )
        else:
            select_clause = (
                f"from {parameter_types[0]} {parameter_names[0]}, {parameter_types[1]} {parameter_names[1]}\n"
                f"where {probe_predicate_name}({parameter_names[0]}, {parameter_names[1]})\n"
                f'select {parameter_names[0]}, {parameter_names[1]}, "FLOWSTEP matched by {probe_predicate_name}"'
            )
    else:
        select_clause = (
            f"from {parameter_types[0]} {parameter_names[0]}\n"
            f"where {probe_predicate_name}({parameter_names[0]})\n"
            f'select {parameter_names[0]}, "{role.upper()} matched by {probe_predicate_name}"'
        )

    metadata_lines = [
        "/**",
        f" * @name {query_name}",
        f" * @description {description}",
        f" * @kind {query_kind}",
        f" * @id debug/{query_id_base}/{id_suffix}",
    ]
    if query_kind == "problem":
        metadata_lines.extend(
            [
                " * @problem.severity warning",
                " * @precision low",
            ]
        )
    metadata_lines.append(" */")

    blocks: list[str] = [
        "\n".join(metadata_lines),
        "",
        "\n".join(imports).strip(),
    ]

    if support_blocks:
        blocks.extend(["", "\n\n".join(block.strip() for block in support_blocks if block.strip())])

    blocks.extend(["", predicate_text.strip(), "", select_clause, ""])
    return "\n".join(block for block in blocks if block is not None)


def build_component_query(
    role: str,
    query_id_base: str,
    config: ConfigInfo,
    grouped_toplevel: dict[str, list[str]],
    role_predicate: PredicateInfo,
    probe_kind_mode: str,
) -> tuple[str, str, str]:
    imports = [
        item for item in grouped_toplevel.get("import", [])
        if "::PathGraph" not in item
    ]
    support_blocks = list(grouped_toplevel.get("support", []))
    support_blocks.extend(grouped_toplevel.get("module_alias", []))

    parameter_names = [param.name for param in role_predicate.parameters]
    parameter_types = [
        param.type_text if param.type_text else "DataFlow::Node"
        for param in role_predicate.parameters
    ]

    if config.style == "configuration_class":
        support_blocks.append(config.full_text.strip())
        invocation = ", ".join(parameter_names)
        predicate_text = (
            f"predicate {role}Probe({', '.join(param.raw_text for param in role_predicate.parameters)}) {{\n"
            f"  exists({config.name} cfg | cfg.{role_predicate.name}({invocation}))\n"
            f"}}"
        )
        generation_mode = "delegated_config_call"
    else:
        helper_predicates = [
            predicate.full_text
            for predicate in config.predicates
            if predicate.role == "helper"
        ]
        support_blocks.extend(helper_predicates)
        predicate_name = {
            "source": "sourceProbe",
            "sink": "sinkProbe",
            "barrier": "barrierProbe",
            "flow": "additionalFlowStepProbe",
        }[role]
        predicate_text = (
            f"predicate {predicate_name}({', '.join(param.raw_text for param in role_predicate.parameters)}) {{\n"
            f"{indent_block(role_predicate.body_text, prefix='  ')}\n"
            f"}}"
        )
        generation_mode = "lifted_predicate_body"

    query_kind = resolve_query_kind(role, probe_kind_mode)
    component_query = generate_probe_query(
        role=role,
        query_id_base=query_id_base,
        imports=imports,
        support_blocks=dedupe_preserve_order(support_blocks),
        predicate_text=predicate_text,
        parameter_names=parameter_names,
        parameter_types=parameter_types,
        query_kind=query_kind,
    )
    return component_query, generation_mode, query_kind


def indent_block(text: str, prefix: str = "  ") -> str:
    lines = text.splitlines() or [text]
    return "\n".join(f"{prefix}{line}" if line else prefix.rstrip() for line in lines)


def dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        normalized = item.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(item)
    return result


def compile_query(query_path: Path, codeql_path: str) -> tuple[bool, int, str, str]:
    query_path = query_path.resolve()
    completed = subprocess.run(
        [codeql_path, "query", "compile", str(query_path)],
        cwd=str(query_path.parent),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return (
        completed.returncode == 0,
        completed.returncode,
        completed.stdout,
        completed.stderr,
    )


def build_markdown_summary(
    report: dict[str, Any],
    generated_components: list[GeneratedComponent],
) -> str:
    lines = [
        "# Structural Extract Summary",
        "",
        f"- Query: `{report['query_label']}`",
        f"- Config style: `{report['config']['style']}`",
        f"- Config name: `{report['config']['name']}`",
        f"- Parse errors: `{len(report['parse_errors'])}`",
        f"- Components generated: `{len(generated_components)}`",
        "",
        "## Components",
        "",
    ]

    for component in generated_components:
        status = "success" if component.success else "failed"
        lines.extend(
            [
                f"- `{component.role}` via `{component.source_predicate}`: `{status}`",
                f"  - file: `{component.output_path}`",
                f"  - mode: `{component.generation_mode}`",
                f"  - kind: `{component.query_kind}`",
            ]
        )
        if component.stderr.strip():
            lines.append("  - stderr:")
            lines.append("```text")
            lines.append(component.stderr.strip())
            lines.append("```")

    if report["parse_errors"]:
        lines.extend(["", "## Parse Errors", ""])
        for error in report["parse_errors"]:
            lines.append(
                f"- `{error['start_line']}:{error['start_column']}` `{error['snippet']}`"
            )

    return "\n".join(lines) + "\n"


def extract_and_compile_components(
    *,
    query_path: Optional[Path] = None,
    query_text: Optional[str] = None,
    output_dir: Optional[Path] = None,
    codeql_path: str = CODEQL_PATH,
    compile_components: bool = True,
    probe_kind_mode: str = "hybrid",
) -> dict[str, Any]:
    if probe_kind_mode not in PROBE_KIND_MODES:
        raise ValueError(
            f"Unsupported probe_kind_mode: {probe_kind_mode}. "
            f"Expected one of {', '.join(PROBE_KIND_MODES)}."
        )

    _, parser = require_tree_sitter()
    source, query_label = read_query_input(query_path, query_text)
    tree = parser.parse(source.encode("utf-8"))
    root = tree.root_node
    parse_errors = collect_parse_errors(root, source)

    config = find_config(root, source)
    grouped_toplevel = collect_top_level_texts(root, source, config.name)

    if output_dir is None:
        if query_path is not None:
            output_dir = query_path.parent / f"{query_path.stem}-structural-extract"
        else:
            output_dir = Path.cwd() / f"{query_label}-structural-extract"
    output_dir.mkdir(parents=True, exist_ok=True)
    ensure_output_qlpack(output_dir)

    query_id_base = sanitize_id_fragment(query_label)

    generated_components: list[GeneratedComponent] = []
    for role in ("source", "sink", "barrier", "flow"):
        role_predicate = next(
            (predicate for predicate in config.predicates if predicate.role == role),
            None,
        )
        if role_predicate is None:
            continue

        component_query, generation_mode, query_kind = build_component_query(
            role=role,
            query_id_base=query_id_base,
            config=config,
            grouped_toplevel=grouped_toplevel,
            role_predicate=role_predicate,
            probe_kind_mode=probe_kind_mode,
        )
        component_path = output_dir / f"{role}_probe.ql"
        component_path.write_text(component_query, encoding="utf-8")

        generated = GeneratedComponent(
            role=role,
            source_predicate=role_predicate.name,
            output_path=str(component_path),
            generation_mode=generation_mode,
            query_kind=query_kind,
        )
        generated_components.append(generated)

    if compile_components and generated_components:
        max_workers = min(4, len(generated_components))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_component = {
                executor.submit(compile_query, Path(component.output_path), codeql_path): component
                for component in generated_components
            }
            for future in as_completed(future_to_component):
                component = future_to_component[future]
                try:
                    success, return_code, stdout, stderr = future.result()
                except Exception as exc:  # pragma: no cover - subprocess wrapper should not fail
                    success, return_code, stdout, stderr = False, -1, "", str(exc)
                component.success = success
                component.return_code = return_code
                component.stdout = stdout
                component.stderr = stderr

    report: dict[str, Any] = {
        "query_label": query_label,
        "query_path": str(query_path) if query_path is not None else None,
        "output_dir": str(output_dir),
        "parse_errors": [asdict(item) for item in parse_errors],
        "config": {
            "style": config.style,
            "name": config.name,
            "signature": config.signature,
            "start_line": config.start_line,
            "end_line": config.end_line,
        },
        "predicates": [
            {
                "name": predicate.name,
                "role": predicate.role,
                "parameters": [asdict(param) for param in predicate.parameters],
                "start_line": predicate.start_line,
                "end_line": predicate.end_line,
            }
            for predicate in config.predicates
        ],
        "generated_components": [asdict(item) for item in generated_components],
        "compile_requested": compile_components,
        "probe_kind_mode": probe_kind_mode,
    }

    summary_json_path = output_dir / "structural_extract_summary.json"
    summary_json_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    summary_md_path = output_dir / "structural_extract_summary.md"
    summary_md_path.write_text(
        build_markdown_summary(report, generated_components),
        encoding="utf-8",
    )

    report["summary_json_path"] = str(summary_json_path)
    report["summary_md_path"] = str(summary_md_path)
    return report


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Decompose a CodeQL query into source/sink/barrier/flow probes using "
            "tree-sitter-ql, then optionally compile each component."
        )
    )
    parser.add_argument("--query-path", type=Path, help="Path to the .ql query file.")
    parser.add_argument(
        "--query-text",
        help="Inline CodeQL query text. Use this when you do not want to read from a file.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Directory for generated probe files and summary artifacts.",
    )
    parser.add_argument(
        "--codeql-path",
        default=CODEQL_PATH,
        help="Path to the codeql executable used for query compilation.",
    )
    parser.add_argument(
        "--skip-compile",
        action="store_true",
        help="Only generate component queries without invoking `codeql query compile`.",
    )
    parser.add_argument(
        "--probe-kind-mode",
        default="hybrid",
        choices=PROBE_KIND_MODES,
        help=(
            "Choose how component probe kinds are generated: "
            "`hybrid` keeps source/sink as problem and barrier/flow as table; "
            "`all-table` forces all probes to table; "
            "`all-problem` forces all probes to problem."
        ),
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the final JSON report.",
    )
    args = parser.parse_args(argv)

    if bool(args.query_path) == bool(args.query_text):
        parser.error("Provide exactly one of --query-path or --query-text.")

    return args


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    try:
        report = extract_and_compile_components(
            query_path=args.query_path,
            query_text=args.query_text,
            output_dir=args.output_dir,
            codeql_path=args.codeql_path,
            compile_components=not args.skip_compile,
            probe_kind_mode=args.probe_kind_mode,
        )
    except Exception as exc:  # pragma: no cover - CLI path
        LOGGER.error("%s", exc)
        return 1

    dump = json.dumps(report, indent=2 if args.pretty else None, ensure_ascii=False)
    print(dump)
    return 0


if __name__ == "__main__":
    sys.exit(main())
