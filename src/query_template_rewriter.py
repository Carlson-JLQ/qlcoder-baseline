#!/usr/bin/env python3

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import tree_sitter_ql as tsql
    from tree_sitter import Language, Parser
except ImportError:  # pragma: no cover - handled at runtime
    tsql = None
    Language = None
    Parser = None


@dataclass
class PredicateSpan:
    name: str
    signature_text: str
    parameter_names: list[str]
    predicate_start_column: int
    body_start_byte: int
    body_end_byte: int
    body_text: str


def require_parser() -> Any:
    if tsql is None or Language is None or Parser is None:
        raise RuntimeError(
            "Missing dependencies: tree_sitter and tree_sitter_ql are required."
        )

    language = Language(tsql.language())
    return Parser(language)


def get_node_text(node: Any, source: str) -> str:
    return source[node.start_byte:node.end_byte]


def walk_named(node: Any):
    yield node
    for child in getattr(node, "named_children", []):
        yield from walk_named(child)


def extract_parameter_names(signature_text: str) -> list[str]:
    start = signature_text.find("(")
    end = signature_text.rfind(")")
    if start == -1 or end == -1 or end <= start:
        return []

    raw_parameters = signature_text[start + 1 : end].strip()
    if not raw_parameters:
        return []

    names: list[str] = []
    for raw_param in raw_parameters.split(","):
        match = raw_param.strip()
        param_name = match.split()[-1] if match else ""
        if param_name:
            names.append(param_name)
    return names


def find_predicate_span(source: str, predicate_name: str) -> PredicateSpan:
    parser = require_parser()
    tree = parser.parse(source.encode("utf-8"))
    root = tree.root_node

    for node in walk_named(root):
        if node.type != "classlessPredicate":
            continue

        name_node = None
        body_node = None
        for child in node.named_children:
            if child.type == "predicateName":
                name_node = child
            elif child.type == "body":
                body_node = child

        if name_node is None or body_node is None:
            continue

        name_text = get_node_text(name_node, source).strip()
        if name_text != predicate_name:
            continue

        signature_text = source[node.start_byte:body_node.start_byte].strip()
        return PredicateSpan(
            name=name_text,
            signature_text=signature_text,
            parameter_names=extract_parameter_names(signature_text),
            predicate_start_column=node.start_point.column,
            body_start_byte=body_node.start_byte,
            body_end_byte=body_node.end_byte,
            body_text=get_node_text(body_node, source),
        )

    raise ValueError(f"Predicate '{predicate_name}' not found in query.")


def strip_body_braces(body_text: str) -> str:
    stripped = body_text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped[1:-1].strip()
    return stripped


def indent_block(text: str, indent: str) -> str:
    lines = text.strip().splitlines()
    return "\n".join(f"{indent}{line.rstrip()}" for line in lines)


def format_wrapped_binary_body(
    old_expr: str, new_expr: str, operator: str, predicate_indent: int
) -> str:
    outer_indent = " " * predicate_indent
    inner_indent = " " * (predicate_indent + 2)
    nested_indent = " " * (predicate_indent + 4)

    return (
        "{\n"
        f"{inner_indent}(\n"
        f"{indent_block(old_expr, nested_indent)}\n"
        f"{inner_indent})\n"
        f"{inner_indent}{operator}\n"
        f"{inner_indent}(\n"
        f"{indent_block(new_expr, nested_indent)}\n"
        f"{inner_indent})\n"
        f"{outer_indent}}}"
    )


def rewrite_predicate_body(
    source: str, predicate_name: str, operation: str, snippet: str
) -> str:
    span = find_predicate_span(source, predicate_name)
    old_expr = strip_body_braces(span.body_text)

    if operation == "append-or":
        new_body = format_wrapped_binary_body(
            old_expr, snippet, "or", span.predicate_start_column
        )
    elif operation == "append-and":
        new_body = format_wrapped_binary_body(
            old_expr, snippet, "and", span.predicate_start_column
        )
    elif operation == "replace":
        outer_indent = " " * span.predicate_start_column
        inner_indent = " " * (span.predicate_start_column + 2)
        new_body = (
            "{\n"
            f"{indent_block(snippet, inner_indent)}\n"
            f"{outer_indent}}}"
        )
    else:  # pragma: no cover - argparse restricts this
        raise ValueError(f"Unsupported operation: {operation}")

    return source[: span.body_start_byte] + new_body + source[span.body_end_byte :]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Minimal tree-sitter-ql based query rewriter for template validation. "
            "This prototype rewrites a single predicate body by appending an OR/AND "
            "clause or replacing the body."
        )
    )
    parser.add_argument("--query-path", type=Path, required=True)
    parser.add_argument("--predicate", required=True)
    parser.add_argument(
        "--operation",
        choices=("append-or", "append-and", "replace"),
        required=True,
    )
    snippet_group = parser.add_mutually_exclusive_group(required=True)
    snippet_group.add_argument("--snippet-text")
    snippet_group.add_argument("--snippet-file", type=Path)
    parser.add_argument("--output-path", type=Path, required=True)
    return parser.parse_args()


def load_snippet(args: argparse.Namespace) -> str:
    if args.snippet_text is not None:
        return args.snippet_text.strip()
    assert args.snippet_file is not None
    return args.snippet_file.read_text(encoding="utf-8").strip()


def main() -> int:
    args = parse_args()
    source = args.query_path.read_text(encoding="utf-8")
    snippet = load_snippet(args)
    rewritten = rewrite_predicate_body(source, args.predicate, args.operation, snippet)
    args.output_path.parent.mkdir(parents=True, exist_ok=True)
    args.output_path.write_text(rewritten, encoding="utf-8")
    print(f"Rewrote {args.predicate} using {args.operation} -> {args.output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
