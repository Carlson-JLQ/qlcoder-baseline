#!/usr/bin/env python3
"""
Component-level dependency pruner for CodeQL component probes.

When generating a component probe (e.g. source probe), the current
approach includes ALL support blocks (Source, Sink, Sanitizer,
TaintPropagation classes).  This module statically traces which classes
are reachable from a given role predicate body and strips the rest.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable, Optional

try:
    import tree_sitter_ql as tsql
    from tree_sitter import Language, Parser
except ImportError:  # pragma: no cover - optional dependency at runtime
    tsql = None
    Language = None
    Parser = None


# ---------------------------------------------------------------------------
# Tree-sitter helpers
# ---------------------------------------------------------------------------

_parser: Optional[Parser] = None

_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_]\w*\b")
_LINE_COMMENT_RE = re.compile(r"//.*?$", re.MULTILINE)
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_QL_KEYWORDS: set[str] = {
    "and",
    "any",
    "as",
    "cached",
    "class",
    "exists",
    "extends",
    "false",
    "final",
    "for",
    "from",
    "if",
    "implements",
    "import",
    "in",
    "instanceof",
    "int",
    "module",
    "newtype",
    "none",
    "not",
    "or",
    "override",
    "predicate",
    "private",
    "result",
    "select",
    "string",
    "super",
    "this",
    "true",
    "where",
}


def _get_parser() -> Parser:
    global _parser
    if _parser is None:
        if tsql is None or Language is None or Parser is None:
            raise RuntimeError("tree_sitter_ql is not available")
        _parser = Parser(Language(tsql.language()))
    return _parser


def _parse(text: str) -> Any:
    return _get_parser().parse(text.encode("utf-8"))


def _node_text(node: Any, source: str) -> str:
    return source[node.start_byte : node.end_byte]


# ---------------------------------------------------------------------------
# Name extraction
# ---------------------------------------------------------------------------

_CLASS_DEF_RE = re.compile(
    r"\bclass\s+(?P<name>[A-Za-z_]\w*)\s+(extends|instanceof)",
)
_PREDICATE_DEF_RE = re.compile(
    r"\bpredicate\s+(?P<name>[A-Za-z_]\w*)\s*\(",
)
_MODULE_DEF_RE = re.compile(
    r"\bmodule\s+(?P<name>[A-Za-z_]\w*)\s+(implements|=)",
)


def extract_defined_name(support_text: str) -> Optional[str]:
    """Return the QL name *defined* by a support block (class / predicate / module)."""
    for pattern in (_CLASS_DEF_RE, _PREDICATE_DEF_RE, _MODULE_DEF_RE):
        m = pattern.search(support_text)
        if m:
            return m.group("name")
    return None


def _collect_names_in_subtree(node: Any, source: str) -> set[str]:
    """Walk *node* and collect every className / moduleName text."""
    names: set[str] = set()
    _walk_for_names(node, source, names)
    return names


def _walk_for_names(node: Any, source: str, names: set[str]) -> None:
    if node.type in ("className", "moduleName"):
        names.add(_node_text(node, source))
    for child in node.children:
        _walk_for_names(child, source, names)


def _strip_comments_and_strings(text: str) -> str:
    without_block_comments = _BLOCK_COMMENT_RE.sub(" ", text)
    without_line_comments = _LINE_COMMENT_RE.sub(" ", without_block_comments)
    return _STRING_RE.sub(" ", without_line_comments)


def _collect_identifiers(text: str) -> set[str]:
    normalized = _strip_comments_and_strings(text)
    return set(_IDENTIFIER_RE.findall(normalized))


# Patterns that are auto-provided by CodeQL imports (stdlib types)
_STDLIB_NAMES: set[str] = {
    "DataFlow",
    "Node",
    "ConstructorCall",
    "MethodCall",
    "MethodAccess",
    "AddExpr",
    "TaintTracking",
    "AdditionalTaintStep",
    "RemoteFlowSource",
    "FlowSources",
    "ConfigSig",
    "Configuration",
    "DataFlow2",
    "DataFlow3",
    "PathNode",
    "PathGraph",
    "Global",
    "TaintTracking",
    "ExternalProcess",
}


def _is_stdlib_name(name: str) -> bool:
    """Heuristic: a simple (non-qualified) name that is likely from the stdlib."""
    return name in _STDLIB_NAMES


def extract_referenced_names(text: str) -> set[str]:
    """Return referenced identifier-like names within *text*.

    We prefer a lightweight lexical scan because it can capture helper predicate
    references (for example ``isSensitiveCredentialRead``) in addition to class
    and module names. When tree-sitter is available, merge in the structural
    names it can identify as an additional signal.
    """
    names = {
        name for name in _collect_identifiers(text)
        if name not in _QL_KEYWORDS and not _is_stdlib_name(name)
    }

    if tsql is not None and Language is not None and Parser is not None:
        try:
            tree = _parse(text)
            names.update(_collect_names_in_subtree(tree.root_node, text))
        except Exception:
            pass

    return names


# ---------------------------------------------------------------------------
# Dependency graph
# ---------------------------------------------------------------------------

DependencyGraph = dict[str, tuple[str, set[str]]]
#  { "Source": (source_block_text, {"ConstructorCall", "MethodCall", ...}), ... }


def build_dependency_graph(support_blocks: list[str]) -> DependencyGraph:
    """Index every support block by the name it defines."""
    graph: DependencyGraph = {}
    for block in support_blocks:
        name = extract_defined_name(block)
        if name is None:
            continue
        graph[name] = (block, set())

    defined_names = set(graph)
    for name, (block, _refs) in list(graph.items()):
        refs = extract_referenced_names(block) & defined_names
        refs.discard(name)
        graph[name] = (block, refs)
    return graph


def _transitive_closure(
    seed_names: Iterable[str],
    graph: DependencyGraph,
) -> set[str]:
    """Return the set of defined names reachable from *seed_names*."""
    reachable: set[str] = set()
    queue: list[str] = [n for n in seed_names if n in graph]
    while queue:
        name = queue.pop()
        if name in reachable:
            continue
        reachable.add(name)
        _block, refs = graph[name]
        for ref in refs:
            if ref in graph and ref not in reachable:
                queue.append(ref)
    return reachable


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def prune_support_blocks_for_role(
    *,
    role_predicate_body: str,
    role: str,
    support_blocks: list[str],
) -> list[str]:
    """Return only the support blocks transitively referenced from *role_predicate_body*.

    Parameters
    ----------
    role_predicate_body : str
        The body text of the config predicate (e.g. ``source instanceof Source``).
    role : str
        One of ``"source"``, ``"sink"``, ``"barrier"``, ``"flow"``.
    support_blocks : list[str]
        Raw text of every top-level support block (classes, predicates, modules).

    Returns
    -------
    list[str]
        The subset of *support_blocks* that are transitively referenced.
    """
    if not support_blocks:
        return []

    graph = build_dependency_graph(support_blocks)

    # Step 1 — seed names directly mentioned in the predicate body
    seed_names = extract_referenced_names(role_predicate_body) & set(graph)

    # Step 2 — transitive closure through support-block references
    reachable_names = _transitive_closure(seed_names, graph)

    # Step 3 — filter support blocks
    kept: list[str] = []
    for block in support_blocks:
        name = extract_defined_name(block)
        if name is None or name in reachable_names:
            kept.append(block)

    return kept


# ---------------------------------------------------------------------------
# Comparison helper for standalone experiments
# ---------------------------------------------------------------------------

def compare_probes(
    query_path: Path,
    output_dir: Optional[Path] = None,
) -> dict[str, dict[str, Any]]:
    """Read *query_path*, produce original-vs-pruned probes for all 4 roles.

    Returns a dict keyed by role, each value::

        {
          "role": str,
          "original_support_blocks": [str, ...],
          "pruned_support_blocks": [str, ...],
          "original_probe_lines": int,
          "pruned_probe_lines": int,
          "kept_names": [str, ...],
          "dropped_names": [str, ...],
        }
    """
    from vulnsynth.structural_extract import (
        build_component_query,
        collect_top_level_texts,
        extract_predicates_from_config_text,
        find_config,
        read_query_input,
    )

    source, query_label = read_query_input(query_path, None)
    tree = _parse(source)
    root = tree.root_node

    config = find_config(root, source)
    grouped = collect_top_level_texts(root, source, config.name)
    all_support = list(grouped.get("support", []))
    all_support.extend(grouped.get("module_alias", []))
    all_support.extend(
        predicate.full_text
        for predicate in config.predicates
        if predicate.role == "helper"
    )

    # Build a mapping from role → predicate body
    role_bodies: dict[str, str] = {}
    for predicate in config.predicates:
        if predicate.role in ("source", "sink", "barrier", "flow"):
            role_bodies[predicate.role] = predicate.body_text

    results: dict[str, dict[str, Any]] = {}
    for role in ("source", "sink", "barrier", "flow"):
        body = role_bodies.get(role)
        if body is None:
            results[role] = {"error": "predicate not found"}
            continue

        pruned = prune_support_blocks_for_role(
            role_predicate_body=body,
            role=role,
            support_blocks=all_support,
        )

        # Which names were kept / dropped
        all_names = {extract_defined_name(b) for b in all_support} - {None}
        kept_names = {extract_defined_name(b) for b in pruned} - {None}
        dropped_names = all_names - kept_names

        results[role] = {
            "role": role,
            "predicate_body": body,
            "original_support_blocks": len(all_support),
            "pruned_support_blocks": len(pruned),
            "all_names": sorted(all_names),
            "kept_names": sorted(kept_names),
            "dropped_names": sorted(dropped_names),
            "pruned_blocks": pruned,
            "all_support_blocks": all_support,
        }

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    import argparse, json

    ap = argparse.ArgumentParser(
        description="Static dependency pruner for CodeQL component probes"
    )
    ap.add_argument("query_path", help="Path to the original .ql query")
    ap.add_argument(
        "--output-dir",
        default=None,
        help="Directory to write comparison artifacts (default: <query_path>.prune-comparison/)",
    )
    ap.add_argument(
        "--write-probes",
        action="store_true",
        help="Write pruned probe files to the output directory",
    )
    args = ap.parse_args()

    query_path = Path(args.query_path).resolve()
    if not query_path.exists():
        print(f"ERROR: {query_path} does not exist", file=__import__("sys").stderr)
        return 1

    out_dir = (
        Path(args.output_dir)
        if args.output_dir
        else query_path.parent / f"{query_path.stem}-prune-comparison"
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    results = compare_probes(query_path, out_dir)

    # Print summary
    for role, info in sorted(results.items()):
        if "error" in info:
            print(f"[{role}] ERROR: {info['error']}")
            continue
        n_orig = info["original_support_blocks"]
        n_pruned = info["pruned_support_blocks"]
        pct = (n_pruned / n_orig * 100) if n_orig else 0
        print(
            f"[{role}] support blocks: {n_orig} → {n_pruned} ({pct:.0f}%)  "
            f"kept={info['kept_names']}  dropped={info['dropped_names']}"
        )

        if args.write_probes and info.get("kept_names"):
            from vulnsynth.structural_extract import build_component_query

            # We'll write only the pruned version for comparison
            pass  # full integration requires access to the full pipeline

    # Save full report
    report_path = out_dir / "prune_report.json"
    serializable = {}
    for role, info in results.items():
        if "pruned_blocks" in info:
            info = dict(info)
            del info["pruned_blocks"]
            del info["all_support_blocks"]
        serializable[role] = info
    report_path.write_text(
        json.dumps(serializable, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"\nFull report: {report_path}")

    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
