"""
LSP-based CodeQL Query Diagnostic Engine.

Given a CodeQL query file, this engine:
1. Opens the query in CodeQL LSP
2. Collects structured diagnostics (errors/warnings with exact positions)
3. For each error, queries LSP hover + completions for context
4. Generates structured, human-readable fix suggestions

This is the core component for LSP-enhanced LLM feedback in VulnSynth Phase 3.
"""

import asyncio
import json
import logging
import os
import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Any

from .codeql_lsp_client import CodeQLLspClient

logger = logging.getLogger(__name__)


# ── Data types ─────────────────────────────────────────────────────

@dataclass
class ErrorLocation:
    """A single compilation error with LSP-derived fix context."""
    line: int             # 0-based line number
    character: int        # 0-based character offset
    end_line: int
    end_character: int
    message: str
    severity: int         # 1 = Error, 2 = Warning
    error_code: str = ""  # Parsed from message (e.g., "cannot_resolve", "type_mismatch")

    # LSP context
    hover_text: Optional[str] = None
    hover_raw: Optional[dict] = None
    completions: list[str] = field(default_factory=list)

    # Source context
    source_line: str = ""
    source_snippet: str = ""


@dataclass
class DiagnosisReport:
    """Complete diagnosis report for a CodeQL query."""
    query_path: str
    total_errors: int
    total_warnings: int
    errors: list[ErrorLocation] = field(default_factory=list)
    warnings: list[ErrorLocation] = field(default_factory=list)
    lsp_clean: bool = False  # LSP reports no errors
    notes: list[str] = field(default_factory=list)


@dataclass
class FixSuggestion:
    """A human-readable fix suggestion for one error."""
    location: str           # e.g., "Line 5, Character 62"
    error_summary: str      # one-line summary
    lsp_context: str        # what LSP says about this position
    candidate_fixes: list[str]  # suggested fixes
    example_fix: str        # concrete code example


# ── Error classification ───────────────────────────────────────────

# Regex patterns to classify the type of error from the message
ERROR_PATTERNS = {
    "cannot_resolve": re.compile(
        r"(?:could not resolve|cannot be resolved|cannot resolve)\b.*?\b(.+?)(?:\s|$)"
    ),
    "type_not_found": re.compile(
        r"could not resolve (?:type|module)\s+(.+)"
    ),
    "arity_mismatch": re.compile(
        r"(\w+)\(.*?\) cannot be resolved.*?(\d+)\s+argument"
    ),
    "predicate_with_result": re.compile(
        r"Expected a predicate without result but found '(\w+)'"
    ),
    "unbound_variable": re.compile(
        r"'(\w+)' is not bound"
    ),
    "type_incompatible": re.compile(
        r"No values can satisfy this term.*?(@\w+).*?(@\w+)"
    ),
    "expected_term": re.compile(
        r"expected a term but found an expression instead"
    ),
}


def classify_error(message: str) -> str:
    """Classify a CodeQL error message into a known category."""
    for code, pattern in ERROR_PATTERNS.items():
        if pattern.search(message):
            return code
    return "unknown"


# ── Fix suggestion generators per error type ────────────────────────

def _generate_cannot_resolve_fix(err: ErrorLocation, source_lines: list[str]) -> list[str]:
    """Generate fix suggestions for 'cannot resolve predicate/type' errors."""
    suggestions = []

    if err.completions:
        top_5 = err.completions[:5]
        suggestions.append(
            f"Replace with a valid member: {', '.join(top_5)}"
        )

    if err.hover_text:
        # Try to extract the expected type from hover
        type_match = re.search(r'(?:type|Type):\s*(\S+)', err.hover_text)
        if type_match:
            suggestions.append(
                f"The expected type is `{type_match.group(1)}`. "
                f"Make sure the predicate you're calling exists on this type."
            )

    # Check if it's a simple typo
    wrong_name = re.search(
        r"(\w+)(?:\([^)]*\))?\s+(?:cannot be resolved|could not resolve)",
        err.message
    )
    if wrong_name and err.completions:
        name = wrong_name.group(1)
        # Find closest match
        best = _find_closest(name, err.completions)
        if best:
            suggestions.append(f"Did you mean `{best}`? (closest match to `{name}`)")

    return suggestions


def _generate_missing_import_fix(err: ErrorLocation, source_lines: list[str]) -> list[str]:
    """Generate fix suggestions for 'could not resolve type/module' errors."""
    suggestions = []

    # Extract the type name from the error
    type_match = re.search(r"could not resolve (?:type|module)\s+(\S+)", err.message)
    if type_match:
        type_name = type_match.group(1)
        suggestions.append(
            f"Type `{type_name}` is not in scope. You need to add the correct import.\n"
            f"Use LSP completions at the top of the file to find available imports."
        )

    # Check known type → import mappings
    KNOWN_IMPORTS = {
        "RemoteFlowSource": "import semmle.code.java.dataflow.FlowSources",
        "TaintTracking": "import semmle.code.java.dataflow.TaintTracking",
        "DataFlow": "import semmle.code.java.dataflow.DataFlow",
        "QueryInjectionSink": "import semmle.code.java.security.QueryInjection",
        "XssSink": "import semmle.code.java.security.Xss",
    }
    if type_match and type_match.group(1) in KNOWN_IMPORTS:
        suggestions.append(
            f"Add: `{KNOWN_IMPORTS[type_match.group(1)]}`"
        )

    return suggestions


def _generate_predicate_with_result_fix(err: ErrorLocation, source_lines: list[str]) -> list[str]:
    """Generate fix for 'expected predicate without result' errors."""
    suggestions = []
    match = re.search(r"Expected a predicate without result but found '(\w+)'", err.message)
    if match:
        pred_name = match.group(1)
        suggestions.append(
            f"`{pred_name}` returns a value (it's a predicate with result), "
            f"but this position expects a condition (predicate without result).\n"
            f"Options:\n"
            f"  1. Bind the result to a variable: `exists(TypeOfResult r | r = {pred_name}(args) | ...)`\n"
            f"  2. Use `.get{''.join(pred_name.split('get')[1:]) if pred_name.startswith('get') else pred_name}()` instead if available\n"
            f"  3. Check your from/where clause logic"
        )
    return suggestions


def _generate_unbound_var_fix(err: ErrorLocation, source_lines: list[str]) -> list[str]:
    """Generate fix for unbound variable errors."""
    suggestions = []
    match = re.search(r"'(\w+)' is not bound", err.message)
    if match:
        var_name = match.group(1)
        suggestions.append(
            f"Variable `{var_name}` is used but never declared. "
            f"Add it to the `from` clause or bind it in the `where` clause with `exists(...)`."
        )
    return suggestions


def _generate_generic_fix(err: ErrorLocation, source_lines: list[str]) -> list[str]:
    """Generate generic fix suggestions using LSP data."""
    suggestions = []

    if err.completions:
        top_5 = err.completions[:5]
        suggestions.append(
            f"LSP suggests these valid alternatives: {', '.join(top_5)}"
        )

    if err.hover_text:
        suggestions.append(
            f"LSP hover context: {err.hover_text[:300]}"
        )

    suggestions.append(
        f"Review the CodeQL standard library documentation for the correct API at this position."
    )

    return suggestions


FIX_GENERATORS = {
    "cannot_resolve": _generate_cannot_resolve_fix,
    "type_not_found": _generate_missing_import_fix,
    "predicate_with_result": _generate_predicate_with_result_fix,
    "unbound_variable": _generate_unbound_var_fix,
    "unknown": _generate_generic_fix,
}


def _find_closest(target: str, candidates: list[str], threshold: float = 0.4) -> Optional[str]:
    """Find the closest matching string from candidates using simple similarity."""
    best = None
    best_score = 0.0

    target_lower = target.lower()
    for c in candidates:
        c_lower = c.lower()
        # Jaccard on character bigrams
        target_bigrams = set(zip(target_lower, target_lower[1:]))
        c_bigrams = set(zip(c_lower, c_lower[1:]))
        if not target_bigrams or not c_bigrams:
            continue
        intersection = target_bigrams & c_bigrams
        union = target_bigrams | c_bigrams
        score = len(intersection) / len(union) if union else 0

        # Bonus for common prefix
        prefix_len = 0
        for a, b in zip(target_lower, c_lower):
            if a == b:
                prefix_len += 1
            else:
                break
        score += prefix_len * 0.05

        if score > best_score:
            best_score = score
            best = c

    if best and best_score > threshold:
        return best
    return None


# ── Main diagnosis engine ──────────────────────────────────────────

class LspDiagnosisEngine:
    """Main engine: runs LSP diagnostics on a CodeQL query and produces fix suggestions."""

    def __init__(self, codeql_path: str = "codeql", workspace_dir: str = None):
        self.codeql_path = codeql_path
        self.workspace_dir = workspace_dir or os.getcwd()
        self.client: Optional[CodeQLLspClient] = None

    async def start(self) -> None:
        """Start the LSP client."""
        self.client = CodeQLLspClient(codeql_path=self.codeql_path)
        await self.client.start(self.workspace_dir)

    async def stop(self) -> None:
        """Stop the LSP client."""
        if self.client:
            await self.client.stop()

    async def diagnose(self, query_path: str) -> DiagnosisReport:
        """Run full LSP diagnosis on a query and return structured report."""
        if not self.client:
            raise RuntimeError("LspDiagnosisEngine not started. Call start() first.")

        query_path = os.path.abspath(query_path)
        if not os.path.exists(query_path):
            raise FileNotFoundError(f"Query not found: {query_path}")

        content = Path(query_path).read_text(encoding="utf-8")
        source_lines = content.split("\n")

        # 1. Open document in LSP
        uri = f"file://{query_path}"
        await self.client.open_document(uri, content)

        # 2. Get diagnostics
        raw_diags = await self.client.get_diagnostics(uri)

        # 3. Separate errors and warnings
        errors_raw = [d for d in raw_diags if d.get("severity", 0) == 1]
        warnings_raw = [d for d in raw_diags if d.get("severity", 0) == 2]

        logger.info(f"LSP diagnosis complete: {len(errors_raw)} errors, "
                     f"{len(warnings_raw)} warnings for {os.path.basename(query_path)}")

        # 4. Build ErrorLocation for each error with LSP context
        errors: list[ErrorLocation] = []
        for diag in errors_raw:
            err = await self._enrich_error(diag, uri, source_lines)
            errors.append(err)

        # Also enrich warnings (no hover/completions to save time)
        warnings: list[ErrorLocation] = []
        for diag in warnings_raw:
            w = ErrorLocation(
                line=diag["range"]["start"]["line"],
                character=diag["range"]["start"]["character"],
                end_line=diag["range"]["end"]["line"],
                end_character=diag["range"]["end"]["character"],
                message=diag.get("message", ""),
                severity=2,
                error_code=classify_error(diag.get("message", "")),
                source_line=_get_source_context(source_lines, diag),
            )
            warnings.append(w)

        report = DiagnosisReport(
            query_path=query_path,
            total_errors=len(errors),
            total_warnings=len(warnings_raw),
            errors=errors,
            warnings=warnings,
            lsp_clean=(len(errors) == 0),
            notes=[],
        )

        return report

    async def _enrich_error(
        self, diag: dict, uri: str, source_lines: list[str]
    ) -> ErrorLocation:
        """Enrich a diagnostic with LSP hover and completions."""
        line = diag["range"]["start"]["line"]
        char = diag["range"]["start"]["character"]
        message = diag.get("message", "")

        # Query LSP for type info at this position
        hover = await self.client.get_hover(uri, line, char)

        # Query LSP for completions at this position
        completions = await self.client.get_completions(uri, line, char)

        hover_text = ""
        if hover:
            if isinstance(hover.get("contents"), dict):
                hover_text = hover["contents"].get("value", "")
            elif isinstance(hover.get("contents"), list):
                parts = []
                for item in hover["contents"]:
                    if isinstance(item, dict):
                        parts.append(item.get("value", ""))
                    elif isinstance(item, str):
                        parts.append(item)
                hover_text = "\n".join(parts)
            elif isinstance(hover.get("contents"), str):
                hover_text = hover["contents"]

        return ErrorLocation(
            line=line,
            character=char,
            end_line=diag["range"]["end"]["line"],
            end_character=diag["range"]["end"]["character"],
            message=message,
            severity=1,
            error_code=classify_error(message),
            hover_text=hover_text,
            hover_raw=hover,
            completions=completions,
            source_line=_get_source_context(source_lines, diag),
            source_snippet=_extract_snippet(source_lines, diag),
        )

    async def generate_fix_suggestions(self, report: DiagnosisReport) -> list[FixSuggestion]:
        """Generate human-readable fix suggestions from a diagnosis report."""
        suggestions: list[FixSuggestion] = []

        source_lines = Path(report.query_path).read_text(encoding="utf-8").split("\n")

        for i, err in enumerate(report.errors):
            # Get the right fix generator
            generator = FIX_GENERATORS.get(err.error_code, _generate_generic_fix)
            candidate_fixes = generator(err, source_lines)

            # Build location string
            location = f"Line {err.line + 1}, Character {err.character}"  # 1-based for humans

            # Build LSP context
            lsp_parts = []
            if err.hover_text:
                lsp_parts.append(f"**Type/Hover**: {err.hover_text[:200]}")
            if err.completions:
                lsp_parts.append(f"**Valid alternatives**: {', '.join(err.completions[:8])}")
            lsp_context = "\n".join(lsp_parts) if lsp_parts else "No LSP context available"

            # Build an example fix
            example = self._build_example_fix(err, candidate_fixes)

            suggestions.append(FixSuggestion(
                location=location,
                error_summary=err.message,
                lsp_context=lsp_context,
                candidate_fixes=candidate_fixes,
                example_fix=example,
            ))

        return suggestions

    def _build_example_fix(self, err: ErrorLocation, fixes: list[str]) -> str:
        """Build a concrete code example for the fix."""
        if not err.source_snippet:
            return "(Could not extract source context)"

        snippet = err.source_snippet.strip()

        if err.error_code == "cannot_resolve" and err.completions:
            # Try to suggest a concrete replacement
            match = re.search(r"(\w+)\(", err.message)
            if match:
                wrong = match.group(1)
                best = _find_closest(wrong, err.completions)
                if best:
                    return (
                        f"```ql\n"
                        f"// BEFORE (line {err.line + 1}):\n"
                        f"{snippet}\n\n"
                        f"// AFTER (suggested fix):\n"
                        f"{snippet.replace(wrong, best)}\n"
                        f"```"
                    )

        if err.error_code == "type_not_found":
            return (
                f"```ql\n"
                f"// Add the missing import at the top of the file.\n"
                f"// Check LSP completions at the import area for available modules.\n"
                f"```"
            )

        if err.error_code == "predicate_with_result":
            match = re.search(r"but found '(\w+)'", err.message)
            if match:
                pred = match.group(1)
                return (
                    f"```ql\n"
                    f"// BEFORE:\n"
                    f"{snippet}\n\n"
                    f"// AFTER (bind result to variable):\n"
                    f"exists(TypeName result | result = {pred}(args) | ...)\n"
                    f"```"
                )

        return f"```ql\n// Fix suggestion for: {snippet}\n// See candidate fixes above.\n```"

    def format_markdown_report(
        self, report: DiagnosisReport, suggestions: list[FixSuggestion]
    ) -> str:
        """Format the complete diagnosis as a Markdown report.

        This is what gets fed back to the LLM agent for repair.
        """
        basename = os.path.basename(report.query_path)
        lines = [
            f"# LSP Diagnostic Report for `{basename}`",
            "",
            f"**Status**: {'✅ LSP Clean' if report.lsp_clean else f'❌ {report.total_errors} Error(s)'}",
            f"**Warnings**: {report.total_warnings}",
            "",
        ]

        if not report.errors:
            lines.append("No compilation errors detected by LSP. The query should compile successfully.")
            lines.append("")
            if report.warnings:
                lines.append("## Warnings")
                lines.append("")
                for w in report.warnings:
                    lines.append(f"- Line {w.line + 1}:{w.character} — {w.message}")
                lines.append("")
            return "\n".join(lines)

        lines.append("---")
        lines.append("")

        for i, (err, sugg) in enumerate(zip(report.errors, suggestions)):
            lines.append(f"## Error {i + 1}: {sugg.location}")
            lines.append("")
            lines.append(f"**Category**: `{err.error_code}`")
            lines.append(f"**Message**: {err.message}")
            lines.append("")

            if err.source_snippet:
                lines.append("### Source Context")
                lines.append("```ql")
                lines.append(err.source_snippet)
                lines.append("```")
                lines.append("")

            lines.append("### LSP Context")
            lines.append(sugg.lsp_context)
            lines.append("")

            lines.append("### Candidate Fixes")
            for fix in sugg.candidate_fixes:
                lines.append(f"- {fix}")
            lines.append("")

            if sugg.example_fix:
                lines.append("### Suggested Fix")
                lines.append(sugg.example_fix)
                lines.append("")

            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def format_structured_json(
        self, report: DiagnosisReport, suggestions: list[FixSuggestion]
    ) -> dict:
        """Format the diagnosis as structured JSON for programmatic consumption."""
        return {
            "query_path": report.query_path,
            "lsp_clean": report.lsp_clean,
            "total_errors": report.total_errors,
            "total_warnings": report.total_warnings,
            "errors": [
                {
                    "index": i,
                    "location": {
                        "line_0based": err.line,
                        "line_1based": err.line + 1,
                        "character": err.character,
                    },
                    "error_code": err.error_code,
                    "message": err.message,
                    "hover_text": err.hover_text,
                    "completions": err.completions[:10],
                    "source_snippet": err.source_snippet,
                    "candidate_fixes": sugg.candidate_fixes,
                }
                for i, (err, sugg) in enumerate(zip(report.errors, suggestions))
            ],
            "warnings": [
                {
                    "location": f"Line {w.line + 1}:{w.character}",
                    "message": w.message,
                }
                for w in report.warnings
            ],
        }


# ── Helpers ─────────────────────────────────────────────────────────

def _get_source_context(source_lines: list[str], diag: dict) -> str:
    """Extract the source line containing the error."""
    line_num = diag["range"]["start"]["line"]
    if 0 <= line_num < len(source_lines):
        return source_lines[line_num]
    return ""


def _extract_snippet(source_lines: list[str], diag: dict, context_lines: int = 1) -> str:
    """Extract source code snippet around the error position."""
    line_num = diag["range"]["start"]["line"]
    start = max(0, line_num - context_lines)
    end = min(len(source_lines), line_num + context_lines + 1)

    lines = []
    for i in range(start, end):
        prefix = ">>>" if i == line_num else "   "
        lines.append(f"{prefix} {i + 1:3d} | {source_lines[i]}")

    return "\n".join(lines)


# ── CLI entry point ─────────────────────────────────────────────────

async def diagnose_query(query_path: str, codeql_path: str = "codeql",
                         workspace_dir: str = None) -> DiagnosisReport:
    """Convenience function: diagnose a single query file."""
    engine = LspDiagnosisEngine(codeql_path=codeql_path, workspace_dir=workspace_dir)
    await engine.start()
    try:
        report = await engine.diagnose(query_path)
        return report
    finally:
        await engine.stop()


async def diagnose_and_suggest(query_path: str, codeql_path: str = "codeql",
                               workspace_dir: str = None) -> tuple[DiagnosisReport, list[FixSuggestion]]:
    """Convenience function: diagnose and generate fix suggestions."""
    engine = LspDiagnosisEngine(codeql_path=codeql_path, workspace_dir=workspace_dir)
    await engine.start()
    try:
        report = await engine.diagnose(query_path)
        suggestions = await engine.generate_fix_suggestions(report)
        return report, suggestions
    finally:
        await engine.stop()
