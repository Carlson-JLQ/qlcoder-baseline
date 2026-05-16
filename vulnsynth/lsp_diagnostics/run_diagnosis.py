#!/usr/bin/env python3
"""
Run LSP diagnosis on all buggy query examples and produce fix suggestions.

Usage:
    # Run on all buggy queries in the default directory
    python -m vulnsynth.lsp_diagnostics.run_diagnosis

    # Run on a specific query
    python -m vulnsynth.lsp_diagnostics.run_diagnosis --query path/to/query.ql

    # Specify CodeQL path
    python -m vulnsynth.lsp_diagnostics.run_diagnosis --codeql-path /opt/codeql/codeql
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

from .diagnosis_engine import LspDiagnosisEngine
from .codeql_lsp_client import CodeQLLspClient

logger = logging.getLogger(__name__)

BUGGY_QUERIES_DIR = Path(__file__).resolve().parent / "buggy_queries"
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # VulnSynth root


def resolve_codeql_path(args_codeql: str = None) -> str:
    """Resolve the codeql executable path."""
    if args_codeql:
        return args_codeql
    for var in ["CODEQL_PATH", "CODEQL_HOME"]:
        val = os.environ.get(var)
        if val:
            if var == "CODEQL_HOME":
                return os.path.join(val, "codeql")
            return val
    return "codeql"  # fallback to PATH


async def diagnose_single(query_path: str, codeql_path: str) -> dict:
    """Diagnose a single query and return JSON results."""
    print(f"\n{'='*70}")
    print(f"Diagnosing: {query_path}")
    print(f"{'='*70}")

    # Use the query file's directory as workspace so LSP finds its qlpack.yml
    query_dir = str(Path(query_path).resolve().parent)
    engine = LspDiagnosisEngine(
        codeql_path=codeql_path,
        workspace_dir=query_dir,
    )

    await engine.start()
    try:
        report = await engine.diagnose(query_path)
        suggestions = await engine.generate_fix_suggestions(report)

        # Print markdown report to stdout
        md_report = engine.format_markdown_report(report, suggestions)
        print(md_report)

        # Also return structured JSON
        json_report = engine.format_structured_json(report, suggestions)

        # Save output files alongside the query
        out_dir = Path(query_path).parent
        stem = Path(query_path).stem

        md_path = out_dir / f"{stem}_lsp_diagnosis.md"
        json_path = out_dir / f"{stem}_lsp_diagnosis.json"

        md_path.write_text(md_report, encoding="utf-8")
        json_path.write_text(
            json.dumps(json_report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        print(f"\nOutput saved to:")
        print(f"  Markdown: {md_path}")
        print(f"  JSON:     {json_path}")

        return json_report

    finally:
        await engine.stop()


async def diagnose_all(codeql_path: str) -> list[dict]:
    """Diagnose all buggy queries in the examples directory."""
    results = []

    ql_files = sorted(BUGGY_QUERIES_DIR.glob("*.ql"))
    if not ql_files:
        print(f"No .ql files found in {BUGGY_QUERIES_DIR}")
        return results

    print(f"Found {len(ql_files)} buggy query files to diagnose")
    print(f"CodeQL: {codeql_path}")
    print(f"Workspace: {PROJECT_ROOT}")
    print()

    for ql_file in ql_files:
        try:
            result = await diagnose_single(str(ql_file), codeql_path)
            results.append(result)
        except Exception as e:
            logger.error(f"Failed to diagnose {ql_file}: {e}")
            results.append({
                "query_path": str(ql_file),
                "error": str(e),
                "lsp_clean": False,
                "total_errors": 0,
                "total_warnings": 0,
                "errors": [],
                "warnings": [],
            })

    # Print summary
    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print()

    total_errors = sum(r.get("total_errors", 0) for r in results)
    total_files = len(results)
    clean_files = sum(1 for r in results if r.get("lsp_clean", False))

    print(f"Files analyzed: {total_files}")
    print(f"Files clean:    {clean_files}")
    print(f"Total errors:   {total_errors}")

    print()
    for r in results:
        path = Path(r["query_path"]).stem if r.get("query_path") else "unknown"
        status = "✅" if r.get("lsp_clean") else "❌"
        error_count = r.get("total_errors", 0)
        if "error" in r and not r.get("errors"):
            print(f"  {status} {path}: EXECUTION FAILED — {r['error'][:80]}")
        else:
            print(f"  {status} {path}: {error_count} error(s)")

    return results


async def test_lsp_connection(codeql_path: str) -> bool:
    """Quick test to verify LSP can start and communicate."""
    print(f"Testing LSP connection (codeql={codeql_path}, workspace={PROJECT_ROOT})...")
    client = CodeQLLspClient(codeql_path=codeql_path)
    try:
        await client.start(str(PROJECT_ROOT))
        print("  ✅ LSP started and initialized successfully")
        await client.stop()
        return True
    except Exception as e:
        print(f"  ❌ LSP connection failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="LSP-based CodeQL Query Diagnostic Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m vulnsynth.lsp_diagnostics.run_diagnosis
  python -m vulnsynth.lsp_diagnostics.run_diagnosis --query buggy_queries/query_wrong_method.ql
  python -m vulnsynth.lsp_diagnostics.run_diagnosis --test-connection
        """,
    )
    parser.add_argument("--query", type=str,
                        help="Path to a specific .ql file to diagnose")
    parser.add_argument("--codeql-path", type=str,
                        help="Path to codeql executable (default: auto-detect)")
    parser.add_argument("--workspace-dir", type=str,
                        help="Workspace directory (default: VulnSynth root)")
    parser.add_argument("--test-connection", action="store_true",
                        help="Only test LSP connection")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    codeql_path = resolve_codeql_path(args.codeql_path)

    if args.test_connection:
        success = asyncio.run(test_lsp_connection(codeql_path))
        sys.exit(0 if success else 1)

    if args.query:
        query_path = os.path.abspath(args.query)
        if not os.path.exists(query_path):
            print(f"Error: query not found: {query_path}", file=sys.stderr)
            sys.exit(1)
        asyncio.run(diagnose_single(query_path, codeql_path))
    else:
        asyncio.run(diagnose_all(codeql_path))


if __name__ == "__main__":
    main()
