"""Claude-specific prompt functions for all ablation modes."""

import os

from .prompt_helpers import query_skeleton as _query_skeleton
from .prompt_helpers import source_sink_taint_examples as _source_sink_taint_examples

# Shared helpers


def _stop_block_initial(ql_file_path: str) -> str:
    return f"""
## CRITICAL: MANDATORY Write Tool Usage

**BEFORE STOPPING**: You MUST use the Write tool to save your final query to disk:
- **Tool**: `Write`
- **File path**: `{ql_file_path}`
- **Content**: Your complete CodeQL query

**IMPORTANT**: LSP tools only update the in-memory representation. The Write tool is required to persist the file to disk for the automated system to find it.

## CRITICAL: STOP EXECUTION IMMEDIATELY

**MANDATORY**: Once you have successfully written a .ql query file with the Write tool, you MUST STOP execution immediately and provide the file path.

**REQUIRED FINAL OUTPUT**: After writing the .ql file, your last message must be:
```
QUERY_FILE_PATH: {ql_file_path}
```

The automated system will take over to:
- Compile and test your query
- Run it on both vulnerable and fixed databases
- Provide feedback for the next iteration

**STOP AS SOON AS THE .ql FILE IS WRITTEN** - This prevents context window bloat and enables iterative refinement.
"""


def _stop_block_refinement(task, iteration: int) -> str:
    ql_file_path = f"{os.path.abspath(task.working_dir or '.')}/{task.cve_id}-query-iter-{iteration}.ql"
    return f"""
## CRITICAL: STOP EXECUTION IMMEDIATELY

**MANDATORY**: Once you have successfully written a .ql query file, you MUST STOP execution immediately and provide the file path.

**REQUIRED FINAL OUTPUT**: After writing the .ql file, your last message must be:
```
QUERY_FILE_PATH: {ql_file_path}
```
The automated system will take over to:
- Compile the query
- Test it on both databases
- Provide feedback for the next iteration

**STOP AS SOON AS THE .ql FILE IS WRITTEN** - This prevents context window bloat and enables iterative refinement.
"""

def _retrieving_chroma_analysis(collection_name) -> str: 
   return f"""### Retrieving Phase 1 Results:
Use `mcp__chroma__chroma_get_documents` with collection_name="{collection_name}" and:
- `where: {{"section": "sources"}}` - Source patterns
- `where: {{"section": "sinks"}}` - Sink patterns
- `where: {{"section": "sanitizers"}}` - Sanitizer patterns
- `where: {{"section": "additional_taint_steps"}}` - Additional taint step patterns
- `where: {{"section": "vulnerability_analysis_summary"}}` - Vulnerability analysis summary
- `where: {{"section": "cve_info"}}` - CVE information from NIST

### Tool Workflows:
- `where: {{"section": "workflow"}}` - Tool usage workflows from each phase

Example:
```
mcp__chroma__chroma_get_documents(
    collection_name="{collection_name}",
    where={{"section": "sources"}},
    limit=1
)
```
"""

# Phase 1

def _phase1_json_shape() -> str:
    return """Return exactly one JSON object with this shape:

{
  "vulnerability_research_summary": "",
  "cve_information": "",
  "relevant_files": [
    {
      "file": "",
      "description": ""
    }
  ],
  "sources": [
    {
      "description": "",
      "file": "",
      "location": "",
      "pattern": "",
      "conceptual_role": "",
      "pattern_category": "",
      "ast_elements": [],
      "detection_strategy": ""
    }
  ],
  "sinks": [],
  "sanitizers": [],
  "additional_taint_steps": [],
  "vulnerability_summary": ""
}

Rules:
- Output JSON only.
- Do not use markdown.
- Do not use code fences.
- Do not write the Phase 1 result to any file.
- Return the final JSON object directly in your final response.
- Keep keys exactly as written above.
- `ast_elements` are best-effort inferred from the diff summary and code context.
"""


def _phase1_input_block(task) -> str:
    return f"""
## Input

The preprocessed diff summary is provided through stdin as JSON.
Use stdin as the primary input.

Additional file references:
- Raw diff path: `{task.raw_diff_path or ""}`
- Diff summary JSON path: `{task.diff_focus_json_path or ""}`
- Diff summary Markdown path: `{task.diff_focus_md_path or ""}`
- Phase 1 schema reference: `{task.phase1_schema_path or ""}`

Use the raw diff only if the stdin summary is not sufficient.
"""


def _phase1_analysis_task() -> str:
    return f"""
## Analysis Task

Use the stdin diff summary to identify:
- relevant files
- sources
- sinks
- sanitizers
- additional taint steps
- final vulnerability summary

For each source/sink/sanitizer/additional taint step, include:
1. description
2. file
3. location
4. pattern
5. conceptual_role
6. pattern_category
7. ast_elements
8. detection_strategy

{_source_sink_taint_examples()}

## Output Format
{_phase1_json_shape()}
"""


def phase1_full(task) -> str:
    """Phase 1 full mode: Chroma-backed analysis using stdin diff summary."""
    cve_context = f" (CVE: {task.cve_id})" if task.cve_id else ""
    return f"""
# Phase 1: Structured Vulnerability Component Extraction {cve_context}

## Objective
Analyze the vulnerability using the preprocessed diff summary from stdin and return a structured Phase 1 JSON object.

{_phase1_input_block(task)}

### Step 1: Vulnerability Research (MANDATORY - Use Chroma MCP)
IMPORTANT: You MUST use the chroma MCP server tools to research this vulnerability. Do not proceed without using these tools:

**Stage 1 - Get CVE Context:**
Query NIST first: `mcp__chroma__chroma_get_documents(collection_name="{task.nvd_cache}", where={{"cve_id": "{task.cve_id}"}})`

**Stage 2 - Context-Driven Searches:**
Based on NIST CWE and the stdin diff summary, search relevant collections with appropriate terms.

1. **CWE patterns**:
   `mcp__chroma__chroma_query_documents(collection_name="cwe_data", query_texts=["CWE from NIST", "vulnerability type"], n_results=3)`

2. **CodeQL documentation**:
   `mcp__chroma__chroma_query_documents(collection_name="codeql_language_guides", query_texts=["terms from diff summary"], n_results=3)`

3. **Local query examples**:
   `mcp__chroma__chroma_query_documents(collection_name="codeql_local_queries", query_texts=["vulnerability category", "detection method"], n_results=3)`

4. **CodeQL reference**:
   `mcp__chroma__chroma_query_documents(collection_name="codeql_ql_reference", query_texts=["taint tracking", "dataflow"], n_results=2)`

Do not call `mcp__chroma__chroma_list_collections`.

### Step 2: Security Component Identification
Base the component extraction on:
- stdin diff summary
- Chroma vulnerability research
- local repository inspection when needed

{_phase1_analysis_task()}
"""


def phase1_no_docs(task) -> str:
    """Phase 1 no-docs/no-tools mode: stdin diff summary without Chroma."""
    cve_context = f" (CVE: {task.cve_id})" if task.cve_id else ""
    return f"""
# Phase 1: Structured Vulnerability Component Extraction {cve_context}

## Objective
Analyze the vulnerability using the preprocessed diff summary from stdin and return a structured Phase 1 JSON object.

{_phase1_input_block(task)}

{_phase1_analysis_task()}
"""


# Phase 3 initial

def phase3_full(task, use_cache: bool, collection_name: str,
                phase1_output: str = None, phase2_output: str = None) -> str:
    """Phase 3 initial prompt: full mode with Chroma + CodeQL LSP."""
    cve_context = f" (CVE: {task.cve_id})" if task.cve_id else ""
    ql_file_path = f"{os.path.abspath(task.working_dir or '.')}/{task.cve_id}-query-iter-1.ql"
    ql_file_uri = f"file://{ql_file_path}"

    if use_cache and collection_name:
        previous_analysis_section = f"""
## Previous Analysis
The results from Phase 1 are stored in Chroma.

**Collection Name:** `{collection_name}`

**IMPORTANT**:
- Only access data from `{collection_name}`
- Do not access other `cve_analysis_*` collections
- Do not call `mcp__chroma__chroma_list_collections`

{_retrieving_chroma_analysis(collection_name=collection_name)}

**AST DATA LOCATION**: `{task.ast_cache}`
"""
    else:
        previous_analysis_section = f"""
## Previous Analysis
### Phase 1 - Security Components:
{phase1_output if phase1_output else "No Phase 1 output available"}

### Phase 2 - AST Analysis:
{phase2_output if phase2_output else "No Phase 2 output available"}"""

    return f"""
# Phase 3: CodeQL Query Generation for {task.cve_id}{cve_context}

## Objective
Write a CodeQL query to detect the vulnerability pattern identified in the previous analysis.
{previous_analysis_section}

**CRITICAL path usage**
- Write tool `file_path`: `{ql_file_path}`
- CodeQL MCP `file_uri`: `{ql_file_uri}`
- Always use the full absolute path.

## Task

### Step 1: Mandatory AST retrieval
Before generating the query, retrieve and compare:
1. Vulnerable AST:
   `mcp__chroma__chroma_get_documents(collection_name="{task.ast_cache}", where={{"$and": [{{"cve_id": "{task.cve_id}"}}, {{"db_type": "vulnerable"}}]}})`
2. Fixed AST:
   `mcp__chroma__chroma_get_documents(collection_name="{task.ast_cache}", where={{"$and": [{{"cve_id": "{task.cve_id}"}}, {{"db_type": "fixed"}}]}})`
3. Use the comparison to identify patterns present only in vulnerable code and patterns added in the fix.

### Step 2: Retrieve reference material
Use Chroma only from the allowed reference collections:
- `cwe_data`
- `codeql_language_guides`
- `codeql_local_queries`
- `codeql_ql_reference`
- `codeql_java_stdlib`

### Step 3: Write the query
Create a complete CodeQL query and save it with `Write`.
You must write the query yourself. Do not import a prebuilt query. `import *Query` is not allowed.
Keep the query in `@kind path-problem` form.

{_query_skeleton()}

### Step 4: Validate with CodeQL MCP
After writing the query:
1. Open it with `mcp__codeql__codeql_update_file`
2. Run `mcp__codeql__codeql_diagnostics`
3. If needed, use:
   - `mcp__codeql__codeql_hover`
   - `mcp__codeql__codeql_complete`
   - `mcp__codeql__codeql_definition`
   - `mcp__codeql__codeql_references`
4. Run `mcp__codeql__codeql_format`
5. Save the final query again with `Write`

### Modeling reminders
- Sources: where untrusted data enters
- Sinks: where that data is used dangerously
- Sanitizers: checks added in the fix that should block the flow
- Additional taint steps: intermediate transfers that preserve dangerous data

### Completion Checklist
- The query kind is `path-problem`
- The final `.ql` file is saved with `Write`
- `mcp__codeql__codeql_diagnostics` reports no blocking errors
- The final response contains only the exact absolute path line

{_stop_block_initial(ql_file_path)}
"""


def phase3_no_tools(task, phase1_output: str = "") -> str:
    """Phase 3 initial prompt: no_tools mode (no MCP)."""
    cve_context = f" (CVE: {task.cve_id})" if task.cve_id else ""
    ql_file_path = f"{os.path.abspath(task.working_dir or '.')}/{task.cve_id}-query-iter-1.ql"
    return f"""
# CodeQL Template Generation and Refinement{cve_context}

**CRITICAL path usage**
- Write tool `file_path`: `{ql_file_path}`
- Do not leave this directory. Do not inspect other benchmark metadata files.

## Objective
Generate a complete CodeQL query based on the available analysis.

## Previous Analysis
{phase1_output if phase1_output else "No Phase 1 output available"}

## Task
1. Create a complete query based on the analysis.
2. Keep it in `@kind path-problem` form.
3. Save it with `Write`.
4. Stop immediately after the file is written.

{_query_skeleton()}

### Completion Checklist
- The query kind is `path-problem`
- The final `.ql` file is saved with `Write`
- The final response contains only the exact absolute path line

{_stop_block_initial(ql_file_path)}"""


def phase3_no_lsp(task, use_cache: bool, collection_name: str) -> str:
    """Phase 3 initial prompt: no_lsp mode (Chroma only, no CodeQL LSP)."""
    cve_context = f" (CVE: {task.cve_id})" if task.cve_id else ""
    ql_file_path = f"{os.path.abspath(task.working_dir or '.')}/{task.cve_id}-query-iter-1.ql"
    if use_cache and collection_name:
        previous_analysis_section = f"""
## Previous Analysis
The results from Phase 1 are stored in Chroma.

**Collection Name:** `{collection_name}`

**IMPORTANT**:
- Only access data from `{collection_name}`
- Do not access other `cve_analysis_*` collections
- Do not call `mcp__chroma__chroma_list_collections`

{_retrieving_chroma_analysis(collection_name=collection_name)}

**AST DATA LOCATION**: `{task.ast_cache}`
"""
    else:
        previous_analysis_section = ""

    return f"""
# Phase 3: CodeQL Query Generation for {task.cve_id}{cve_context}

## Objective
Write a CodeQL query using Chroma context and AST comparison, without CodeQL LSP tools.
{previous_analysis_section}

**CRITICAL path usage**
- Write tool `file_path`: `{ql_file_path}`

## Task
1. Retrieve vulnerable and fixed AST from `{task.ast_cache}` and compare them.
2. Retrieve relevant Phase 1 sections from `{collection_name}`.
3. Use allowed reference collections for guidance.
4. Write a complete query and save it with `Write`.

{_query_skeleton()}

### Completion Checklist
- The query kind is `path-problem`
- The final `.ql` file is saved with `Write`
- The final response contains only the exact absolute path line

{_stop_block_initial(ql_file_path)}"""


def phase3_no_docs(task, use_cache: bool, collection_name: str) -> str:
    """Phase 3 initial prompt: no_docs mode (AST + LSP, no Chroma docs)."""
    cve_context = f" (CVE: {task.cve_id})" if task.cve_id else ""
    ql_file_path = f"{os.path.abspath(task.working_dir or '.')}/{task.cve_id}-query-iter-1.ql"
    ql_file_uri = f"file://{ql_file_path}"
    if use_cache and collection_name:
        previous_analysis_section = f"""
## Previous Analysis
The results from Phase 1 are stored in Chroma.

**Collection Name:** `{collection_name}`

**IMPORTANT**:
- Only access data from `{collection_name}`
- Do not access other `cve_analysis_*` collections
- Do not call `mcp__chroma__chroma_list_collections`

{_retrieving_chroma_analysis(collection_name=collection_name)}

**AST DATA LOCATION**: `{task.ast_cache}`
"""
    else:
        previous_analysis_section = ""

    return f"""
# Phase 3: CodeQL Query Generation for {task.cve_id}{cve_context}

## Objective
Write a CodeQL query using AST comparison and CodeQL LSP tools, without additional Chroma documentation lookups.
{previous_analysis_section}

**CRITICAL path usage**
- Write tool `file_path`: `{ql_file_path}`
- CodeQL MCP `file_uri`: `{ql_file_uri}`

## Task
1. Retrieve and compare vulnerable/fixed AST from `{task.ast_cache}`.
2. Use the Phase 1 context already stored in `{collection_name}`.
3. Write the query and save it with `Write`.
4. Validate with CodeQL MCP tools.
5. Save the final query again with `Write`.

{_query_skeleton()}

### Completion Checklist
- The query kind is `path-problem`
- The final `.ql` file is saved with `Write`
- `mcp__codeql__codeql_diagnostics` reports no blocking errors
- The final response contains only the exact absolute path line

{_stop_block_initial(ql_file_path)}"""


def phase3_no_ast(task, use_cache: bool, collection_name: str) -> str:
    """Phase 3 initial prompt: no_ast mode (Chroma docs + LSP, no AST retrieval)."""
    cve_context = f" (CVE: {task.cve_id})" if task.cve_id else ""
    ql_file_path = f"{os.path.abspath(task.working_dir or '.')}/{task.cve_id}-query-iter-1.ql"
    ql_file_uri = f"file://{ql_file_path}"
    if use_cache and collection_name:
        previous_analysis_section = f"""
## Previous Analysis
The results from Phase 1 are stored in Chroma.

**Collection Name:** `{collection_name}`

**IMPORTANT**:
- Only access data from `{collection_name}`
- Do not access other `cve_analysis_*` collections
- Do not call `mcp__chroma__chroma_list_collections`

{_retrieving_chroma_analysis(collection_name=collection_name)}
"""
    else:
        previous_analysis_section = ""

    return f"""
# Phase 3: CodeQL Query Generation for {task.cve_id}{cve_context}

## Objective
Write a CodeQL query using Phase 1 context and reference documentation, without AST retrieval.
{previous_analysis_section}

**CRITICAL path usage**
- Write tool `file_path`: `{ql_file_path}`
- CodeQL MCP `file_uri`: `{ql_file_uri}`

## Task
1. Retrieve the relevant Phase 1 sections from `{collection_name}`.
2. Use only the allowed reference collections for documentation and examples.
3. Write the query and save it with `Write`.
4. Validate with CodeQL MCP tools and save the final query again.

{_query_skeleton()}

### Completion Checklist
- The query kind is `path-problem`
- The final `.ql` file is saved with `Write`
- `mcp__codeql__codeql_diagnostics` reports no blocking errors
- The final response contains only the exact absolute path line

{_stop_block_initial(ql_file_path)}"""


def refinement_full(task, previous_feedback: str, iteration: int, collection_name: str) -> str:
    ql_file_path = f"{os.path.abspath(task.working_dir or '.')}/{task.cve_id}-query-iter-{iteration}.ql"
    ql_file_uri = f"file://{ql_file_path}"
    return f"""# Phase 3 Query Refinement - Iteration {iteration}

**CRITICAL path usage**
- Write tool `file_path`: `{ql_file_path}`
- CodeQL MCP `file_uri`: `{ql_file_uri}`
- Always use the full absolute path.

## Objective
Refine the CodeQL query based on previous iteration feedback.

## Previous Iteration Feedback
{previous_feedback or "No previous feedback available"}

## Collection Name
`{collection_name}`

## Task
1. Analyze what went wrong in the previous iteration.
2. Retrieve the Phase 1 sections from `{collection_name}`.
3. Retrieve vulnerable and fixed AST from `{task.ast_cache}`.
4. Update the query with `Write`.
5. Validate with:
   - `mcp__codeql__codeql_update_file`
   - `mcp__codeql__codeql_diagnostics`
   - `mcp__codeql__codeql_hover`
   - `mcp__codeql__codeql_complete`
   - `mcp__codeql__codeql_definition`
   - `mcp__codeql__codeql_references`
   - `mcp__codeql__codeql_format`
6. Save the final query again with `Write`.

## Important Reminders
- Keep the query in `@kind path-problem` form
- Improve the existing logic rather than replacing it with a much simpler query
- The query should find true positives in the vulnerable database and avoid true positives in the fixed database
- Do not call `mcp__chroma__chroma_list_collections`

## Completion Checklist
- The final `.ql` file is saved with `Write`
- `mcp__codeql__codeql_diagnostics` reports no blocking errors
- The final response contains only the exact absolute path line

{_stop_block_refinement(task, iteration)}"""


def refinement_no_tools(task, previous_feedback: str, iteration: int) -> str:
    ql_file_path = f"{os.path.abspath(task.working_dir or '.')}/{task.cve_id}-query-iter-{iteration}.ql"
    return f"""Query Refinement - Iteration {iteration}

**CRITICAL path usage**
- Write tool `file_path`: `{ql_file_path}`
- Do not leave this directory. Do not inspect other benchmark metadata files.

## Objective
Refine the CodeQL query based on previous iteration feedback.

## Previous Iteration Feedback
{previous_feedback or "No previous feedback available"}

## Task
1. Analyze what went wrong.
2. Update the query with `Write`.
3. Keep the query in `@kind path-problem` form.
4. Stop immediately after writing the file.

## Important Reminders
- The query should find results in the vulnerable database and avoid results in the fixed database
- Fix compilation issues reported in the feedback

## Completion Checklist
- The final `.ql` file is saved with `Write`
- The final response contains only the exact absolute path line

{_stop_block_refinement(task, iteration)}"""


def refinement_no_lsp(task, previous_feedback: str, iteration: int, collection_name: str) -> str:
    ql_file_path = f"{os.path.abspath(task.working_dir or '.')}/{task.cve_id}-query-iter-{iteration}.ql"
    return f"""# Phase 3 Query Refinement - Iteration {iteration}

**CRITICAL path usage**
- Write tool `file_path`: `{ql_file_path}`

## Objective
Refine the CodeQL query based on previous iteration feedback, without CodeQL LSP tools.

## Previous Iteration Feedback
{previous_feedback or "No previous feedback available"}

## Collection Name
`{collection_name}`

## Task
1. Analyze what went wrong in the previous iteration.
2. Retrieve Phase 1 sections from `{collection_name}`.
3. Retrieve vulnerable and fixed AST from `{task.ast_cache}`.
4. Use allowed Chroma reference collections for guidance.
5. Update the query with `Write` and stop.

## Important Reminders
- Keep the query in `@kind path-problem` form
- The query should find true positives in the vulnerable database and avoid true positives in the fixed database
- Do not call `mcp__chroma__chroma_list_collections`

## Completion Checklist
- The final `.ql` file is saved with `Write`
- The final response contains only the exact absolute path line

{_stop_block_refinement(task, iteration)}"""


def refinement_no_docs(task, previous_feedback: str, iteration: int, collection_name: str) -> str:
    ql_file_path = f"{os.path.abspath(task.working_dir or '.')}/{task.cve_id}-query-iter-{iteration}.ql"
    ql_file_uri = f"file://{ql_file_path}"
    return f"""# Phase 3 Query Refinement - Iteration {iteration}

**CRITICAL path usage**
- Write tool `file_path`: `{ql_file_path}`
- CodeQL MCP `file_uri`: `{ql_file_uri}`
- Always use the full absolute path.

## Objective
Refine the CodeQL query based on previous iteration feedback, using AST and CodeQL LSP but without additional documentation lookups.

## Previous Iteration Feedback
{previous_feedback or "No previous feedback available"}

## Collection Name
`{collection_name}`

## Task
1. Analyze what went wrong in the previous iteration.
2. Retrieve Phase 1 sections from `{collection_name}`.
3. Retrieve vulnerable and fixed AST from `{task.ast_cache}`.
4. Update the query with `Write`.
5. Validate with CodeQL MCP tools.
6. Save the final query again with `Write`.

## Important Reminders
- Keep the query in `@kind path-problem` form
- The query should find true positives in the vulnerable database and avoid true positives in the fixed database
- Do not call `mcp__chroma__chroma_list_collections`

## Completion Checklist
- The final `.ql` file is saved with `Write`
- `mcp__codeql__codeql_diagnostics` reports no blocking errors
- The final response contains only the exact absolute path line

{_stop_block_refinement(task, iteration)}"""


def refinement_no_ast(task, previous_feedback: str, iteration: int, collection_name: str) -> str:
    ql_file_path = f"{os.path.abspath(task.working_dir or '.')}/{task.cve_id}-query-iter-{iteration}.ql"
    ql_file_uri = f"file://{ql_file_path}"
    return f"""# Phase 3 Query Refinement - Iteration {iteration}

**CRITICAL path usage**
- Write tool `file_path`: `{ql_file_path}`
- CodeQL MCP `file_uri`: `{ql_file_uri}`
- Always use the full absolute path.

## Objective
Refine the CodeQL query based on previous iteration feedback, using Phase 1 context and CodeQL LSP without AST retrieval.

## Previous Iteration Feedback
{previous_feedback or "No previous feedback available"}

## Collection Name
`{collection_name}`

## Task
1. Analyze what went wrong in the previous iteration.
2. Retrieve Phase 1 sections from `{collection_name}`.
3. Use allowed Chroma reference collections for guidance.
4. Update the query with `Write`.
5. Validate with CodeQL MCP tools.
6. Save the final query again with `Write`.

## Important Reminders
- Keep the query in `@kind path-problem` form
- The query should find true positives in the vulnerable database and avoid true positives in the fixed database
- Do not call `mcp__chroma__chroma_list_collections`

## Completion Checklist
- The final `.ql` file is saved with `Write`
- `mcp__codeql__codeql_diagnostics` reports no blocking errors
- The final response contains only the exact absolute path line

{_stop_block_refinement(task, iteration)}"""

