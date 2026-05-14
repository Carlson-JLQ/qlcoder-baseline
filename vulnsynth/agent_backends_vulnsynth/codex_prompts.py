"""Codex-specific prompt functions for all ablation modes.

"""
import os

from .prompt_helpers import query_skeleton as _query_skeleton
from .prompt_helpers import source_sink_taint_examples as _source_sink_taint_examples
from .prompt_helpers import phase1_expected_output as _phase1_expected_output

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


def phase1_no_tools(task) -> str:
    """Phase 1 no_tools mode: stdin diff summary, no Chroma."""
    cve_context = f" (CVE: {task.cve_id})" if task.cve_id else ""
    return f"""
# Phase 1: Structured Vulnerability Component Extraction {cve_context}

## Objective
Analyze the vulnerability using the preprocessed diff summary from stdin and return a structured Phase 1 JSON object.

{_phase1_input_block(task)}

{_phase1_analysis_task()}
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
Query NIST first: `chroma_get_documents(collection_name="{task.nvd_cache}", where={{"cve_id": "{task.cve_id}"}})`

**Stage 2 - Context-Driven Searches:**
Based on NIST CWE and the stdin diff summary, search relevant collections with appropriate terms.

1. **CWE patterns**:
   `chroma_query_documents(collection_name="cwe_data", query_texts=["CWE from NIST", "vulnerability type"], n_results=3)`

2. **CodeQL documentation**:
   `chroma_query_documents(collection_name="codeql_language_guides", query_texts=["terms from diff summary"], n_results=3)`

3. **Local query examples**:
   `chroma_query_documents(collection_name="codeql_local_queries", query_texts=["vulnerability category", "detection method"], n_results=3)`

4. **CodeQL reference**:
   `chroma_query_documents(collection_name="codeql_ql_reference", query_texts=["taint tracking", "dataflow"], n_results=2)`

Do not call `chroma_list_collections`.

### Step 2: Security Component Identification
Base the component extraction on:
- stdin diff summary
- Chroma vulnerability research
- local repository inspection when needed

{_phase1_analysis_task()}
"""


# Phase 3 initial

def phase3_no_tools(task, phase1_output: str = "") -> str:
    """Phase 3 initial prompt: no_tools mode (no MCP)."""
    ql_file_path = f"{task.working_dir or '.'}/{task.cve_id}-query-iter-1.ql"
    cve_context = f" (CVE: {task.cve_id})" if task.cve_id else ""
    return f"""
# CodeQL Template Generation and Refinement {cve_context}

**CRITICAL: When calling Write tool this file path format:**
**Write tool file_path: "{ql_file_path}"**

## Objective
Generate a complete CodeQL query based on the analysis and AST patterns, then iteratively refine it.

## Previous Analysis
{phase1_output if phase1_output else "No Phase 1 output available"}

## Task

### Step 1: Template Generation
Create a CodeQL query based given the former vulnerability analysis. You MUST use the Write tool to save the query file.
{_query_skeleton()}

### Step 2: Write Complete CodeQL Query

**PRIMARY GOAL: Write a complete, working CodeQL query.**

Stick to @kind path-problem query structure.
1. **Write the full query skeleton** based on the analysis
2. **Save as**: `{ql_file_path}` using the Write tool

**REMEMBER: The vulnerability is the ABSENCE of proper validation:**
- Sources: Where untrusted data enters (user input, file names, etc.)
- Sinks: Where that data is used dangerously (file operations, path resolution)
- Sanitizers: Validation that was ADDED in the fix to block the flow
- Additional taint steps: Any intermediate code that receives tainted data, transforms or moves it, and passes it along while preserving its dangerous properties

**YOUR ONLY TASK**: Create the initial CodeQL query based on the analysis. The automated system will handle testing, refinement, and iteration.

## Expected Output
**ONLY CREATE THE INITIAL CODEQL QUERY** - Do not run it, test it, or refine it. Just create it and stop.

Focus on creating a query that accurately detects the vulnerability pattern while minimizing false positives!

## CRITICAL: MANDATORY Write Tool Usage

**BEFORE STOPPING**: You MUST use the Write tool to save your final query to disk:
- **Tool**: `Write`
- **File path**: `{ql_file_path}`
- **Content**: Your complete CodeQL query

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


def phase3_full(task, use_cache: bool, collection_name: str) -> str:
    """Phase 3 initial prompt: full mode with Chroma + CodeQL LSP.

    """
    abs_working_dir = os.path.abspath(task.working_dir or ".")
    ql_file_path = f"{abs_working_dir}/{task.cve_id}-query-iter-1.ql"
    ql_file_uri = f"file://{ql_file_path}"
    if use_cache and collection_name:
        previous_analysis_section = f"""
## Previous Analysis
The results from Phase 1 Chroma in a run-specific collection.

**Collection Name:** `{collection_name}`

**IMPORTANT**: 
- Only access data from collection `{collection_name}`

### Retrieving Phase 1 Results:
Use `chroma_get_documents` with collection_name="{collection_name}" and:
- `where: {{"section": "sources"}}` - Source patterns
- `where: {{"section": "sinks"}}` - Sink patterns
- `where: {{"section": "sanitizers"}}` - Sanitizer patterns
- `where: {{"section": "additional_taint_steps"}}` - Additional taint step patterns
- `where: {{"section": "vulnerability_analysis_summary"}}` - Vulnerability analysis summary
- `where: {{"section": "cve_info"}}` - CVE information from NIST

Example:
```
chroma_get_documents(
    collection_name="{collection_name}",
    where={{"section": "sources"}},
    limit=1
)
```
"""
    return f"""
# Phase 3: CodeQL Query Generation for {task.cve_id}

## Objective
Write a CodeQL query to detect the vulnerability pattern identified in the previous security analysis. The analysis results have been stored in ChromaDB and need to be retrieved to inform your query implementation.
{previous_analysis_section}

**CRITICAL: When calling Write tool and CodeQL MCP tools, use these file path formats:**
**Write tool file_path: "{ql_file_path}"**
**CodeQL MCP file_uri: "{ql_file_uri}"**
**Use the FULL ABSOLUTE PATH to ensure the file can be found by CodeQL MCP tools.**

## Task
Using the Chroma MCP server for documentation and CodeQL query examples, and CodeQL MCP server for CodeQL development:

### Step 1: MANDATORY AST Retrieval and Comparison
**BEFORE generating any CodeQL query, you MUST:**
1. Retrieve the vulnerable AST: `chroma_get_documents(collection_name="{task.ast_cache}", where={{"$and": [{{"cve_id": "{task.cve_id}"}}, {{"db_type": "vulnerable"}}]}})` 
2. Retrieve the fixed AST: `chroma_get_documents(collection_name="{task.ast_cache}", where={{"$and": [{{"cve_id": "{task.cve_id}"}}, {{"db_type": "fixed"}}]}})`
3. Compare the AST structures to identify:
   - What patterns exist in vulnerable code but NOT in fixed code
   - What new patterns were added in the fixed code
   - The exact AST node types and relationships that changed
4. Use this comparison to inform your source, sink, and sanitizer definitions

## Step 2: Query Template Generation
Create a CodeQL query based on the AST comparison analysis. Look up similar existing queries from the allowed reference collections (cwe_data, codeql_language_guides, codeql_local_queries, codeql_ql_reference, codeql_java_stdlib) - DO NOT search cve_analysis_* collections:

{_query_skeleton()}

### Step 3: Create Initial CodeQL Query
1. **Write the complete query** to `{ql_file_path}` using the `Write` tool.
2. **Open it in the CodeQL LSP** with `codeql_update_file`.
3. **Run diagnostics** with `codeql_diagnostics`.
4. **If there are errors**, use the LSP tools to fix them:
   - `codeql_hover` for types and signatures
   - `codeql_complete` for syntax help
   - `codeql_format` after edits
   - repeat `codeql_diagnostics` until clean
5. **For implementation guidance**, look up patterns as you write:
   - **CodeQL Java syntax**: `chroma_query_documents(collection_name="codeql_java_stdlib", query_texts=["[ClassName methodName]"], n_results=2)`
   - **CodeQL examples**: `chroma_query_documents(collection_name="codeql_language_guides", query_texts=["[specific pattern]"], n_results=3)`
   - **Similar queries**: `chroma_query_documents(collection_name="codeql_local_queries", query_texts=["[vulnerability category]"], n_results=3)`
   - **QL syntax**: `chroma_query_documents(collection_name="codeql_ql_reference", query_texts=["[syntax concept]"], n_results=2)`
6. **Final format pass** with `codeql_format` before finishing.

**REMEMBER: The vulnerability is the ABSENCE of proper validation:**
- Sources: Where untrusted data enters (user input, file names, etc.)
- Sinks: Where that data is used dangerously (file operations, path resolution)
- Sanitizers: Validation that was ADDED in the fix to block the flow
- Additional taint steps: Any intermediate code that receives tainted data, transforms or moves it, and passes it along while preserving its dangerous properties

### Completion Checklist
- The query kind is `path-problem`
- The final `.ql` file is saved with `Write`
- `codeql_diagnostics` reports no blocking errors
- The final response contains only the exact absolute path line

## CRITICAL: STOP EXECUTION IMMEDIATELY 
**IMPORTANT**: LSP tools only update the in-memory representation. The Write tool is required to persist the file to disk for the automated system to find it.
**MANDATORY**: Once you have successfully written a .ql query file, you MUST STOP execution immediately and provide the file path.

**REQUIRED FINAL OUTPUT**: After writing the .ql file, your last message must be:
```
QUERY_FILE_PATH: {ql_file_path}
```

**STOP AS SOON AS THE .ql FILE IS WRITTEN** - This prevents context window bloat and enables iterative refinement.
"""


# Refinement prompts

def refinement_no_tools(task, previous_feedback: str, iteration: int) -> str:
    ql_file_path = f"{os.path.abspath(task.working_dir or '.')}/{task.cve_id}-query-iter-{iteration}.ql"
    return f"""Query Refinement - Iteration {iteration}

**CRITICAL: When calling Write tool, use this file path format:**
**file_path: "{ql_file_path}"**

## Objective
Refine the CodeQL query based on previous iteration feedback to improve vulnerability detection.

## Previous Iteration Feedback
{previous_feedback or "No previous feedback available"}

## Task
1. **Analyze the previous results** to understand what went wrong. Stick to @kind path-problem query structure.
2. **Refine the query** to address the issues identified. Improve existing predicates rather than simplifying the overall approach.

   **PRACTICAL CodeQL Development Process**:
   - **STEP 1**: **CREATE THE QUERY FILE**: Use `Write` tool to create/update `{ql_file_path}` with your improved query
   - **STEP 2**: **FOCUS ON COMPLETING THE QUERY**:
     - Read the existing query and understand what needs to be changed
     - Make the necessary improvements to fix the issues identified in feedback
     - **Write complete logic** - don't get stuck validating every line

   **KEY PRINCIPLES**:
   - **ALWAYS use Write tool to save the .ql file**
   - **Complete the query first, validate second**

3. **CRITICAL: You MUST use Write tool to save the final query** as `{ql_file_path}`
   - **File path**: `{task.cve_id}-query-iter-{iteration}.ql` (NOT "/path/to/{task.cve_id}-query-{iteration}.ql")

## Important Reminders
- Query MUST find results in vulnerable database
- Query MUST NOT find results (or fewer) in fixed database
- Focus on hitting the target methods/files if feedback shows misses
- Fix compilation errors if any were reported
- Adjust source/sink/sanitizer patterns based on execution results

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


def refinement_full(task, previous_feedback: str, iteration: int, collection_name: str) -> str:
    abs_working_dir = os.path.abspath(task.working_dir or ".")
    ql_file_path = f"{abs_working_dir}/{task.cve_id}-query-iter-{iteration}.ql"
    ql_file_uri = f"file://{ql_file_path}"
    return f"""# Phase 3 Query Refinement - Iteration {iteration}

**CRITICAL: When calling Write tool and CodeQL MCP tools, use these file path formats:**
**Write tool file_path: "{ql_file_path}"**
**CodeQL MCP file_uri: "{ql_file_uri}"**
**Use the FULL ABSOLUTE PATH to ensure the file can be found by CodeQL MCP tools.**

## Objective
Refine the CodeQL query based on previous iteration feedback to improve vulnerability detection.

## Previous Iteration Feedback
{previous_feedback or "No previous feedback available"}

## Collection Name: `{collection_name}`

## Your Task
1. **Analyze what went wrong** in the previous iteration

2. **Retrieve context from ChromaDB** (use EXACTLY these commands):
   - Sources: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "sources"}})`
   - Sinks: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "sinks"}})`
   - Sanitizers: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "sanitizers"}})`
   - Additional taint steps: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "additional_taint_steps"}})`
   - Vulnerability summary: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "vulnerability_analysis_summary"}})`
   - CVE info: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "cve_info"}})`
   - Vulnerable AST: `chroma_get_documents(collection_name="{task.ast_cache}", where={{"$and": [{{"cve_id": "{task.cve_id}"}}, {{"db_type": "vulnerable"}}]}})`
   - Fixed AST: `chroma_get_documents(collection_name="{task.ast_cache}", where={{"$and": [{{"cve_id": "{task.cve_id}"}}, {{"db_type": "fixed"}}]}})`

3. **Refine the query** to address the issues identified. Improve existing predicates rather than simplifying the overall approach. Each refinement should make the analysis more accurate, not simpler.
   ** PRACTICAL CodeQL Development Process**:
   - **STEP 1**: **CREATE THE QUERY FILE**: Use `Write` tool to create/update `{ql_file_path}` with your improved query
   - **STEP 2**: **VALIDATE WITH LSP (Optional)**: 
     - Open with LSP: `codeql_update_file` (for validation only, NOT file creation)
     - Check errors: `codeql_diagnostics`
     - **IF ERRORS**: Use `codeql_hover`, `codeql_complete` for help, then **update with Write tool again**
     - Format: `codeql_format` (optional)
   - **STEP 3**: **FOCUS ON COMPLETING THE QUERY**:
     - Read the existing query and understand what needs to be changed
     - Make the necessary improvements to fix the issues identified in feedback
     - **Write complete logic** - don't get stuck validating every line
   - **STEP 4**: **USE LSP TOOLS FOR HELP (Not File Creation)**:
     - **When you need help**: Use `codeql_complete` for auto-completion
     - **When confused**: Use `codeql_hover` on elements for documentation
     - **For library methods**: Use `codeql_definition` on CodeQL library types (like `MethodCall`, `TryStmt`) - NOT on user variables
     - **For examples**: Use `codeql_references` on library predicates or `chroma_query_documents`

   ** KEY PRINCIPLES**:
   - **ALWAYS use Write tool to save the .ql file** - LSP tools only validate, they don't save files
   - **Complete the query first, validate second**
   - **Use tools when helpful, not as mandatory checkpoints** 
   - **`definition` works on**: CodeQL library classes/methods (e.g., `TryStmt`, `MethodCall`, `getMethod()`)
   - **`definition` doesn't work on**: imports, user variables, keywords
   - **Don't let tool usage block query completion**
   - **For implementation guidance**: Actively look up patterns as you write:
     - CodeQL Java syntax: `chroma_query_documents(collection_name="codeql_java_stdlib", query_texts=["[ClassName methodName]"], n_results=2)`
     - CodeQL examples: `chroma_query_documents(collection_name="codeql_language_guides", query_texts=["[specific pattern]"], n_results=3)`
     - Similar queries: `chroma_query_documents(collection_name="codeql_local_queries", query_texts=["[vulnerability category]"], n_results=3)`
     - QL syntax: `chroma_query_documents(collection_name="codeql_ql_reference", query_texts=["[syntax concept]"], n_results=2)`
4. **CRITICAL: After all LSP work, MUST use Write tool to save the final query** as `{ql_file_path}`
   - **IMPORTANT**: LSP tools only update the in-memory representation - they don't save files to disk
   - You MUST use the `Write` tool at the end to persist the query file
   - **File path**: `{ql_file_path}`
**DO NOT call `chroma_list_collections`**

## Completion Checklist
- Keep the query in `@kind path-problem` form
- Save the final `.ql` file with `Write`
- Run `codeql_diagnostics` before finishing
- End with the exact absolute `QUERY_FILE_PATH` line

## CRITICAL: STOP EXECUTION IMMEDIATELY 
**MANDATORY**: Once you have successfully written a .ql query file, you MUST STOP execution immediately and provide the file path.

**REQUIRED FINAL OUTPUT**:
```
QUERY_FILE_PATH: {ql_file_path}
```
The automated system will take over to compile and evaluate.
"""
