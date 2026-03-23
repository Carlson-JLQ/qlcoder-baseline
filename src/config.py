import os
import chromadb
from dotenv import load_dotenv

load_dotenv()

QL_CODER_ROOT_DIR = os.path.join(os.path.dirname(__file__), "..")
# path to vulnerable and fixed CodeQL databases for CVEs 
CVES_PATH = f"{QL_CODER_ROOT_DIR}/cves"
LOGS_DIR = f"{QL_CODER_ROOT_DIR}/logs"
# contains Java CVE project fix metadata. Adapted from CWE-Bench-Java 
FIX_INFO=f"{QL_CODER_ROOT_DIR}/data/fix_info.csv"
# contains Java CVE project metadata. Adapted from CWE-Bench-Java
PROJECT_INFO = f"{QL_CODER_ROOT_DIR}/data/project_info.csv"
CVE_DESCRIPTIONS_FILE = f"{QL_CODER_ROOT_DIR}/data/cve_descriptions.json"
QUERIES_PATH = f"{QL_CODER_ROOT_DIR}/src/queries" 
BUILD_INFO = f"{QL_CODER_ROOT_DIR}/data/build_info.csv"
# chroma db collection for retrieving CVE descriptions 
NVD_CACHE="nist_cve_cache"
# chroma db collection for retrieving ASTs of CVE diffs. 
AST_CACHE = "cve_ast_cache"
# path to CodeQL security qlpack. Depending on your CodeQL version, use the [language]-queries version for the security QLpack path - path/to/codeql/qlpacks/codeql/java-queries/[version number]
_CODEQL_HOME = os.environ.get("CODEQL_HOME", "/path/to/codeql")
SECURITY_QLPACK_PATH = os.environ.get(
    "SECURITY_QLPACK_PATH",
    f"{_CODEQL_HOME}/qlpacks/codeql/java-queries/1.6.1/Security/CWE",
)
# path to CodeQL library qlpack. Depending on your CodeQL version, use the [language]-all version for the language library QLpack path - path/to/codeql/qselpacks/codeql/java-all/[version number]
LIBRARY_QLPACK_PATH = os.environ.get(
    "LIBRARY_QLPACK_PATH",
    f"{_CODEQL_HOME}/qlpacks/codeql/java-all/7.4.0/semmle/code/java",
)
CODEQL_LSP_MCP_PATH = os.environ.get("CODEQL_LSP_MCP_PATH", "/path/to/codeql-lsp-mcp")
CODEQL_PATH = os.environ.get("CODEQL_PATH", f"{_CODEQL_HOME}/codeql")
# ChromaDB connection settings
# Set CHROMA_HOST to use HTTP client (Docker/remote), unset for local PersistentClient
CHROMA_HOST = os.environ.get("CHROMA_HOST", None)
CHROMA_PORT = int(os.environ.get("CHROMA_PORT", "8000"))
CHROMA_AUTH_TOKEN = os.environ.get("CHROMA_AUTH_TOKEN", "test")
CHROMA_DB_PATH = os.environ.get(
    "CHROMA_DB_PATH",
    os.path.join(QL_CODER_ROOT_DIR, "data", "chroma_db")
)

def get_chroma_client() -> chromadb.ClientAPI:
    """Return a ChromaDB client based on environment configuration.

    - If CHROMA_HOST is set: returns HttpClient (for Docker / remote ChromaDB server)
    - Otherwise: returns PersistentClient (for local development)
    """
    if CHROMA_HOST:
        return chromadb.HttpClient(
            host=CHROMA_HOST,
            port=CHROMA_PORT,
            headers={"Authorization": f"Bearer {CHROMA_AUTH_TOKEN}"} if CHROMA_AUTH_TOKEN else None,
        )
    else:
        os.makedirs(CHROMA_DB_PATH, exist_ok=True)
        return chromadb.PersistentClient(path=CHROMA_DB_PATH)