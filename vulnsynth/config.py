import os
from dotenv import load_dotenv
try:
    import chromadb
except ImportError:  # pragma: no cover - optional at import time
    chromadb = None
load_dotenv()

VULNSYNTH_ROOT_DIR = os.path.join(os.path.dirname(__file__), "..")


    

PROJECT_INFO = f"{VULNSYNTH_ROOT_DIR}/data/project_info.csv"
FIX_INFO = f"{VULNSYNTH_ROOT_DIR}/data/fix_info.csv"
CVES_PATH = f"{VULNSYNTH_ROOT_DIR}/cves"
LOGS_DIR = f"{VULNSYNTH_ROOT_DIR}/logs"
QUERIES_PATH = f"{VULNSYNTH_ROOT_DIR}/src/queries"
# CVES_PATH = f"{VULNSYNTH_ROOT_DIR}/cves"
FIX_INFO=f"{VULNSYNTH_ROOT_DIR}/data/fix_info.csv"
QUERIES_PATH = f"{VULNSYNTH_ROOT_DIR}/src/queries" 
NVD_CACHE="nist_cve_cache"


AST_CACHE = "cve_ast_cache"
BUILD_INFO = f"{VULNSYNTH_ROOT_DIR}/data/build_info.csv"
CVE_DESCRIPTIONS_FILE = f"{VULNSYNTH_ROOT_DIR}/data/cve_descriptions.json"

CODEQL_HOME = os.environ.get("CODEQL_HOME")
CODEQL_PATH = os.environ.get("CODEQL_PATH", f"{CODEQL_HOME}/codeql")
CODEQL_LSP_MCP_PATH = os.environ.get("CODEQL_LSP_MCP_PATH", "/path/to/codeql-lsp-mcp")


JAVA_SECURITY_QLPACK_PATH= os.environ.get("JAVA_SECURITY_QLPACK_PATH", f"{CODEQL_HOME}/qlpacks/codeql/java-queries/")
JAVA_LIBRARY_QLPACK_PATH = os.environ.get("JAVA_LIBRARY_QLPACK_PATH", f"{CODEQL_HOME}/qlpacks/codeql/java-all/")

CPP_SECURITY_QLPACK_PATH = os.environ.get("CPP_SECURITY_QLPACK_PATH", f"{CODEQL_HOME}/qlpacks/codeql/cpp-queries/")

CPP_LIBRARY_QLPACK_PATH = os.environ.get("CPP_LIBRARY_QLPACK_PATH", f"{CODEQL_HOME}/qlpacks/codeql/cpp-all/")



# chroma db collection for retrieving CVE descriptions 
NVD_CACHE="nist_cve_cache"
# chroma db collection for retrieving ASTs of CVE diffs. 
AST_CACHE = "cve_ast_cache"


# ChromaDB connection settings
# Set CHROMA_HOST to use HTTP client (Docker/remote), unset for local PersistentClient
CHROMA_HOST = os.environ.get("CHROMA_HOST", None)
CHROMA_PORT = int(os.environ.get("CHROMA_PORT", "8000"))
CHROMA_AUTH_TOKEN = os.environ.get("CHROMA_AUTH_TOKEN", "test")
CHROMA_DB_PATH = os.environ.get("CHROMA_DB_PATH",os.path.join(VULNSYNTH_ROOT_DIR,  "data", "chroma_db"))

CHROMA_MCP_PATH='mcp__chroma__'  # Prefix for MCP tool calls to ChromaDB in prompts
def get_chroma_client():
    """Return a ChromaDB client based on environment configuration.

    - If CHROMA_HOST is set: returns HttpClient (for Docker / remote ChromaDB server)
    - Otherwise: returns PersistentClient (for local development)
    """
    if chromadb is None:
        raise ImportError("chromadb is required to create a Chroma client")
    if CHROMA_HOST:
        return chromadb.HttpClient(
            host=CHROMA_HOST,
            port=CHROMA_PORT,
            headers={"Authorization": f"Bearer {CHROMA_AUTH_TOKEN}"} if CHROMA_AUTH_TOKEN else None,
        )
    else:
        os.makedirs(CHROMA_DB_PATH, exist_ok=True)
      
        return chromadb.PersistentClient(path=CHROMA_DB_PATH)
