from __future__ import annotations

import argparse
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .repository import TraceRepository


MODULE_DIR = Path(__file__).resolve().parent
DEFAULT_ROOT = MODULE_DIR.parent


def create_app(root: Path = DEFAULT_ROOT) -> FastAPI:
    repository = TraceRepository(root)
    app = FastAPI(title="QLCoder Trace Viewer", version="0.1.0")

    def translate_error(error: Exception) -> HTTPException:
        if isinstance(error, FileNotFoundError):
            return HTTPException(status_code=404, detail=str(error))
        if isinstance(error, ValueError):
            return HTTPException(status_code=409, detail=str(error))
        return HTTPException(status_code=500, detail=str(error))

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "root": str(repository.root), "output": str(repository.output_root)}

    @app.get("/api/summary")
    def summary():
        return repository.summary()

    @app.get("/api/runs")
    def list_runs():
        return {"runs": repository.list_runs(), "summary": repository.summary()}

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str):
        try:
            return repository.get_run(run_id)
        except Exception as error:
            raise translate_error(error) from error

    @app.get("/api/runs/{run_id}/phases")
    def list_phases(run_id: str):
        try:
            return {"phases": repository.list_phases(run_id)}
        except Exception as error:
            raise translate_error(error) from error

    @app.get("/api/runs/{run_id}/trace/{phase_id}")
    def trace_page(
        run_id: str,
        phase_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(80, ge=1, le=250),
        kind: str | None = None,
        tool: str | None = None,
        search: str | None = None,
    ):
        try:
            return repository.get_trace_page(run_id, phase_id, offset, limit, kind, tool, search)
        except Exception as error:
            raise translate_error(error) from error

    @app.get("/api/runs/{run_id}/trace/{phase_id}/events/{sequence}")
    def trace_event(run_id: str, phase_id: str, sequence: int):
        try:
            return repository.get_trace_event(run_id, phase_id, sequence)
        except Exception as error:
            raise translate_error(error) from error

    @app.get("/api/runs/{run_id}/artifacts")
    def artifacts(run_id: str):
        try:
            return {"artifacts": repository.list_artifacts(run_id)}
        except Exception as error:
            raise translate_error(error) from error

    @app.get("/api/runs/{run_id}/artifacts/{name}")
    def artifact(run_id: str, name: str):
        try:
            return repository.read_artifact(run_id, name)
        except Exception as error:
            raise translate_error(error) from error

    @app.get("/api/runs/{run_id}/query-diff")
    def query_diff(run_id: str, from_iteration: int = Query(..., ge=1), to_iteration: int = Query(..., ge=1)):
        try:
            return repository.query_diff(run_id, from_iteration, to_iteration)
        except Exception as error:
            raise translate_error(error) from error

    static_dir = MODULE_DIR / "static"
    app.mount("/assets", StaticFiles(directory=static_dir), name="assets")

    @app.head("/", include_in_schema=False)
    def index_head():
        return FileResponse(static_dir / "index.html")

    @app.get("/{path:path}", include_in_schema=False)
    def single_page(path: str):
        return FileResponse(static_dir / "index.html")

    return app


app = create_app()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local QLCoder Trace Viewer")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8765, type=int)
    parser.add_argument("--root", default=str(DEFAULT_ROOT), help="QLCoder repository root")
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    import uvicorn

    if Path(args.root).resolve() == DEFAULT_ROOT.resolve():
        uvicorn.run("trace_viewer.server:app", host=args.host, port=args.port, reload=args.reload)
    else:
        uvicorn.run(create_app(Path(args.root)), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
