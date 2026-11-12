"""FastAPI server: JSON endpoints for the dashboard and the built dashboard itself."""
import pathlib
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

STATIC = pathlib.Path(__file__).resolve().parent / "static"

def build_app(engine):
    app = FastAPI(title="PW25 live detection")

    @app.get("/api/summary")
    def summary():
        return engine.summary()

    @app.get("/api/session/{key}")
    def session(key: str):
        s = engine.session(key)
        if not s:
            raise HTTPException(404, "unknown session")
        return s

    @app.get("/api/config")
    def config():
        c = engine.cfg
        return {k: c[k] for k in ("reliability", "thresholds", "cmax", "delta_seconds", "privileged")}

    if (STATIC / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=STATIC / "assets"), name="assets")

        @app.get("/{path:path}")
        def index(path: str):
            return FileResponse(STATIC / "index.html")
    return app
