# app/main.py
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from app.database import engine, Base
from app.routers import imports, vulnerabilities, insights

# Create tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Vulnerability Management", version="0.1.0")

# Include routers
app.include_router(imports.router)
app.include_router(vulnerabilities.router)
app.include_router(insights.router)

# Static files
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
async def root():
    index_path = static_dir / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {"status": "ok", "message": "Vulnerability Management API"}


@app.get("/health")
async def health():
    return {"status": "healthy"}
