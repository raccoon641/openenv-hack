"""
server/app.py  –  Entry point for multi-mode deployment.

Re-exports the FastAPI app from the parent package so the server can be
started from either the repo root or the server/ subdirectory.
"""

import os
import sys

# Allow imports from the repo root regardless of working directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import app  # noqa: F401 — re-export for uvicorn


def main():
    import uvicorn
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860, reload=False)


if __name__ == "__main__":
    main()
