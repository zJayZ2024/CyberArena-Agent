from __future__ import annotations

import json
import sys
from pathlib import Path

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI


app = FastAPI(title="CyberArena Replay Server")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/replay")
def replay(path: str = "backend_engine/results/mock_simulation.json") -> dict:
    replay_path = Path(path)
    return json.loads(replay_path.read_text(encoding="utf-8"))
