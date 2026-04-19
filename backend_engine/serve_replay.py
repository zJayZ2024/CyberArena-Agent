from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR / "results"
SCENARIOS_DIR = BASE_DIR / "scenarios"
DEFAULT_SCENARIO_NAME = "level_2_ransomware"

app = FastAPI(title="CyberArena Replay Server")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SimulationRunRequest(BaseModel):
    rounds: int = Field(default=20, ge=5, le=30)


def _safe_json_read(file_path: Path) -> dict[str, Any]:
    try:
        return json.loads(file_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"File not found: {file_path.name}") from exc
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"Invalid JSON file: {file_path.name}") from exc


def _extract_scores(frame: dict[str, Any]) -> tuple[int, int]:
    if not isinstance(frame, dict):
        return 0, 0

    world_state = frame.get("world_state", {})
    if isinstance(world_state, dict):
        score = world_state.get("score", {})
        if isinstance(score, dict):
            red = int(score.get("red", frame.get("red_score", 0)) or 0)
            blue = int(score.get("blue", frame.get("blue_score", 0)) or 0)
            return red, blue

    return int(frame.get("red_score", 0) or 0), int(frame.get("blue_score", 0) or 0)


def _build_simulation_summary(payload: dict[str, Any], *, source_file: Path) -> dict[str, Any]:
    frames = payload.get("frames", [])
    final_frame = frames[-1] if isinstance(frames, list) and frames else {}
    red_score, blue_score = _extract_scores(final_frame if isinstance(final_frame, dict) else {})

    total_rounds = payload.get("total_rounds")
    if not isinstance(total_rounds, int) or total_rounds <= 0:
        total_rounds = max(len(frames) - 1, 0) if isinstance(frames, list) else 0

    created_at = datetime.fromtimestamp(source_file.stat().st_mtime).isoformat(timespec="seconds")
    winner = "Draw"
    if red_score > blue_score:
        winner = "Red"
    elif blue_score > red_score:
        winner = "Blue"

    return {
        "file": source_file.name,
        "simulation_id": source_file.stem,
        "scenario": payload.get("scenario", DEFAULT_SCENARIO_NAME),
        "rounds": total_rounds,
        "red_score": red_score,
        "blue_score": blue_score,
        "winner": winner,
        "created_at": created_at,
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/replay")
def replay(path: str = "backend_engine/results/mock_simulation.json") -> dict[str, Any]:
    replay_path = Path(path)
    return _safe_json_read(replay_path)


@app.post("/api/simulation/run")
def run_simulation_api(request: SimulationRunRequest) -> dict[str, Any]:
    from backend_engine.start_simulation_zh import run_simulation

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    scenario_path = SCENARIOS_DIR / f"{DEFAULT_SCENARIO_NAME}.json"
    if not scenario_path.exists():
        raise HTTPException(status_code=500, detail=f"Default scenario not found: {scenario_path.name}")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = RESULTS_DIR / f"simulation_{timestamp}.json"

    try:
        replay = run_simulation(
            rounds=request.rounds,
            scenario_path=scenario_path,
            output_path=output_path,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Simulation failed: {exc}") from exc

    summary = _build_simulation_summary(replay, source_file=output_path)
    return {"status": "ok", "simulation": summary}


@app.get("/api/simulation/history")
def list_simulation_history() -> dict[str, list[dict[str, Any]]]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []

    for file_path in sorted(RESULTS_DIR.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            payload = _safe_json_read(file_path)
            records.append(_build_simulation_summary(payload, source_file=file_path))
        except HTTPException:
            continue
        except Exception:
            continue

    return {"items": records}


@app.get("/api/simulation/download")
def download_simulation_result(file: str = Query(..., description="Result file name in backend_engine/results")) -> dict[str, Any]:
    if Path(file).name != file:
        raise HTTPException(status_code=400, detail="Invalid file name")

    target = RESULTS_DIR / file
    if not target.exists():
        raise HTTPException(status_code=404, detail="Simulation file not found")
    return _safe_json_read(target)


@app.delete("/api/simulation/delete")
def delete_simulation_result(file: str = Query(..., description="Result file name in backend_engine/results")) -> dict[str, str]:
    if Path(file).name != file:
        raise HTTPException(status_code=400, detail="Invalid file name")

    target = RESULTS_DIR / file
    if not target.exists():
        raise HTTPException(status_code=404, detail="Simulation file not found")

    try:
        target.unlink()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Delete failed: {exc}") from exc

    return {"status": "ok"}
