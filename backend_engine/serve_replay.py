from __future__ import annotations

import json
import sys
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend_engine.start_simulation_zh import run_simulation
from backend_engine.report_engine import generate_report, report_to_markdown


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_ROOT = (PROJECT_ROOT / "backend_engine" / "scenarios").resolve()
RESULT_ROOT = (PROJECT_ROOT / "backend_engine" / "results" / "frontend_runs").resolve()
REPORT_ROOT = (PROJECT_ROOT / "backend_engine" / "results" / "reports").resolve()
RESULT_ROOT.mkdir(parents=True, exist_ok=True)
REPORT_ROOT.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="CyberArena Simulation Server")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_jobs: dict[str, dict[str, Any]] = {}
_cancel_events: dict[str, threading.Event] = {}
_report_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.Lock()


class SimulationRequest(BaseModel):
    scenario_path: str
    rounds: int = Field(default=20, ge=1, le=100)
    use_probability: bool = True
    random_seed: int | None = None


class ReportRequest(BaseModel):
    replay_name: str = ""
    replay: dict[str, Any]


def _safe_scenario_path(raw_path: str) -> Path:
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    resolved = candidate.resolve()
    if SCENARIO_ROOT not in resolved.parents or resolved.suffix.lower() != ".json":
        raise HTTPException(status_code=400, detail="场景文件必须位于 backend_engine/scenarios 目录")
    if not resolved.exists():
        raise HTTPException(status_code=404, detail="场景文件不存在")
    return resolved


def _job_public(job: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in job.items() if key not in {"output_path"}}


def _report_public(job: dict[str, Any], *, include_report: bool = False) -> dict[str, Any]:
    hidden = set() if include_report else {"report"}
    return {key: value for key, value in job.items() if key not in hidden}


def _persist_report_job(report_id: str) -> None:
    job = _report_jobs.get(report_id)
    if not job:
        return
    output_path = REPORT_ROOT / f"{report_id}.json"
    output_path.write_text(json.dumps(job, indent=2, ensure_ascii=False), encoding="utf-8")


def _load_existing_reports() -> None:
    for output_path in REPORT_ROOT.glob("report_*.json"):
        try:
            job = json.loads(output_path.read_text(encoding="utf-8"))
            report_id = str(job.get("id") or output_path.stem)
            job["id"] = report_id
            interrupted = job.get("status") == "running"
            if interrupted:
                job.update(
                    {
                        "status": "failed",
                        "completed_at": datetime.now().isoformat(timespec="seconds"),
                        "error": "报告服务重启，生成任务已中断，请重新生成。",
                    }
                )
            _report_jobs[report_id] = job
            if interrupted:
                _persist_report_job(report_id)
        except Exception:
            continue


def _load_existing_jobs() -> None:
    for output_path in RESULT_ROOT.glob("*.json"):
        try:
            replay = json.loads(output_path.read_text(encoding="utf-8"))
            final_frame = replay.get("frames", [{}])[-1]
            job_id = output_path.stem
            _jobs[job_id] = {
                "id": job_id,
                "name": f"{replay.get('scenario', job_id)} · {replay.get('total_rounds', 0)} 回合仿真",
                "scenario": replay.get("scenario", ""),
                "scenario_path": "",
                "rounds": replay.get("total_rounds", 0),
                "status": "stopped" if replay.get("stopped_early") else "completed",
                "started_at": datetime.fromtimestamp(output_path.stat().st_mtime).isoformat(timespec="seconds"),
                "completed_at": datetime.fromtimestamp(output_path.stat().st_mtime).isoformat(timespec="seconds"),
                "red_score": final_frame.get("red_score", 0),
                "blue_score": final_frame.get("blue_score", 0),
                "winner_side": final_frame.get("winner_side"),
                "winner_reason": final_frame.get("winner_reason", ""),
                "replay_path": f"/api/simulations/{job_id}/replay",
                "output_path": output_path,
                "error": None,
            }
        except Exception:
            continue


_load_existing_jobs()
_load_existing_reports()


def _run_job(job_id: str, scenario_path: Path, rounds: int, use_probability: bool, random_seed: int | None) -> None:
    output_path = RESULT_ROOT / f"{job_id}.json"
    try:
        cancel_event = _cancel_events[job_id]
        replay = run_simulation(
            rounds=rounds,
            scenario_path=scenario_path,
            output_path=output_path,
            strict_llm=True,
            use_probability=use_probability,
            random_seed=random_seed,
            output_lite_path=None,
            continue_after_winner_locked=True,
            heartbeat_seconds=15.0,
            should_stop=cancel_event.is_set,
        )
        final_frame = replay.get("frames", [{}])[-1]
        stopped = bool(replay.get("stopped_early"))
        with _jobs_lock:
            _jobs[job_id].update(
                {
                    "status": "stopped" if stopped else "completed",
                    "completed_at": datetime.now().isoformat(timespec="seconds"),
                    "rounds": replay.get("total_rounds", rounds),
                    "red_score": final_frame.get("red_score", 0),
                    "blue_score": final_frame.get("blue_score", 0),
                    "winner_side": final_frame.get("winner_side"),
                    "winner_reason": final_frame.get("winner_reason", ""),
                    "replay_path": f"/api/simulations/{job_id}/replay",
                    "output_path": output_path,
                }
            )
    except Exception as exc:
        with _jobs_lock:
            _jobs[job_id].update(
                {
                    "status": "failed",
                    "completed_at": datetime.now().isoformat(timespec="seconds"),
                    "error": str(exc),
                }
            )
    finally:
        with _jobs_lock:
            _cancel_events.pop(job_id, None)


def _run_report_job(report_id: str, replay: dict[str, Any], replay_name: str) -> None:
    try:
        report = generate_report(replay, replay_name=replay_name)
        with _jobs_lock:
            _report_jobs[report_id].update(
                {
                    "status": "completed",
                    "completed_at": datetime.now().isoformat(timespec="seconds"),
                    "report": report,
                }
            )
            _persist_report_job(report_id)
    except Exception as exc:
        with _jobs_lock:
            _report_jobs[report_id].update(
                {
                    "status": "failed",
                    "completed_at": datetime.now().isoformat(timespec="seconds"),
                    "error": str(exc),
                }
            )
            _persist_report_job(report_id)


@app.get("/health")
@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/replay")
def replay(path: str = "backend_engine/results/mock_simulation.json") -> dict[str, Any]:
    replay_path = Path(path)
    if not replay_path.is_absolute():
        replay_path = PROJECT_ROOT / replay_path
    return json.loads(replay_path.read_text(encoding="utf-8"))


@app.post("/api/simulations", status_code=202)
def start_simulation(request: SimulationRequest) -> dict[str, Any]:
    scenario_path = _safe_scenario_path(request.scenario_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    job_id = f"{scenario_path.stem}_{timestamp}_{uuid.uuid4().hex[:6]}"
    job = {
        "id": job_id,
        "name": f"{scenario_path.stem} · {request.rounds} 回合仿真",
        "scenario": scenario_path.stem,
        "scenario_path": str(scenario_path.relative_to(PROJECT_ROOT)).replace("\\", "/"),
        "rounds": request.rounds,
        "status": "running",
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "replay_path": None,
        "error": None,
    }
    with _jobs_lock:
        _jobs[job_id] = job
        _cancel_events[job_id] = threading.Event()

    worker = threading.Thread(
        target=_run_job,
        args=(job_id, scenario_path, request.rounds, request.use_probability, request.random_seed),
        name=f"simulation-{job_id}",
        daemon=True,
    )
    worker.start()
    return _job_public(job)


@app.get("/api/simulations")
def list_simulations() -> dict[str, list[dict[str, Any]]]:
    with _jobs_lock:
        jobs = [_job_public(job) for job in _jobs.values()]
    jobs.sort(key=lambda item: item.get("started_at", ""), reverse=True)
    return {"simulations": jobs}


@app.get("/api/simulations/{job_id}")
def simulation_status(job_id: str) -> dict[str, Any]:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="仿真任务不存在")
        return _job_public(job)


@app.post("/api/simulations/{job_id}/stop", status_code=202)
def stop_simulation(job_id: str) -> dict[str, Any]:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="仿真任务不存在")
        if job.get("status") not in {"running", "stopping"}:
            return _job_public(job)
        cancel_event = _cancel_events.get(job_id)
        if cancel_event is not None:
            cancel_event.set()
        job["status"] = "stopping"
        job["stop_requested_at"] = datetime.now().isoformat(timespec="seconds")
        return _job_public(job)


@app.get("/api/simulations/{job_id}/replay")
def simulation_replay(job_id: str) -> dict[str, Any]:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="仿真任务不存在")
        if job.get("status") not in {"completed", "stopped"}:
            raise HTTPException(status_code=409, detail="仿真尚未完成")
        output_path = job.get("output_path")
    return json.loads(Path(output_path).read_text(encoding="utf-8"))


@app.post("/api/reports", status_code=202)
def start_report(request: ReportRequest) -> dict[str, Any]:
    report_id = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    job = {
        "id": report_id,
        "status": "running",
        "replay_name": request.replay_name or request.replay.get("scenario", "CyberArena"),
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "error": None,
    }
    with _jobs_lock:
        _report_jobs[report_id] = job
        _persist_report_job(report_id)
    worker = threading.Thread(
        target=_run_report_job,
        args=(report_id, request.replay, job["replay_name"]),
        name=f"report-{report_id}",
        daemon=True,
    )
    worker.start()
    return _job_public(job)


@app.get("/api/reports")
def list_reports() -> dict[str, list[dict[str, Any]]]:
    with _jobs_lock:
        reports = [_report_public(job) for job in _report_jobs.values()]
    reports.sort(key=lambda item: item.get("started_at", ""), reverse=True)
    return {"reports": reports}


@app.get("/api/reports/{report_id}")
def report_status(report_id: str) -> dict[str, Any]:
    with _jobs_lock:
        job = _report_jobs.get(report_id)
        if not job:
            raise HTTPException(status_code=404, detail="报告任务不存在")
        return _report_public(job, include_report=True)


@app.get("/api/reports/{report_id}/download")
def download_report(report_id: str, format: str = "markdown"):
    with _jobs_lock:
        job = _report_jobs.get(report_id)
        if not job:
            raise HTTPException(status_code=404, detail="报告任务不存在")
        if job.get("status") != "completed":
            raise HTTPException(status_code=409, detail="报告尚未生成完成")
        report = job["report"]
    filename = f"{report_id}.{'json' if format == 'json' else 'md'}"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    if format == "json":
        return JSONResponse(report, headers=headers)
    return PlainTextResponse(report_to_markdown(report), media_type="text/markdown; charset=utf-8", headers=headers)
