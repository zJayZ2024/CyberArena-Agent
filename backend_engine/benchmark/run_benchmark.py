from __future__ import annotations

import argparse
import json
import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend_engine.core.replay_export import build_replay_lite
from backend_engine.start_simulation_zh import run_simulation


@dataclass(slots=True)
class BenchmarkConfig:
    scenario: Path
    rounds: int
    runs: int
    seed_base: int
    output_dir: Path
    strict_llm: bool
    use_probability: bool
    stop_on_winner: bool


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run repeatable benchmark and export benchmark.json/benchmark.md.")
    parser.add_argument("--scenario", default="backend_engine/scenarios/level_1_basic_web.json")
    parser.add_argument("--rounds", type=int, default=None)
    parser.add_argument("--runs", type=int, default=None)
    parser.add_argument("--seed_base", type=int, default=42)
    parser.add_argument("--output_dir", default="backend_engine/results/benchmark")
    parser.add_argument("--strict_llm", action="store_true", help="Use strict LLM mode (default: fallback mode).")
    parser.add_argument("--use_probability", action="store_true")
    parser.add_argument("--stop_on_winner", action="store_true")
    parser.add_argument("--smoke", action="store_true", help="Quick smoke benchmark with small run count.")
    return parser.parse_args()


def _resolve_config(args: argparse.Namespace) -> BenchmarkConfig:
    default_rounds = 6 if args.smoke else 20
    default_runs = 3 if args.smoke else 10
    return BenchmarkConfig(
        scenario=Path(args.scenario),
        rounds=max(1, int(args.rounds if args.rounds is not None else default_rounds)),
        runs=max(1, int(args.runs if args.runs is not None else default_runs)),
        seed_base=int(args.seed_base),
        output_dir=Path(args.output_dir),
        strict_llm=bool(args.strict_llm),
        use_probability=bool(args.use_probability),
        stop_on_winner=bool(args.stop_on_winner),
    )


def _first_agent_log(frame: dict[str, Any], agent_type: str) -> dict[str, Any] | None:
    logs = frame.get("action_logs")
    if not isinstance(logs, list):
        return None
    for row in logs:
        if isinstance(row, dict) and row.get("agent_type") == agent_type:
            return row
    return None


def _is_illegal_action(log: dict[str, Any]) -> bool:
    metadata = log.get("metadata")
    if isinstance(metadata, dict):
        if str(metadata.get("validation", "")).lower() == "failed":
            return True
        if str(metadata.get("referee_effect", "")).lower() == "rejected":
            return True
    referee_result = str(log.get("referee_result", "")).lower()
    if "illegal action" in referee_result or "非法动作" in referee_result:
        return True
    return False


def _compute_run_metrics(
    replay: dict[str, Any],
    *,
    simulation_duration_ms: float,
    export_duration_ms: float,
) -> dict[str, Any]:
    frames = replay.get("frames")
    if not isinstance(frames, list):
        frames = []

    executed_rounds = max(0, len(frames) - 1)
    total_actions = 0
    illegal_actions = 0
    successful_rounds = 0

    for idx in range(1, len(frames)):
        frame = frames[idx] if isinstance(frames[idx], dict) else {}
        red_log = _first_agent_log(frame, "Red")
        blue_log = _first_agent_log(frame, "Blue")
        round_logs = [red_log, blue_log]
        round_illegal = False
        round_complete = True

        for log in round_logs:
            if not isinstance(log, dict):
                round_complete = False
                continue
            total_actions += 1
            is_illegal = _is_illegal_action(log)
            illegal_actions += int(is_illegal)
            round_illegal = round_illegal or is_illegal

        if round_complete and not round_illegal:
            successful_rounds += 1

    illegal_action_rate = illegal_actions / total_actions if total_actions else 0.0
    round_success_rate = successful_rounds / executed_rounds if executed_rounds else 0.0
    avg_response_latency_ms = simulation_duration_ms / executed_rounds if executed_rounds else 0.0

    final_frame = frames[-1] if frames and isinstance(frames[-1], dict) else {}
    return {
        "executed_rounds": executed_rounds,
        "round_success_rate": round(round_success_rate, 6),
        "illegal_action_rate": round(illegal_action_rate, 6),
        "avg_response_latency_ms": round(avg_response_latency_ms, 3),
        "replay_export_duration_ms": round(export_duration_ms, 3),
        "winner_locked": bool(final_frame.get("winner_locked", False)),
        "winner_side": final_frame.get("winner_side"),
        "winner_reason": final_frame.get("winner_reason"),
        "total_actions": total_actions,
        "illegal_actions": illegal_actions,
    }


def _mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return float(statistics.fmean(values))


def _build_summary(run_rows: list[dict[str, Any]]) -> dict[str, Any]:
    ok_rows = [row for row in run_rows if row.get("status") == "ok"]
    if not ok_rows:
        return {
            "successful_runs": 0,
            "failed_runs": len(run_rows),
            "round_success_rate": 0.0,
            "illegal_action_rate": 0.0,
            "avg_response_latency_ms": 0.0,
            "avg_replay_export_duration_ms": 0.0,
        }

    return {
        "successful_runs": len(ok_rows),
        "failed_runs": len(run_rows) - len(ok_rows),
        "round_success_rate": round(_mean([float(row["metrics"]["round_success_rate"]) for row in ok_rows]), 6),
        "illegal_action_rate": round(_mean([float(row["metrics"]["illegal_action_rate"]) for row in ok_rows]), 6),
        "avg_response_latency_ms": round(_mean([float(row["metrics"]["avg_response_latency_ms"]) for row in ok_rows]), 3),
        "avg_replay_export_duration_ms": round(
            _mean([float(row["metrics"]["replay_export_duration_ms"]) for row in ok_rows]),
            3,
        ),
    }


def _render_markdown_report(payload: dict[str, Any]) -> str:
    cfg = payload.get("config", {})
    summary = payload.get("summary", {})
    rows = payload.get("runs", [])

    lines = [
        "# Benchmark Report",
        "",
        "## Config",
        f"- scenario: `{cfg.get('scenario', '')}`",
        f"- rounds: `{cfg.get('rounds', 0)}`",
        f"- runs: `{cfg.get('runs', 0)}`",
        f"- seed_base: `{cfg.get('seed_base', 0)}`",
        f"- strict_llm: `{cfg.get('strict_llm', False)}`",
        f"- use_probability: `{cfg.get('use_probability', False)}`",
        f"- stop_on_winner: `{cfg.get('stop_on_winner', False)}`",
        "",
        "## Summary Metrics",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| 回合成功率 | `{summary.get('round_success_rate', 0.0):.6f}` |",
        f"| 非法动作率 | `{summary.get('illegal_action_rate', 0.0):.6f}` |",
        f"| 平均响应时延(ms/round) | `{summary.get('avg_response_latency_ms', 0.0):.3f}` |",
        f"| 回放导出耗时(ms) | `{summary.get('avg_replay_export_duration_ms', 0.0):.3f}` |",
        f"| successful_runs | `{summary.get('successful_runs', 0)}` |",
        f"| failed_runs | `{summary.get('failed_runs', 0)}` |",
        "",
        "## Run Details",
        "",
        "| run | status | rounds | round_success_rate | illegal_action_rate | avg_latency_ms | export_ms | winner |",
        "|---:|---|---:|---:|---:|---:|---:|---|",
    ]

    for row in rows:
        run_id = row.get("run_id")
        status = row.get("status")
        if status != "ok":
            lines.append(f"| {run_id} | error | 0 | 0 | 0 | 0 | 0 | - |")
            continue
        metrics = row.get("metrics", {})
        winner = metrics.get("winner_side") or ("None" if not metrics.get("winner_locked") else "Unknown")
        lines.append(
            "| {run} | ok | {rounds} | {succ:.6f} | {illegal:.6f} | {latency:.3f} | {export:.3f} | {winner} |".format(
                run=run_id,
                rounds=int(metrics.get("executed_rounds", 0)),
                succ=float(metrics.get("round_success_rate", 0.0)),
                illegal=float(metrics.get("illegal_action_rate", 0.0)),
                latency=float(metrics.get("avg_response_latency_ms", 0.0)),
                export=float(metrics.get("replay_export_duration_ms", 0.0)),
                winner=winner,
            )
        )

    lines.extend(
        [
            "",
            "## 指标口径",
            "- 回合成功率: 有完整红蓝动作日志且两者均非非法动作的回合数 / 执行回合数。",
            "- 非法动作率: 红蓝动作中 `validation=failed` 或 `referee_effect=rejected` 的占比。",
            "- 平均响应时延: 单次模拟总耗时 / 执行回合数。",
            "- 回放导出耗时: `build_replay_lite + 写盘` 的耗时。",
        ]
    )
    return "\n".join(lines) + "\n"


def _run_once(config: BenchmarkConfig, run_id: int) -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_seed = config.seed_base + run_id - 1
    run_dir = config.output_dir / f"run_{run_id:03d}"
    run_dir.mkdir(parents=True, exist_ok=True)

    raw_path = run_dir / "simulation.json"
    lite_path = run_dir / "simulation_lite.json"

    start_sim = time.perf_counter()
    replay = run_simulation(
        rounds=config.rounds,
        scenario_path=config.scenario,
        output_path=raw_path,
        strict_llm=config.strict_llm,
        use_probability=config.use_probability,
        random_seed=run_seed,
        output_lite_path=None,
        continue_after_winner_locked=not config.stop_on_winner,
    )
    end_sim = time.perf_counter()

    start_export = time.perf_counter()
    lite = build_replay_lite(replay)
    lite_path.write_text(json.dumps(lite, indent=2, ensure_ascii=False), encoding="utf-8")
    end_export = time.perf_counter()

    metrics = _compute_run_metrics(
        replay,
        simulation_duration_ms=(end_sim - start_sim) * 1000.0,
        export_duration_ms=(end_export - start_export) * 1000.0,
    )
    return {
        "run_id": run_id,
        "timestamp": timestamp,
        "status": "ok",
        "seed": run_seed,
        "output": {
            "raw_replay": str(raw_path),
            "lite_replay": str(lite_path),
        },
        "metrics": metrics,
    }


def main() -> None:
    args = _parse_args()
    config = _resolve_config(args)
    config.output_dir.mkdir(parents=True, exist_ok=True)

    run_rows: list[dict[str, Any]] = []
    for run_id in range(1, config.runs + 1):
        try:
            row = _run_once(config, run_id)
            print(
                "[benchmark] run={run} rounds={rounds} success_rate={succ:.4f} illegal_rate={illegal:.4f}".format(
                    run=run_id,
                    rounds=row["metrics"]["executed_rounds"],
                    succ=row["metrics"]["round_success_rate"],
                    illegal=row["metrics"]["illegal_action_rate"],
                )
            )
            run_rows.append(row)
        except Exception as exc:  # noqa: BLE001
            print(f"[benchmark] run={run_id} failed: {exc}")
            run_rows.append(
                {
                    "run_id": run_id,
                    "status": "error",
                    "error": str(exc),
                    "seed": config.seed_base + run_id - 1,
                }
            )

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "scenario": str(config.scenario),
            "rounds": config.rounds,
            "runs": config.runs,
            "seed_base": config.seed_base,
            "strict_llm": config.strict_llm,
            "use_probability": config.use_probability,
            "stop_on_winner": config.stop_on_winner,
            "output_dir": str(config.output_dir),
        },
        "summary": _build_summary(run_rows),
        "runs": run_rows,
    }

    json_path = config.output_dir / "benchmark.json"
    md_path = config.output_dir / "benchmark.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(_render_markdown_report(payload), encoding="utf-8")

    print(f"[benchmark] report_json={json_path}")
    print(f"[benchmark] report_md={md_path}")


if __name__ == "__main__":
    main()
