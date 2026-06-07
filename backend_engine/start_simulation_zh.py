# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from backend_engine.agents.blue_agent_zh import BlueAgent
from backend_engine.agents.red_agent_zh import RedAgent
from backend_engine.agents.llm_agent import LLMDecisionError
from backend_engine.core.network_topology import load_scenario
from backend_engine.core.referee_engine_zh import RefereeEngine
from backend_engine.core.replay_export import build_replay_lite
from backend_engine.engine.context_builder import build_blue_context, build_red_context


def _progress(message: str) -> None:
    print(message, flush=True)


@contextmanager
def _heartbeat(label: str, *, interval_seconds: float):
    started = time.monotonic()
    stop_event = threading.Event()

    def emit_heartbeat() -> None:
        while not stop_event.wait(interval_seconds):
            elapsed = time.monotonic() - started
            _progress(f"  ... {label}仍在进行，已等待 {elapsed:.0f} 秒")

    worker = None
    if interval_seconds > 0:
        worker = threading.Thread(target=emit_heartbeat, name=f"heartbeat-{label}", daemon=True)
        worker.start()
    try:
        yield
    finally:
        stop_event.set()
        if worker is not None:
            worker.join(timeout=0.2)


def _decision_summary(decision) -> str:
    target = decision.target or "无目标"
    vuln = f" | vuln={decision.vuln_id}" if decision.vuln_id else ""
    return f"{decision.action_type} -> {target}{vuln}"


def _round_result_summary(state) -> str:
    referee_log = next((log for log in reversed(state.action_logs) if log.agent_type == "Referee"), None)
    metadata = referee_log.metadata if referee_log is not None else {}
    score = metadata.get("score_summary", {})
    interaction = metadata.get("interaction", {})
    red_log = next((log for log in state.action_logs if log.agent_type == "Red"), None)
    blue_log = next((log for log in state.action_logs if log.agent_type == "Blue"), None)
    red_effect = red_log.metadata.get("referee_effect", red_log.metadata.get("effect", "未知")) if red_log else "未知"
    blue_effect = blue_log.metadata.get("referee_effect", blue_log.metadata.get("effect", "未知")) if blue_log else "未知"
    interaction_type = interaction.get("type", "independent")
    return (
        f"红方={red_effect} +{score.get('red_delta', 0)} | "
        f"蓝方={blue_effect} +{score.get('blue_delta', 0)} | "
        f"交互={interaction_type}"
    )


def _state_summary(state) -> str:
    compromised = [name for name, node in state.network_nodes.items() if node.status == "Compromised"]
    sessions = [name for name, node in state.network_nodes.items() if node.red_state.session_active]
    persistence = [name for name, node in state.network_nodes.items() if node.red_state.persistence]
    isolated = [name for name, node in state.network_nodes.items() if node.status == "Isolated" or node.blue_state.isolated]

    def compact(values: list[str]) -> str:
        return ",".join(values) if values else "无"

    return (
        f"比分 R{state.red_score}:B{state.blue_score} | 健康 {state.system_health}% | 暴露 {state.exposure_level}% | "
        f"失陷[{compact(compromised)}] | 会话[{compact(sessions)}] | "
        f"持久化[{compact(persistence)}] | 隔离[{compact(isolated)}]"
    )


def _resolve_timeout_outcome(state, *, executed_rounds: int) -> None:
    core_assets = [node_name for node_name in state.core_assets if node_name in state.network_nodes] or ["db"]
    red_controlled_core = [
        node_name
        for node_name in core_assets
        if (
            state.network_nodes.get(node_name) is not None
            and (
                state.network_nodes[node_name].status == "Compromised"
                or state.network_nodes[node_name].red_state.foothold
                or state.network_nodes[node_name].red_state.persistence
            )
        )
    ]
    red_residual_nodes = [
        node_name
        for node_name, node in state.network_nodes.items()
        if (
            node.status == "Compromised"
            or node.red_state.session_active
            or node.red_state.foothold
            or node.red_state.persistence
            or node_name in state.red_anchored_nodes
        )
    ]

    if red_controlled_core:
        state.winner_locked = True
        state.winner_side = "Red"
        state.winner_reason = (
            f"{executed_rounds}轮结束：核心资产存在红方控制态({', '.join(red_controlled_core)})，"
            "按状态判定红方胜。"
        )
        return

    if not red_residual_nodes:
        state.winner_locked = True
        state.winner_side = "Blue"
        state.winner_reason = (
            f"{executed_rounds}轮结束：无失陷节点、活动会话、foothold 或 persistence 残留，"
            "按状态判定蓝方胜。"
        )
        return

    state.winner_locked = False
    state.winner_side = None
    state.winner_reason = (
        f"{executed_rounds}轮结束：未达成明确胜利状态，判定平局。"
        f"(red_residual={len(red_residual_nodes)}, anchored={len(state.red_anchored_nodes)})"
    )


def run_simulation(
    rounds: int,
    scenario_path: Path,
    output_path: Path,
    *,
    strict_llm: bool = True,
    use_probability: bool = False,
    random_seed: int | None = None,
    output_lite_path: Path | None = None,
    continue_after_winner_locked: bool = True,
    heartbeat_seconds: float = 15.0,
) -> dict:
    simulation_started = time.monotonic()
    state = load_scenario(scenario_path)
    red_agent = RedAgent(strict_llm=strict_llm)
    blue_agent = BlueAgent(strict_llm=strict_llm)
    referee = RefereeEngine(use_probability=use_probability, random_seed=random_seed)
    state = referee.prepare_state(state)

    frames = [state.model_dump(mode="json")]
    _progress("=" * 72)
    _progress(f"启动模拟：{scenario_path.stem}")
    _progress(
        f"配置：轮数={rounds} | strict_llm={strict_llm} | model={red_agent.model_name} | "
        f"概率门控={use_probability} | seed={random_seed} | 心跳={heartbeat_seconds:g}s"
    )
    _progress(f"初始态势：{_state_summary(state)}")
    _progress("=" * 72)

    for round_index in range(1, rounds + 1):
        round_started = time.monotonic()
        _progress(f"\n[回合 {round_index}/{rounds}] 开始")
        state = referee.prepare_state(state)
        blue_perceived_state = referee.get_blue_perceived_state()
        recent_logs = referee.get_blue_recent_alerts()

        red_context = build_red_context(state)
        red_started = time.monotonic()
        _progress("  [1/3] 正在请求红方 LLM 决策...")
        try:
            with _heartbeat("红方 LLM 决策", interval_seconds=heartbeat_seconds):
                red_action = red_agent.decide(state, context_markdown=red_context)
        except Exception as exc:
            if strict_llm:
                raise LLMDecisionError(f"中文入口严格 LLM 模式下红方决策失败：{exc}") from exc
            _progress(f"[Simulation-ZH] RedAgent 决策异常，回退规则策略：{exc}")
            red_action = red_agent._fallback_decide(state)
        _progress(f"        红方完成 ({time.monotonic() - red_started:.1f}s)：{_decision_summary(red_action)}")

        blue_context = build_blue_context(blue_perceived_state, recent_logs)
        blue_started = time.monotonic()
        _progress(f"  [2/3] 正在请求蓝方 LLM 决策... 当前可见告警={len(recent_logs)}")
        try:
            with _heartbeat("蓝方 LLM 决策", interval_seconds=heartbeat_seconds):
                blue_action = blue_agent.decide(
                    blue_perceived_state,
                    recent_logs=recent_logs,
                    context_markdown=blue_context,
                )
        except Exception as exc:
            if strict_llm:
                raise LLMDecisionError(f"中文入口严格 LLM 模式下蓝方决策失败：{exc}") from exc
            _progress(f"[Simulation-ZH] BlueAgent 决策异常，回退规则策略：{exc}")
            blue_action = blue_agent._fallback_decide(blue_perceived_state, recent_logs=recent_logs)
        _progress(f"        蓝方完成 ({time.monotonic() - blue_started:.1f}s)：{_decision_summary(blue_action)}")

        referee_started = time.monotonic()
        _progress("  [3/3] 正在进行裁判结算...")
        with _heartbeat("裁判结算", interval_seconds=heartbeat_seconds):
            state = referee.resolve_round(state, red_action, blue_action)
        _progress(f"        裁判完成 ({time.monotonic() - referee_started:.1f}s)：{_round_result_summary(state)}")
        red_memory = red_agent.observe_outcome(state)
        blue_memory = blue_agent.observe_outcome(state)
        if state.action_logs:
            state.action_logs[-1].metadata["agent_memory"] = {
                "red": red_memory,
                "blue": blue_memory,
            }
        frames.append(state.model_dump(mode="json"))
        _progress(f"  回合态势：{_state_summary(state)}")
        _progress(f"[回合 {round_index}/{rounds}] 完成，用时 {time.monotonic() - round_started:.1f}s")
        if state.winner_locked:
            _progress(f"  胜负锁定：{state.winner_side} | {state.winner_reason}")
        if state.winner_locked and not continue_after_winner_locked:
            break

    if not state.winner_locked:
        executed_rounds = len(frames) - 1
        _resolve_timeout_outcome(state, executed_rounds=executed_rounds)
        frames[-1] = state.model_dump(mode="json")

    replay = {
        "scenario": scenario_path.stem,
        "total_rounds": len(frames) - 1,
        "frames": frames,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(replay, indent=2, ensure_ascii=False), encoding="utf-8")
    _progress(f"\n完整回放已写入：{output_path}")
    if output_lite_path is not None:
        output_lite_path.parent.mkdir(parents=True, exist_ok=True)
        output_lite = build_replay_lite(replay)
        output_lite_path.write_text(json.dumps(output_lite, indent=2, ensure_ascii=False), encoding="utf-8")
        _progress(f"精简回放已写入：{output_lite_path}")
    _progress(f"模拟总耗时：{time.monotonic() - simulation_started:.1f}s")
    return replay


def main() -> None:
    # 强制 UTF-8 输出，避免 Windows 终端中文乱码。
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = argparse.ArgumentParser(description="运行一个中文入口的 CyberArena 对抗模拟（默认严格 LLM 决策）。")
    parser.add_argument("--scenario", default="backend_engine/scenarios/level_1_basic_web.json")
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--output", default="backend_engine/results/mock_simulation_zh.json")
    parser.add_argument(
        "--output_lite",
        default="",
        help="可选：写入前端回放友好的精简结果 JSON。",
    )
    parser.add_argument(
        "--use_probability",
        action="store_true",
        help="启用漏洞 exploit_prob/patch_prob 概率门控（默认关闭）。",
    )
    parser.add_argument(
        "--random_seed",
        type=int,
        default=None,
        help="可选：为裁判概率门控随机数设置固定 seed。",
    )
    parser.add_argument(
        "--allow_fallback",
        action="store_true",
        help="允许红蓝在 LLM 决策失败时回退规则策略（默认关闭，严格走 LLM）。",
    )
    parser.add_argument(
        "--stop_on_winner",
        action="store_true",
        help="命中胜利锁定后立刻停止（默认继续跑满回合用于回放）。",
    )
    parser.add_argument(
        "--heartbeat_seconds",
        type=float,
        default=15.0,
        help="等待 LLM 或裁判时的进度心跳间隔秒数；设为 0 可关闭（默认 15）。",
    )
    args = parser.parse_args()

    replay = run_simulation(
        rounds=args.rounds,
        scenario_path=Path(args.scenario),
        output_path=Path(args.output),
        strict_llm=not args.allow_fallback,
        use_probability=args.use_probability,
        random_seed=args.random_seed,
        output_lite_path=Path(args.output_lite) if args.output_lite else None,
        continue_after_winner_locked=not args.stop_on_winner,
        heartbeat_seconds=max(0.0, args.heartbeat_seconds),
    )

    final_frame = replay["frames"][-1]
    print(f"模拟完成：共写入 {len(replay['frames'])} 帧")
    print(
        f"最终状态：turn={final_frame['turn']} "
        f"health={final_frame['system_health']} "
        f"exposure={final_frame['exposure_level']}"
    )


if __name__ == "__main__":
    main()
