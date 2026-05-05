# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import sys
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


def _resolve_timeout_outcome(state, *, executed_rounds: int) -> None:
    core_assets = [node_name for node_name in state.core_assets if node_name in state.network_nodes] or ["db"]
    compromised_core = [
        node_name
        for node_name in core_assets
        if state.network_nodes.get(node_name) is not None and state.network_nodes[node_name].status == "Compromised"
    ]
    compromised_nodes = [
        node_name for node_name, node in state.network_nodes.items() if node.status == "Compromised"
    ]

    if compromised_core:
        state.winner_locked = True
        state.winner_side = "Red"
        state.winner_reason = (
            f"{executed_rounds}轮结束：核心资产已失陷({', '.join(compromised_core)})，"
            "按状态判定红方胜。"
        )
        return

    if not compromised_nodes and not state.red_anchored_nodes:
        state.winner_locked = True
        state.winner_side = "Blue"
        state.winner_reason = (
            f"{executed_rounds}轮结束：无失陷节点且无红方据点残留，"
            "按状态判定蓝方胜。"
        )
        return

    state.winner_locked = False
    state.winner_side = None
    state.winner_reason = (
        f"{executed_rounds}轮结束：未达成明确胜利状态，判定平局。"
        f"(compromised={len(compromised_nodes)}, anchored={len(state.red_anchored_nodes)})"
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
) -> dict:
    state = load_scenario(scenario_path)
    red_agent = RedAgent(strict_llm=strict_llm)
    blue_agent = BlueAgent(strict_llm=strict_llm)
    referee = RefereeEngine(use_probability=use_probability, random_seed=random_seed)
    state = referee.prepare_state(state)

    frames = [state.model_dump(mode="json")]

    for _ in range(rounds):
        state = referee.prepare_state(state)
        blue_perceived_state = referee.get_blue_perceived_state()
        recent_logs = referee.get_blue_recent_alerts()

        red_context = build_red_context(state)
        try:
            red_action = red_agent.decide(state, context_markdown=red_context)
        except Exception as exc:
            if strict_llm:
                raise LLMDecisionError(f"中文入口严格 LLM 模式下红方决策失败：{exc}") from exc
            print(f"[Simulation-ZH] RedAgent 决策异常，回退规则策略：{exc}")
            red_action = red_agent._fallback_decide(state)

        blue_context = build_blue_context(blue_perceived_state, recent_logs)
        try:
            blue_action = blue_agent.decide(
                blue_perceived_state,
                recent_logs=recent_logs,
                context_markdown=blue_context,
            )
        except Exception as exc:
            if strict_llm:
                raise LLMDecisionError(f"中文入口严格 LLM 模式下蓝方决策失败：{exc}") from exc
            print(f"[Simulation-ZH] BlueAgent 决策异常，回退规则策略：{exc}")
            blue_action = blue_agent._fallback_decide(blue_perceived_state, recent_logs=recent_logs)

        state = referee.resolve_round(state, red_action, blue_action)
        frames.append(state.model_dump(mode="json"))
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
    if output_lite_path is not None:
        output_lite_path.parent.mkdir(parents=True, exist_ok=True)
        output_lite = build_replay_lite(replay)
        output_lite_path.write_text(json.dumps(output_lite, indent=2, ensure_ascii=False), encoding="utf-8")
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
