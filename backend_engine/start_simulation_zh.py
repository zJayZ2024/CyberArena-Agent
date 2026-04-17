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
from backend_engine.core.replay_export import build_replay_lite
from backend_engine.core.referee_engine_zh import RefereeEngine
from backend_engine.engine.context_builder import build_blue_context, build_red_context


def run_simulation(
    rounds: int,
    scenario_path: Path,
    output_path: Path,
    *,
    strict_llm: bool = True,
    use_probability: bool = False,
    output_lite_path: Path | None = None,
) -> dict:
    state = load_scenario(scenario_path)
    red_agent = RedAgent(strict_llm=strict_llm)
    blue_agent = BlueAgent(strict_llm=strict_llm)
    referee = RefereeEngine(use_probability=use_probability)
    state = referee.prepare_state(state)

    frames = [state.model_dump(mode="json")]

    for _ in range(rounds):
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

    replay = {
        "scenario": scenario_path.stem,
        "total_rounds": rounds,
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
    parser = argparse.ArgumentParser(description="运行一个中文入口的 CyberArena 对抗模拟（红蓝决策默认强制 LLM）。")
    parser.add_argument("--scenario", default="backend_engine/scenarios/level_1_basic_web.json")
    parser.add_argument("--rounds", type=int, default=3)
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
        "--allow_fallback",
        action="store_true",
        help="允许红蓝在 LLM 决策失败时回退规则策略（默认关闭，严格走 LLM）。",
    )
    args = parser.parse_args()

    replay = run_simulation(
        rounds=args.rounds,
        scenario_path=Path(args.scenario),
        output_path=Path(args.output),
        strict_llm=not args.allow_fallback,
        use_probability=args.use_probability,
        output_lite_path=Path(args.output_lite) if args.output_lite else None,
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
