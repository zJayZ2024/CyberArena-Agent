from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from backend_engine.agents.blue_agent import BlueAgent
from backend_engine.agents.red_agent import RedAgent
from backend_engine.core.network_topology import load_scenario
from backend_engine.core.referee_engine import RefereeEngine
from backend_engine.engine.context_builder import build_blue_context, build_red_context


def run_simulation(rounds: int, scenario_path: Path, output_path: Path) -> dict:
    state = load_scenario(scenario_path)
    red_agent = RedAgent()
    blue_agent = BlueAgent()
    referee = RefereeEngine()
    state = referee.prepare_state(state)

    frames = [state.model_dump(mode="json")]

    for _ in range(rounds):
        red_context = build_red_context(state)
        try:
            red_action = red_agent.decide(state, context_markdown=red_context)
        except Exception as exc:
            print(f"[Simulation] RedAgent 决策异常，回退规则策略：{exc}")
            red_action = red_agent._fallback_decide(state)

        interim_state, red_result, recent_logs = referee.resolve_red_phase(state, red_action)

        blue_context = build_blue_context(interim_state, recent_logs)
        try:
            blue_action = blue_agent.decide(
                interim_state,
                recent_logs=recent_logs,
                context_markdown=blue_context,
            )
        except Exception as exc:
            print(f"[Simulation] BlueAgent 决策异常，回退规则策略：{exc}")
            blue_action = blue_agent._fallback_decide(interim_state, recent_logs=recent_logs)

        state = referee.finalize_round(interim_state, red_action, red_result, blue_action)
        frames.append(state.model_dump(mode="json"))

    replay = {
        "scenario": scenario_path.stem,
        "total_rounds": rounds,
        "frames": frames,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(replay, indent=2, ensure_ascii=False), encoding="utf-8")
    return replay


def main() -> None:
    parser = argparse.ArgumentParser(description="运行一个最小可用的 CyberArena 对抗模拟。")
    parser.add_argument("--scenario", default="backend_engine/scenarios/level_1_basic_web.json")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--output", default="backend_engine/results/mock_simulation.json")
    args = parser.parse_args()

    replay = run_simulation(
        rounds=args.rounds,
        scenario_path=Path(args.scenario),
        output_path=Path(args.output),
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
