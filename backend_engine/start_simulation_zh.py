from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from backend_engine.agents.blue_agent_zh import BlueAgent
from backend_engine.agents.red_agent_zh import RedAgent
from backend_engine.core.network_topology import load_scenario
from backend_engine.core.referee_engine_zh import RefereeEngine


def run_simulation(rounds: int, scenario_path: Path, output_path: Path) -> dict:
    state = load_scenario(scenario_path)
    red_agent = RedAgent()
    blue_agent = BlueAgent()
    referee = RefereeEngine()

    frames = [state.model_dump(mode="json")]

    for _ in range(rounds):
        red_action = red_agent.decide(state)
        blue_action = blue_agent.decide(state, red_action)
        state = referee.resolve_round(state, red_action, blue_action)
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
    parser = argparse.ArgumentParser(description="\u8fd0\u884c\u4e00\u4e2a\u6700\u5c0f\u53ef\u7528\u7684 CyberArena \u5bf9\u6297\u6a21\u62df\u3002")
    parser.add_argument("--scenario", default="backend_engine/scenarios/level_1_basic_web.json")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--output", default="backend_engine/results/mock_simulation_zh.json")
    args = parser.parse_args()

    replay = run_simulation(
        rounds=args.rounds,
        scenario_path=Path(args.scenario),
        output_path=Path(args.output),
    )

    final_frame = replay["frames"][-1]
    print(f"\u6a21\u62df\u5b8c\u6210\uff1a\u5171\u5199\u5165 {len(replay['frames'])} \u5e27")
    print(
        f"\u6700\u7ec8\u72b6\u6001\uff1aturn={final_frame['turn']} "
        f"health={final_frame['system_health']} "
        f"exposure={final_frame['exposure_level']}"
    )


if __name__ == "__main__":
    main()
