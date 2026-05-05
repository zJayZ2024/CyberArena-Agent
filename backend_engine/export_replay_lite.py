from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from backend_engine.core.replay_export import build_replay_lite


def main() -> None:
    parser = argparse.ArgumentParser(description="将全量回放 JSON 转换为前端友好的 replay_lite JSON。")
    parser.add_argument("--input", required=True, help="全量回放 JSON 文件路径。")
    parser.add_argument("--output", required=True, help="输出 replay_lite JSON 文件路径。")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    lite = build_replay_lite(payload)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(lite, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"replay_lite 导出完成: {output_path}")


if __name__ == "__main__":
    main()
