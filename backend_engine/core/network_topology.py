from __future__ import annotations

import json
from pathlib import Path

from backend_engine.core.models import WorldState


def load_scenario(path: str | Path) -> WorldState:
    scenario_path = Path(path)
    with scenario_path.open("r", encoding="utf-8") as file:
        payload = json.load(file)
    return WorldState.model_validate(payload)
