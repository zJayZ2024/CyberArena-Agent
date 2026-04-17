from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

from backend_engine.core.models import ActionLog, AgentDecision, RefereeJudgement, WorldState


DEFAULT_REFEREE_PROMPT = """你是 CyberArena 的技术裁判（Referee）。
你只做语义判定，不直接修改状态。

判定原则：
1. 只基于给定 world_state、动作定义与 payload 做技术可行性判断。
2. 不要使用随机数；不要输出概率推测。
3. 若动作从技术上可成立，is_success=true；否则 false。
4. rationale 必须解释动作生效或失效的技术原因（网络路径、前置条件、漏洞匹配、目标状态）。
5. llm_score_suggest 必须是整数，且 >= 0（仅为建议分，不直接用于最终计分）。
6. effect 必须是短标签（如 intel/compromise/exfiltration/hardening/restoration/isolation/monitoring/failed）。

输出必须是严格 JSON，不要输出 Markdown。
"""


class RefereeAgent:
    agent_name = "Referee"

    def __init__(self, *, max_retries: int = 3) -> None:
        load_dotenv(override=False, encoding="utf-8")
        self.max_retries = max(1, max_retries)

        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "referee_judge.md"
        if prompt_path.exists():
            prompt_text = prompt_path.read_text(encoding="utf-8").strip()
            self.system_prompt = prompt_text or DEFAULT_REFEREE_PROMPT
        else:
            self.system_prompt = DEFAULT_REFEREE_PROMPT

        api_key = os.getenv("OPENAI_API_KEY")
        base_url = os.getenv("OPENAI_BASE_URL")
        self.model_name = os.getenv("REFEREE_MODEL_NAME") or os.getenv("LLM_MODEL_NAME", "ecnu-max")
        self.client = OpenAI(api_key=api_key, base_url=base_url) if api_key else None

    def judge_action(
        self,
        state: WorldState,
        decision: AgentDecision,
        *,
        action_descriptor: dict[str, Any] | None = None,
        validation_summary: dict[str, Any] | None = None,
    ) -> RefereeJudgement:
        if self.client is None:
            return self._fallback_failure("缺少可用的 LLM 客户端，裁判默认判定失败。")

        target_snapshot: dict[str, Any] | None = None
        if decision.target and decision.target in state.network_nodes:
            target_snapshot = state.network_nodes[decision.target].model_dump(mode="json")

        user_payload = {
            "turn": state.turn,
            "decision": decision.model_dump(mode="json"),
            "action_descriptor": action_descriptor or {},
            "target_snapshot": target_snapshot,
            "world_state_summary": {
                "system_health": state.system_health,
                "exposure_level": state.exposure_level,
                "red_score": state.red_score,
                "blue_score": state.blue_score,
                "compromised_nodes": [
                    node_name
                    for node_name, node in state.network_nodes.items()
                    if node.status == "Compromised"
                ],
                "down_nodes": [
                    node_name
                    for node_name, node in state.network_nodes.items()
                    if node.status == "Down"
                ],
            },
            "validation_summary": validation_summary or {},
        }

        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ]

        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            raw_text = ""
            try:
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    response_format={"type": "json_object"},
                    temperature=0.2,
                    top_p=0.8,
                )
                raw_text = response.choices[0].message.content or ""
                if not raw_text.strip():
                    raise ValueError("Referee returned empty content")
                return RefereeJudgement.model_validate_json(self._strip_code_fences(raw_text))
            except Exception as exc:
                last_error = exc
                if attempt >= self.max_retries:
                    break
                if raw_text:
                    messages.append({"role": "assistant", "content": raw_text})
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "上一条输出不是合法 JSON 或字段不完整。"
                            "请仅输出 RefereeJudgement JSON："
                            '{"is_success": bool, "rationale": str, "llm_score_suggest": int, "effect": str}'
                        ),
                    }
                )
                time.sleep(0.5)

        return self._fallback_failure(f"裁判 JSON 解析失败，默认判定失败：{last_error}")

    def log_resolution(
        self,
        red: AgentDecision,
        blue: AgentDecision,
        result: str,
        *,
        metadata: dict | None = None,
    ) -> ActionLog:
        return ActionLog(
            agent_type="Referee",
            thought=f"本回合已完成裁定：红方动作为 {red.action_type}，蓝方动作为 {blue.action_type}。",
            action_type="ResolveRound",
            payload=f"{red.target or '无目标'}|{blue.target or '无目标'}",
            referee_result=result,
            metadata=metadata or {},
        )

    def _fallback_failure(self, reason: str) -> RefereeJudgement:
        return RefereeJudgement(
            is_success=False,
            rationale=reason,
            llm_score_suggest=0,
            effect="failed",
        )

    @staticmethod
    def _strip_code_fences(text: str) -> str:
        cleaned = text.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        return cleaned.strip()
