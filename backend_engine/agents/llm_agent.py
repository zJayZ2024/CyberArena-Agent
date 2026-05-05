from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Iterable

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:  # pragma: no cover - environment compatibility fallback
    def load_dotenv(*args, **kwargs):  # type: ignore[no-redef]
        return False


try:
    from openai import OpenAI
except ModuleNotFoundError:  # pragma: no cover - environment compatibility fallback
    OpenAI = None  # type: ignore[assignment]

from backend_engine.core.models import AgentDecision, WorldState
from backend_engine.engine.actions import ACTION_REGISTRY, ActionContext


class LLMDecisionError(RuntimeError):
    pass


class BaseLLMAgent:
    def __init__(
        self,
        *,
        agent_name: str,
        agent_type: str,
        prompt_path: str | Path,
        max_retries: int = 3,
    ) -> None:
        load_dotenv(override=False, encoding="utf-8")

        self.agent_name = agent_name
        self.agent_type = agent_type
        self.max_retries = max_retries
        self.prompt_path = Path(prompt_path)
        self.system_prompt = self.prompt_path.read_text(encoding="utf-8").strip()

        if not self.system_prompt:
            raise ValueError(f"{self.prompt_path} 不能为空。")

        api_key = os.getenv("OPENAI_API_KEY")
        base_url = os.getenv("OPENAI_BASE_URL")
        model_name = os.getenv("LLM_MODEL_NAME", "ecnu-max")
        self.model_name = model_name
        if api_key and OpenAI is None:
            raise LLMDecisionError("检测到 OPENAI_API_KEY，但未安装 openai 包。")
        self.client = OpenAI(api_key=api_key, base_url=base_url) if (api_key and OpenAI is not None) else None

    def decide(
        self,
        state: WorldState,
        context_markdown: str,
        *,
        allowed_targets: Iterable[str] | None = None,
    ) -> AgentDecision:
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": context_markdown},
        ]

        last_error: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            raw_text = ""
            try:
                raw_text = self._request_decision(messages)
                decision = AgentDecision.model_validate_json(self._strip_code_fences(raw_text))
                self._validate_decision(decision, state, allowed_targets=allowed_targets)
                return decision
            except Exception as exc:
                last_error = exc
                if attempt >= self.max_retries:
                    break

                error_message = str(exc)
                if raw_text:
                    messages.append({"role": "assistant", "content": raw_text})
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "你的上一条输出未通过校验。\n"
                            f"错误原因：{error_message}\n"
                            "请重新输出一个严格符合要求的 JSON 对象，不要输出任何解释或 Markdown。"
                        ),
                    }
                )
                time.sleep(0.6)

        raise LLMDecisionError(f"{self.agent_name} 连续 {self.max_retries} 次输出无效：{last_error}")

    def _request_decision(self, messages: list[dict[str, str]]) -> str:
        if self.client is None:
            raise LLMDecisionError("缺少可用的 LLM 客户端。")

        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            response_format={"type": "json_object"},
            temperature=0.4,
            top_p=0.8,
        )
        content = response.choices[0].message.content
        if not content:
            raise LLMDecisionError(f"{self.agent_name} 未返回任何内容。")
        return content

    def _strip_code_fences(self, text: str) -> str:
        cleaned = text.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:]

        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]

        return cleaned.strip()

    def _validate_decision(
        self,
        decision: AgentDecision,
        state: WorldState,
        *,
        allowed_targets: Iterable[str] | None = None,
    ) -> None:
        if decision.agent_type != self.agent_type:
            raise LLMDecisionError(f"agent_type 必须为 {self.agent_type}")

        action = ACTION_REGISTRY.get(decision.action_type)
        if action is None:
            raise LLMDecisionError(f"非法动作：{decision.action_type}")

        if action.agent_type != self.agent_type:
            raise LLMDecisionError(f"{self.agent_type} 不能使用动作 {decision.action_type}")

        if allowed_targets is not None and decision.target is not None:
            allowed_target_set = set(allowed_targets)
            allowed_target_set.update(action.virtual_targets)
            if decision.target not in allowed_target_set:
                raise LLMDecisionError(f"目标 {decision.target} 不在当前允许范围内")

        validation_error = action.validate(
            ActionContext(
                state=state,
                decision=decision,
                locale="zh",
                opposing_decision=None,
            )
        )
        if validation_error is not None:
            raise LLMDecisionError(validation_error.message)
