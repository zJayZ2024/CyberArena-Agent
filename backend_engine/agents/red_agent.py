from __future__ import annotations

from pathlib import Path

from backend_engine.agents.llm_agent import BaseLLMAgent, LLMDecisionError
from backend_engine.core.models import AgentDecision, WorldState
from backend_engine.engine.actions import ACTION_REGISTRY, ActionContext
from backend_engine.engine.decision_framework import (
    ActionSpaceBuilder,
    AntiStagnationController,
    FallbackPlanner,
    LLMPlanner,
    OpponentModeler,
    ReflectionEngine,
    build_battle_state,
)


class RedAgent(BaseLLMAgent):
    def __init__(self, *, strict_llm: bool = False) -> None:
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "red_attacker.md"
        super().__init__(
            agent_name="Red",
            agent_type="Red",
            prompt_path=prompt_path,
            max_retries=3,
        )
        self.strict_llm = strict_llm
        self._action_space_builder = ActionSpaceBuilder(max_candidates=24)
        self._llm_planner = LLMPlanner(max_retries=3)
        self._opponent_modeler = OpponentModeler(self_agent_type="Red")
        self._reflection_engine = ReflectionEngine(self_agent_type="Red")
        self._anti_stagnation = AntiStagnationController(
            self_agent_type="Red",
            max_recon_streak=2,
            no_progress_threshold=3,
        )
        self._fallback_planner = FallbackPlanner()

    def decide(self, state: WorldState, context_markdown: str | None = None) -> AgentDecision:
        if not context_markdown:
            raise LLMDecisionError("红方缺少 context_markdown，无法进行 LLM 决策。")

        self._opponent_modeler.observe(state)
        self._reflection_engine.observe(state)
        self._anti_stagnation.observe_state(state)

        opponent_model = self._opponent_modeler.build()
        reflections = self._reflection_engine.recent(limit=3)
        battle_state = build_battle_state(
            state,
            agent_type="Red",
            failure_streak=self._reflection_engine.failure_streak(limit=4),
            no_progress_rounds=self._anti_stagnation.no_progress_rounds(),
            recent_alerts=None,
        )
        candidates = self._action_space_builder.build_candidates(
            state,
            agent_type="Red",
            recent_alerts=None,
            battle_state=battle_state,
            opponent_model=opponent_model,
        )
        candidates = self._anti_stagnation.apply(candidates, battle_state=battle_state)
        if not candidates:
            raise LLMDecisionError("红方当前没有可执行候选动作。")

        try:
            decision, candidate_id, thought = self._choose_with_llm(
                state=state,
                context_markdown=context_markdown,
                battle_state=battle_state,
                opponent_model=opponent_model,
                reflections=reflections,
                candidates=candidates,
            )
        except Exception as exc:
            if self.strict_llm:
                raise LLMDecisionError(f"RedAgent 严格 LLM 模式下决策失败：{exc}") from exc
            print(f"[RedAgent] LLM 决策失败，回退到候选集兜底规划：{exc}")
            fallback = self._fallback_planner.choose(
                candidates=candidates,
                agent_type="Red",
                opponent_model=opponent_model,
                reflections=reflections,
            )
            decision = fallback.decision.model_copy(deep=True)
            thought = f"LLM 决策失败，启用候选集兜底：{fallback.reason}"
            candidate_id = fallback.candidate_id

        decision.thought = thought
        self._anti_stagnation.observe_decision(decision.action_type)
        self._reflection_engine.set_expected(decision=decision, candidate_id=candidate_id, thought=thought)
        return decision

    def _choose_with_llm(
        self,
        *,
        state: WorldState,
        context_markdown: str,
        battle_state: dict,
        opponent_model: dict,
        reflections: list[dict],
        candidates: list,
    ) -> tuple[AgentDecision, str, str]:
        rejected_ids: set[str] = set()
        last_error: Exception | None = None
        for _ in range(2):
            available = [row for row in candidates if row.candidate_id not in rejected_ids]
            if not available:
                break
            plan = self._llm_planner.plan(
                client=self.client,
                model_name=self.model_name,
                agent_type="Red",
                background_prompt=self.system_prompt,
                context_markdown=context_markdown,
                battle_state=battle_state,
                opponent_model=opponent_model,
                reflections=reflections,
                candidates=available,
            )
            chosen = next((row for row in available if row.candidate_id == plan.chosen_candidate_id), None)
            if chosen is None and plan.backup_candidate_id:
                chosen = next((row for row in available if row.candidate_id == plan.backup_candidate_id), None)
            if chosen is None:
                last_error = LLMDecisionError("LLM 输出的候选动作不在候选池中。")
                continue

            decision = chosen.decision.model_copy(deep=True)
            validation_error = self._validate_selected_decision(state, decision)
            if validation_error is not None:
                rejected_ids.add(chosen.candidate_id)
                last_error = validation_error
                continue

            return decision, chosen.candidate_id, plan.thought

        raise LLMDecisionError(f"红方候选决策在纠错阶段仍失败：{last_error}")

    def _validate_selected_decision(self, state: WorldState, decision: AgentDecision) -> Exception | None:
        action = ACTION_REGISTRY.get(decision.action_type)
        if action is None:
            return LLMDecisionError(f"动作不存在：{decision.action_type}")
        validation_error = action.validate(
            ActionContext(
                state=state,
                decision=decision,
                locale="zh",
                opposing_decision=None,
            )
        )
        if validation_error is not None:
            return LLMDecisionError(validation_error.message)
        return None

    def _fallback_decide(self, state: WorldState) -> AgentDecision:
        self._opponent_modeler.observe(state)
        self._reflection_engine.observe(state)
        self._anti_stagnation.observe_state(state)
        opponent_model = self._opponent_modeler.build()
        reflections = self._reflection_engine.recent(limit=3)
        battle_state = build_battle_state(
            state,
            agent_type="Red",
            failure_streak=self._reflection_engine.failure_streak(limit=4),
            no_progress_rounds=self._anti_stagnation.no_progress_rounds(),
            recent_alerts=None,
        )
        candidates = self._action_space_builder.build_candidates(
            state,
            agent_type="Red",
            recent_alerts=None,
            battle_state=battle_state,
            opponent_model=opponent_model,
        )
        candidates = self._anti_stagnation.apply(candidates, battle_state=battle_state)
        if not candidates:
            raise LLMDecisionError("红方 fallback 阶段没有可执行动作。")
        chosen = self._fallback_planner.choose(
            candidates=candidates,
            agent_type="Red",
            opponent_model=opponent_model,
            reflections=reflections,
        )
        decision = chosen.decision.model_copy(deep=True)
        decision.thought = f"红方候选集兜底规划：{chosen.reason}"
        self._anti_stagnation.observe_decision(decision.action_type)
        self._reflection_engine.set_expected(decision=decision, candidate_id=chosen.candidate_id, thought=decision.thought)
        return decision
