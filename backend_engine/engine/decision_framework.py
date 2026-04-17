from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Iterable, Literal

from backend_engine.agents.llm_agent import LLMDecisionError
from backend_engine.core.models import AgentDecision, SecurityAlert, WorldState
from backend_engine.engine.actions import ACTION_REGISTRY, ActionContext

AgentType = Literal["Red", "Blue"]

RED_PASSIVE_ACTIONS = {"Recon"}
BLUE_PASSIVE_ACTIONS = {"Monitor"}
CRITICAL_NODES = ("web", "app", "db", "storage")


@dataclass(slots=True)
class CandidateAction:
    candidate_id: str
    decision: AgentDecision
    expected_impact: float
    expected_risk: float
    progress_value: float
    heuristic_score: float
    tags: tuple[str, ...]
    reason: str

    def as_prompt_row(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "action_type": self.decision.action_type,
            "target": self.decision.target,
            "vuln_id": self.decision.vuln_id,
            "payload": self.decision.payload,
            "expected_impact": round(self.expected_impact, 2),
            "expected_risk": round(self.expected_risk, 2),
            "progress_value": round(self.progress_value, 2),
            "heuristic_score": round(self.heuristic_score, 2),
            "tags": list(self.tags),
            "reason": self.reason,
        }


@dataclass(slots=True)
class PlannerDecision:
    chosen_candidate_id: str
    backup_candidate_id: str | None
    thought: str
    raw_payload: dict[str, Any]


@dataclass(slots=True)
class IntelPackage:
    visible_nodes: tuple[str, ...]
    known_services: dict[str, tuple[int, ...]]
    known_vulnerabilities: dict[str, tuple[str, ...]]
    compromised_footholds: tuple[str, ...]
    recon_nodes: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "visible_nodes": list(self.visible_nodes),
            "known_services": {node: list(ports) for node, ports in self.known_services.items()},
            "known_vulnerabilities": {node: list(vulns) for node, vulns in self.known_vulnerabilities.items()},
            "compromised_footholds": list(self.compromised_footholds),
            "recon_nodes": list(self.recon_nodes),
        }


def build_red_intel_package(state: WorldState) -> IntelPackage:
    visible = set(state.red_visible_nodes)
    if not visible:
        visible.update({"internet", "fw", "web"} & set(state.network_nodes))
    visible.update(node_name for node_name, node in state.network_nodes.items() if node.status == "Compromised")

    known_services: dict[str, tuple[int, ...]] = {}
    for node_name, ports in state.red_known_services.items():
        if node_name in visible:
            known_services[node_name] = tuple(sorted(set(int(port) for port in ports)))

    known_vulnerabilities: dict[str, tuple[str, ...]] = {}
    for node_name, vuln_map in state.red_known_vulnerabilities.items():
        if node_name not in visible:
            continue
        if isinstance(vuln_map, dict):
            vuln_ids = sorted(vuln_map.keys())
            if vuln_ids:
                known_vulnerabilities[node_name] = tuple(vuln_ids)

    compromised_footholds = tuple(
        sorted(node_name for node_name, node in state.network_nodes.items() if node.status == "Compromised")
    )
    recon_nodes = tuple(sorted(set(state.red_recon_nodes)))
    return IntelPackage(
        visible_nodes=tuple(sorted(visible)),
        known_services=known_services,
        known_vulnerabilities=known_vulnerabilities,
        compromised_footholds=compromised_footholds,
        recon_nodes=recon_nodes,
    )


class ActionSpaceBuilder:
    def __init__(self, *, max_candidates: int = 24) -> None:
        self.max_candidates = max(8, max_candidates)

    def build_candidates(
        self,
        state: WorldState,
        *,
        agent_type: AgentType,
        recent_alerts: Iterable[SecurityAlert] | None = None,
        battle_state: dict[str, Any] | None = None,
        opponent_model: dict[str, Any] | None = None,
    ) -> list[CandidateAction]:
        del battle_state
        candidates: list[CandidateAction] = []
        seen: set[tuple[str, str | None, str | None]] = set()
        intel_package = build_red_intel_package(state) if agent_type == "Red" else None
        target_pool = self._target_pool(state, agent_type=agent_type, intel_package=intel_package)

        for action in ACTION_REGISTRY.all():
            if action.agent_type != agent_type:
                continue

            if not action.requires_target:
                proposed_targets: list[str | None] = [None]
                proposed_targets.extend(action.virtual_targets)
                if action.action_type == "Monitor":
                    proposed_targets.extend(sorted(state.network_nodes))
            else:
                proposed_targets = list(target_pool)
                proposed_targets.extend(action.virtual_targets)

            for target in proposed_targets:
                vuln_candidates = self._vuln_candidates(
                    state,
                    target=target,
                    agent_type=agent_type,
                    intel_package=intel_package,
                )
                if action.action_type in {"Recon", "RestoreNode", "Monitor"}:
                    vuln_candidates = [None]

                for vuln_id in vuln_candidates:
                    draft = AgentDecision(
                        agent_type=agent_type,
                        thought=f"候选动作 {action.action_type}",
                        action_type=action.action_type,
                        target=target,
                        vuln_id=vuln_id,
                        payload=self._build_payload(
                            action_type=action.action_type,
                            target=target,
                            vuln_id=vuln_id,
                            agent_type=agent_type,
                        ),
                    )
                    validation_error = action.validate(
                        ActionContext(
                            state=state,
                            decision=draft,
                            locale="zh",
                            opposing_decision=None,
                        )
                    )
                    if validation_error is not None:
                        continue

                    key = (draft.action_type, draft.target, draft.vuln_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    candidate = self._to_candidate(
                        state,
                        decision=draft,
                        agent_type=agent_type,
                        recent_alerts=recent_alerts,
                        opponent_model=opponent_model or {},
                    )
                    candidates.append(candidate)

        candidates.sort(key=lambda row: (row.heuristic_score, row.expected_impact), reverse=True)
        return candidates[: self.max_candidates]

    def _target_pool(
        self,
        state: WorldState,
        *,
        agent_type: AgentType,
        intel_package: IntelPackage | None = None,
    ) -> list[str]:
        if agent_type == "Blue":
            return sorted(state.network_nodes)

        if intel_package is not None:
            return sorted(intel_package.visible_nodes)

        visible = set(state.red_visible_nodes)
        if not visible:
            visible.update({"internet", "fw", "web"} & set(state.network_nodes))
        visible.update(node_name for node_name, node in state.network_nodes.items() if node.status == "Compromised")
        return sorted(visible)

    def _vuln_candidates(
        self,
        state: WorldState,
        *,
        target: str | None,
        agent_type: AgentType,
        intel_package: IntelPackage | None = None,
    ) -> list[str | None]:
        if not target or target not in state.network_nodes:
            return [None]

        if agent_type == "Red":
            if intel_package is None:
                intel_package = build_red_intel_package(state)
            known_vulns = intel_package.known_vulnerabilities.get(target, ())
            if not known_vulns:
                return [None]
            return [None, *list(known_vulns[:3])]

        node = state.network_nodes[target]
        vuln_rows = sorted(node.vulnerabilities.items(), key=lambda item: item[1].score, reverse=True)
        vuln_ids = [vuln_id for vuln_id, _ in vuln_rows[:3]]
        if not vuln_ids:
            return [None]
        return [None, *vuln_ids]

    def _build_payload(
        self,
        *,
        action_type: str,
        target: str | None,
        vuln_id: str | None,
        agent_type: AgentType,
    ) -> str:
        scope = target or "network"
        if action_type == "Recon":
            return f"对 {scope} 执行侦察，收集服务与漏洞线索"
        if action_type == "ExploitService":
            return f"利用 vuln_id={vuln_id} 通过边界服务攻破 {scope}"
        if action_type == "LateralMove":
            return f"利用 vuln_id={vuln_id} 对 {scope} 执行横向移动"
        if action_type == "ExfiltrateDatabase":
            return f"利用 vuln_id={vuln_id} 从 {scope} 导出高价值数据"
        if action_type == "PatchNode":
            return f"修补 {scope} 的 vuln_id={vuln_id} 以降低攻击面"
        if action_type == "RestoreNode":
            return f"恢复 {scope} 到干净基线并恢复业务"
        if action_type == "Isolate":
            if vuln_id:
                return f"隔离 {scope} 并针对 vuln_id={vuln_id} 切断攻击路径"
            return f"隔离 {scope} 并切断攻击路径"
        if action_type == "Monitor":
            if agent_type == "Blue":
                return f"持续监控 {scope} 并追踪告警趋势"
            return f"监控 {scope}"
        return f"执行 {action_type} 于 {scope}"

    def _to_candidate(
        self,
        state: WorldState,
        *,
        decision: AgentDecision,
        agent_type: AgentType,
        recent_alerts: Iterable[SecurityAlert] | None,
        opponent_model: dict[str, Any],
    ) -> CandidateAction:
        action_type = decision.action_type
        target = decision.target
        vuln_score = 0
        if target and target in state.network_nodes and decision.vuln_id:
            vulnerability = state.network_nodes[target].vulnerabilities.get(decision.vuln_id)
            if vulnerability is not None:
                vuln_score = vulnerability.score

        asset_weight = 0
        if target:
            lowered = target.lower()
            if lowered in {"db", "storage"}:
                asset_weight = 3
            elif lowered in {"app", "web"}:
                asset_weight = 2
            elif lowered in {"fw", "internet"}:
                asset_weight = 1

        if agent_type == "Red":
            base_impact = {
                "ExfiltrateDatabase": 95,
                "LateralMove": 72,
                "ExploitService": 64,
                "Recon": 22,
            }.get(action_type, 20)
            base_risk = {
                "ExfiltrateDatabase": 35,
                "LateralMove": 24,
                "ExploitService": 26,
                "Recon": 8,
            }.get(action_type, 12)
            progress = {
                "ExfiltrateDatabase": 60,
                "LateralMove": 42,
                "ExploitService": 30,
                "Recon": 12,
            }.get(action_type, 10)
            if action_type == "Recon" and target in state.red_recon_nodes:
                progress -= 10
            if target and target in state.network_nodes and state.network_nodes[target].status == "Compromised":
                if action_type in {"ExploitService", "LateralMove"}:
                    progress -= 25
            expected_impact = base_impact + vuln_score + asset_weight * 5
            expected_risk = base_risk
        else:
            latest_pressure_target = opponent_model.get("pressure_target")
            pressure_bonus = 12 if latest_pressure_target and latest_pressure_target == target else 0
            base_impact = {
                "RestoreNode": 86,
                "Isolate": 74,
                "PatchNode": 62,
                "Monitor": 24,
            }.get(action_type, 18)
            base_risk = {
                "RestoreNode": 18,
                "Isolate": 28,
                "PatchNode": 12,
                "Monitor": 6,
            }.get(action_type, 10)
            progress = {
                "RestoreNode": 48,
                "Isolate": 40,
                "PatchNode": 30,
                "Monitor": 10,
            }.get(action_type, 10)
            if target and target in state.network_nodes:
                node = state.network_nodes[target]
                if node.status == "Compromised" and action_type in {"RestoreNode", "Isolate"}:
                    progress += 28
                if node.status == "Down" and action_type == "RestoreNode":
                    progress += 26
                if node.status == "Compromised" and action_type == "Monitor":
                    progress -= 30

            alert_bonus = 0
            if recent_alerts:
                for alert in recent_alerts:
                    if alert.target and alert.target == target:
                        if alert.severity == "CRIT":
                            alert_bonus += 16
                        elif alert.severity == "WARN":
                            alert_bonus += 8
            expected_impact = base_impact + vuln_score + asset_weight * 6 + alert_bonus + pressure_bonus
            expected_risk = base_risk

        heuristic = expected_impact + progress - expected_risk
        tags: list[str] = [action_type.lower()]
        if target:
            tags.append(f"target:{target}")
        if decision.vuln_id:
            tags.append("with_vuln")
        reason = f"{action_type} 预估收益={expected_impact:.1f}, 风险={expected_risk:.1f}, 推进={progress:.1f}"
        candidate_id = f"C{abs(hash((action_type, target, decision.vuln_id))) % 10_000:04d}"
        return CandidateAction(
            candidate_id=candidate_id,
            decision=decision,
            expected_impact=expected_impact,
            expected_risk=expected_risk,
            progress_value=progress,
            heuristic_score=heuristic,
            tags=tuple(tags),
            reason=reason,
        )


class LLMPlanner:
    def __init__(self, *, max_retries: int = 3) -> None:
        self.max_retries = max(1, max_retries)

    def plan(
        self,
        *,
        client: Any,
        model_name: str,
        agent_type: AgentType,
        background_prompt: str,
        context_markdown: str,
        battle_state: dict[str, Any],
        opponent_model: dict[str, Any],
        reflections: list[dict[str, Any]],
        candidates: list[CandidateAction],
        intel_package: dict[str, Any] | None = None,
    ) -> PlannerDecision:
        if client is None:
            raise LLMDecisionError("缺少可用的 LLM 客户端。")
        if not candidates:
            raise LLMDecisionError("当前不存在可执行候选动作。")

        candidate_rows = [row.as_prompt_row() for row in candidates]
        candidate_id_set = {row["candidate_id"] for row in candidate_rows}
        role_goal = (
            "红方目标：基于当前可用信息推进据点建立、横向移动与数据目标达成。"
            if agent_type == "Red"
            else "蓝方目标：基于当前风险态势完成遏制、修补、恢复并维持业务连续性。"
        )
        payload = {
            "agent_type": agent_type,
            "role_goal": role_goal,
            "battle_state": battle_state,
            "opponent_model": opponent_model,
            "recent_reflections": reflections[-3:],
            "intel_package": intel_package or {},
            "context_markdown": context_markdown,
            "candidates": candidate_rows,
            "output_schema": {
                "situation_assessment": "str",
                "objective_priority": "str",
                "top3_candidates": [{"candidate_id": "str", "reason": "str"}],
                "chosen_candidate_id": "str",
                "backup_candidate_id": "str|optional",
                "why_not_others": "str",
                "expected_risk": "low|medium|high",
            },
        }
        del background_prompt

        system_prompt = (
            "你是网络攻防对抗决策器。"
            "你必须基于当前战局、对手模型、候选动作做比较后再决策。"
            "禁止编造候选ID，必须从给定 candidates 中选择。"
            "输出必须是严格 JSON。"
        )
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ]

        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            raw_text = ""
            try:
                response = client.chat.completions.create(
                    model=model_name,
                    messages=messages,
                    response_format={"type": "json_object"},
                    temperature=0.2,
                    top_p=0.8,
                )
                raw_text = response.choices[0].message.content or ""
                parsed = json.loads(raw_text)
                chosen = str(parsed.get("chosen_candidate_id", "")).strip()
                if chosen not in candidate_id_set:
                    chosen = self._recover_candidate_id(parsed, candidates)
                    if chosen:
                        parsed["chosen_candidate_id"] = chosen
                if chosen not in candidate_id_set:
                    raise ValueError(f"chosen_candidate_id 不在候选集合内: {chosen}")
                backup = parsed.get("backup_candidate_id")
                backup_id = str(backup).strip() if isinstance(backup, str) and backup else None
                if backup_id and backup_id not in candidate_id_set:
                    backup_id = None
                thought = (
                    f"态势评估：{parsed.get('situation_assessment', '无')}; "
                    f"优先目标：{parsed.get('objective_priority', '无')}; "
                    f"已选动作：{chosen}; "
                    f"放弃原因：{parsed.get('why_not_others', '无')}"
                )
                return PlannerDecision(
                    chosen_candidate_id=chosen,
                    backup_candidate_id=backup_id,
                    thought=thought,
                    raw_payload=parsed,
                )
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
                            "上一条输出无效。"
                            f"错误原因：{exc}。"
                            f"请仅从以下候选ID中选择 chosen_candidate_id: {sorted(candidate_id_set)}。"
                            "必须输出严格 JSON。"
                        ),
                    }
                )
                time.sleep(0.4)

        raise LLMDecisionError(f"{agent_type} 候选决策失败：{last_error}")

    def _recover_candidate_id(self, parsed: dict[str, Any], candidates: list[CandidateAction]) -> str:
        top3 = parsed.get("top3_candidates")
        if isinstance(top3, list):
            for row in top3:
                if isinstance(row, dict):
                    candidate_id = str(row.get("candidate_id", "")).strip()
                    if candidate_id and any(item.candidate_id == candidate_id for item in candidates):
                        return candidate_id

        action_type = str(parsed.get("action_type", "")).strip()
        target = parsed.get("target")
        vuln_id = parsed.get("vuln_id")

        if not action_type and isinstance(parsed.get("selected_action"), dict):
            selected = parsed["selected_action"]
            action_type = str(selected.get("action_type", "")).strip()
            target = selected.get("target")
            vuln_id = selected.get("vuln_id")

        if not action_type:
            return ""

        target_str = target if isinstance(target, str) and target else None
        vuln_str = vuln_id if isinstance(vuln_id, str) and vuln_id else None

        exact = [
            row
            for row in candidates
            if row.decision.action_type == action_type
            and row.decision.target == target_str
            and row.decision.vuln_id == vuln_str
        ]
        if exact:
            exact.sort(key=lambda item: item.heuristic_score, reverse=True)
            return exact[0].candidate_id

        same_action_target = [
            row
            for row in candidates
            if row.decision.action_type == action_type and row.decision.target == target_str
        ]
        if same_action_target:
            same_action_target.sort(key=lambda item: item.heuristic_score, reverse=True)
            return same_action_target[0].candidate_id

        same_action = [row for row in candidates if row.decision.action_type == action_type]
        if same_action:
            same_action.sort(key=lambda item: item.heuristic_score, reverse=True)
            return same_action[0].candidate_id

        return ""


class OpponentModeler:
    def __init__(self, *, self_agent_type: AgentType, max_history: int = 12) -> None:
        self.self_agent_type = self_agent_type
        self.max_history = max(6, max_history)
        self._history: list[dict[str, Any]] = []
        self._last_observed_turn = -1

    def observe(self, state: WorldState) -> None:
        if state.turn <= self._last_observed_turn:
            return
        for log in state.action_logs:
            if log.agent_type not in {"Red", "Blue"}:
                continue
            if log.agent_type == self.self_agent_type:
                continue
            metadata = log.metadata if isinstance(log.metadata, dict) else {}
            self._history.append(
                {
                    "turn": state.turn,
                    "agent_type": log.agent_type,
                    "action_type": log.action_type,
                    "target": metadata.get("target"),
                    "effect": metadata.get("referee_effect"),
                    "score_awarded": metadata.get("score_awarded", 0),
                }
            )
        self._history = self._history[-self.max_history :]
        self._last_observed_turn = state.turn

    def build(self) -> dict[str, Any]:
        action_counts: dict[str, int] = {}
        target_counts: dict[str, int] = {}
        recent = self._history[-6:]
        for row in recent:
            action = str(row.get("action_type", "Unknown"))
            action_counts[action] = action_counts.get(action, 0) + 1
            target = row.get("target")
            if isinstance(target, str) and target:
                target_counts[target] = target_counts.get(target, 0) + 1

        pressure_target = None
        if target_counts:
            pressure_target = max(target_counts.items(), key=lambda item: item[1])[0]

        inferred_phase = "reconnaissance"
        if action_counts.get("ExfiltrateDatabase", 0) > 0:
            inferred_phase = "objective"
        elif action_counts.get("LateralMove", 0) > 0 or action_counts.get("ExploitService", 0) > 0:
            inferred_phase = "intrusion"

        return {
            "recent_actions": recent,
            "action_counts": action_counts,
            "target_counts": target_counts,
            "pressure_target": pressure_target,
            "inferred_phase": inferred_phase,
        }


class ReflectionEngine:
    def __init__(self, *, self_agent_type: AgentType, max_items: int = 8) -> None:
        self.self_agent_type = self_agent_type
        self.max_items = max(4, max_items)
        self._records: list[dict[str, Any]] = []
        self._last_observed_turn = -1
        self._last_expected: dict[str, Any] | None = None

    def set_expected(self, *, decision: AgentDecision, candidate_id: str, thought: str) -> None:
        self._last_expected = {
            "action_type": decision.action_type,
            "target": decision.target,
            "vuln_id": decision.vuln_id,
            "candidate_id": candidate_id,
            "thought": thought,
        }

    def observe(self, state: WorldState) -> None:
        if state.turn <= self._last_observed_turn:
            return
        own_log = next((log for log in state.action_logs if log.agent_type == self.self_agent_type), None)
        if own_log is None:
            self._last_observed_turn = state.turn
            return

        metadata = own_log.metadata if isinstance(own_log.metadata, dict) else {}
        score_awarded = int(metadata.get("score_awarded", 0) or 0)
        effect = str(metadata.get("referee_effect", "unknown"))
        execution_status = metadata.get("execution")
        validation_status = metadata.get("validation")
        success = execution_status != "failed_after_judgement" and validation_status == "passed"

        adjustment = "维持当前策略"
        if not success:
            adjustment = "当前动作未落地成功，下一回合优先切换目标或漏洞。"
        elif score_awarded == 0 and own_log.action_type in {"Recon", "Monitor"}:
            adjustment = "被动动作收益不足，下一回合应提升动作等级。"
        elif score_awarded == 0:
            adjustment = "收益偏低，下一回合应优化目标选择。"

        self._records.append(
            {
                "turn": state.turn,
                "expected": self._last_expected or {},
                "actual": {
                    "action_type": own_log.action_type,
                    "target": metadata.get("target"),
                    "vuln_id": metadata.get("vuln_id"),
                    "score_awarded": score_awarded,
                    "effect": effect,
                    "success": success,
                },
                "adjustment": adjustment,
            }
        )
        self._records = self._records[-self.max_items :]
        self._last_observed_turn = state.turn

    def recent(self, limit: int = 3) -> list[dict[str, Any]]:
        return self._records[-max(1, limit) :]

    def failure_streak(self, *, limit: int = 4) -> int:
        streak = 0
        for row in reversed(self._records[-max(1, limit) :]):
            actual = row.get("actual", {})
            if actual.get("success") and int(actual.get("score_awarded", 0) or 0) > 0:
                break
            streak += 1
        return streak


class AntiStagnationController:
    def __init__(
        self,
        *,
        self_agent_type: AgentType,
        max_recon_streak: int = 2,
        max_monitor_streak: int = 2,
        no_progress_threshold: int = 3,
    ) -> None:
        self.self_agent_type = self_agent_type
        self.max_recon_streak = max(1, max_recon_streak)
        self.max_monitor_streak = max(1, max_monitor_streak)
        self.no_progress_threshold = max(2, no_progress_threshold)
        self._last_action_type: str | None = None
        self._action_streak = 0
        self._last_progress_signature: tuple[Any, ...] | None = None
        self._no_progress_rounds = 0
        self._last_observed_turn = -1

    def observe_state(self, state: WorldState) -> None:
        if state.turn <= self._last_observed_turn:
            return
        compromised_count = sum(1 for node in state.network_nodes.values() if node.status == "Compromised")
        if self.self_agent_type == "Red":
            signature = (state.red_score, compromised_count, state.exposure_level)
        else:
            signature = (state.blue_score, state.system_health, compromised_count)
        if self._last_progress_signature == signature:
            self._no_progress_rounds += 1
        else:
            self._no_progress_rounds = 0
        self._last_progress_signature = signature
        self._last_observed_turn = state.turn

    def observe_decision(self, action_type: str) -> None:
        if self._last_action_type == action_type:
            self._action_streak += 1
        else:
            self._last_action_type = action_type
            self._action_streak = 1

    def no_progress_rounds(self) -> int:
        return self._no_progress_rounds

    def apply(
        self,
        candidates: list[CandidateAction],
        *,
        battle_state: dict[str, Any],
    ) -> list[CandidateAction]:
        if not candidates:
            return []
        filtered = list(candidates)

        if self.self_agent_type == "Red" and self._last_action_type == "Recon" and self._action_streak >= self.max_recon_streak:
            non_recon = [row for row in filtered if row.decision.action_type != "Recon"]
            if non_recon:
                filtered = non_recon

        if self.self_agent_type == "Blue" and self._last_action_type == "Monitor" and self._action_streak >= self.max_monitor_streak:
            non_monitor = [row for row in filtered if row.decision.action_type != "Monitor"]
            if non_monitor:
                filtered = non_monitor

        critical_assets_compromised = battle_state.get("critical_assets_compromised", [])
        if self.self_agent_type == "Blue" and critical_assets_compromised:
            non_monitor = [row for row in filtered if row.decision.action_type != "Monitor"]
            if non_monitor:
                filtered = non_monitor

        if self._no_progress_rounds >= self.no_progress_threshold:
            if self.self_agent_type == "Red":
                progressive = [row for row in filtered if row.decision.action_type not in RED_PASSIVE_ACTIONS]
            else:
                progressive = [row for row in filtered if row.decision.action_type not in BLUE_PASSIVE_ACTIONS]
            if progressive:
                filtered = progressive

        filtered.sort(key=lambda row: row.heuristic_score, reverse=True)
        return filtered


class FallbackPlanner:
    def choose(
        self,
        *,
        candidates: list[CandidateAction],
        agent_type: AgentType,
        opponent_model: dict[str, Any],
        reflections: list[dict[str, Any]],
    ) -> CandidateAction:
        if not candidates:
            raise LLMDecisionError("FallbackPlanner 无可执行候选动作。")

        pressure_target = opponent_model.get("pressure_target")
        reflection_penalty = 0
        if reflections:
            latest = reflections[-1]
            adjustment = str(latest.get("adjustment", ""))
            if "提升动作等级" in adjustment:
                reflection_penalty = 8

        def score(row: CandidateAction) -> tuple[float, str]:
            base = row.heuristic_score
            if pressure_target and row.decision.target == pressure_target:
                base += 6
            if reflection_penalty and row.decision.action_type in {"Recon", "Monitor"}:
                base -= reflection_penalty
            if agent_type == "Blue" and row.decision.action_type == "Monitor":
                base -= 4
            if agent_type == "Red" and row.decision.action_type == "Recon":
                base -= 4
            return base, row.candidate_id

        return sorted(candidates, key=score, reverse=True)[0]


def build_battle_state(
    state: WorldState,
    *,
    agent_type: AgentType,
    failure_streak: int,
    no_progress_rounds: int,
    recent_alerts: Iterable[SecurityAlert] | None = None,
) -> dict[str, Any]:
    compromised_nodes = sorted(node_name for node_name, node in state.network_nodes.items() if node.status == "Compromised")
    down_nodes = sorted(node_name for node_name, node in state.network_nodes.items() if node.status == "Down")
    critical_assets_compromised = [node for node in compromised_nodes if node in CRITICAL_NODES]
    critical_assets_down = [node for node in down_nodes if node in CRITICAL_NODES]

    if agent_type == "Red":
        killchain_phase = "recon"
        if any(node in compromised_nodes for node in ("web", "fw")):
            killchain_phase = "foothold"
        if any(node in compromised_nodes for node in ("app", "storage")):
            killchain_phase = "lateral"
        if "db" in compromised_nodes:
            killchain_phase = "objective"
    else:
        killchain_phase = "stabilize"
        if critical_assets_compromised:
            killchain_phase = "containment"
        elif critical_assets_down:
            killchain_phase = "restoration"

    pressure_targets: list[str] = []
    if recent_alerts:
        for alert in recent_alerts:
            if alert.target:
                pressure_targets.append(alert.target)

    return {
        "turn": state.turn,
        "agent_type": agent_type,
        "system_health": state.system_health,
        "exposure_level": state.exposure_level,
        "red_score": state.red_score,
        "blue_score": state.blue_score,
        "compromised_nodes": compromised_nodes,
        "down_nodes": down_nodes,
        "critical_assets_compromised": critical_assets_compromised,
        "critical_assets_down": critical_assets_down,
        "killchain_phase": killchain_phase,
        "failure_streak": failure_streak,
        "no_progress_rounds": no_progress_rounds,
        "pressure_targets": pressure_targets,
    }
