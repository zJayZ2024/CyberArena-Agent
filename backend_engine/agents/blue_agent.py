from pathlib import Path
from typing import Any, Iterable, Mapping

from backend_engine.agents.llm_agent import BaseLLMAgent, LLMDecisionError
from backend_engine.core.models import AgentDecision, SecurityAlert, VulnerabilityInfo, WorldState


def _vulnerability_score(value: VulnerabilityInfo | dict[str, Any]) -> int:
    if isinstance(value, VulnerabilityInfo):
        return value.score
    if isinstance(value, dict):
        raw_score = value.get("score", 0)
        if isinstance(raw_score, (int, float)):
            return int(raw_score)
    return 0


def _pick_best_vuln_id(vulnerabilities: Mapping[str, VulnerabilityInfo | dict[str, Any]] | None) -> str | None:
    if not vulnerabilities:
        return None
    vuln_id, _ = max(vulnerabilities.items(), key=lambda item: (_vulnerability_score(item[1]), item[0]))
    return vuln_id


class BlueAgent(BaseLLMAgent):
    def __init__(self, *, strict_llm: bool = False) -> None:
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "blue_defender.md"
        super().__init__(
            agent_name="Blue",
            agent_type="Blue",
            prompt_path=prompt_path,
            max_retries=3,
        )
        self.strict_llm = strict_llm
        self._last_pressure_target: str | None = None
        self._last_pressure_turn: int | None = None
        self._same_target_pressure_streak = 0

    def decide(
        self,
        state: WorldState,
        recent_logs: Iterable[SecurityAlert] | None = None,
        context_markdown: str | None = None,
    ) -> AgentDecision:
        if not context_markdown:
            raise LLMDecisionError("蓝方缺少 context_markdown，无法进行 LLM 决策。")

        allowed_targets = set(state.network_nodes)
        allowed_targets.update({"network", "all"})
        sop_alert, allow_sop_override = self._evaluate_monitor_sop(
            state,
            recent_logs=recent_logs,
        )

        try:
            decision = super().decide(
                state,
                context_markdown,
                allowed_targets=allowed_targets,
            )
            self._validate_alert_sop(
                state,
                decision,
                sop_alert=sop_alert,
                allow_sop_override=allow_sop_override,
            )
            return decision
        except Exception as exc:
            if self.strict_llm:
                raise LLMDecisionError(f"BlueAgent 严格 LLM 模式下决策失败：{exc}") from exc
            print(f"[BlueAgent] LLM 决策失败，回退到规则策略：{exc}")
            return self._fallback_decide(
                state,
                recent_logs=recent_logs,
                sop_alert=sop_alert,
                allow_sop_override=allow_sop_override,
            )

    def _find_monitor_only_alert(
        self,
        recent_logs: Iterable[SecurityAlert] | None = None,
    ) -> SecurityAlert | None:
        if not recent_logs:
            return None

        for alert in reversed(list(recent_logs)):
            if alert.source_action == "Recon" or alert.severity == "WARN":
                return alert
        return None

    def _evaluate_monitor_sop(
        self,
        state: WorldState,
        recent_logs: Iterable[SecurityAlert] | None = None,
    ) -> tuple[SecurityAlert | None, bool]:
        sop_alert = self._find_monitor_only_alert(recent_logs)
        if sop_alert is None or not sop_alert.target:
            self._last_pressure_target = None
            self._same_target_pressure_streak = 0
            self._last_pressure_turn = state.turn
            return sop_alert, False

        if (
            self._last_pressure_target == sop_alert.target
            and self._last_pressure_turn is not None
            and state.turn == self._last_pressure_turn + 1
        ):
            self._same_target_pressure_streak += 1
        else:
            self._same_target_pressure_streak = 1

        self._last_pressure_target = sop_alert.target
        self._last_pressure_turn = state.turn
        return sop_alert, self._same_target_pressure_streak >= 2

    def _validate_alert_sop(
        self,
        state: WorldState,
        decision: AgentDecision,
        *,
        sop_alert: SecurityAlert | None,
        allow_sop_override: bool,
    ) -> None:
        if sop_alert is None:
            return
        if allow_sop_override:
            target = sop_alert.target
            if target and target in state.network_nodes:
                vuln_id = _pick_best_vuln_id(state.network_nodes[target].vulnerabilities)
                if vuln_id and decision.action_type == "Monitor":
                    raise LLMDecisionError(
                        "同一节点连续两轮及以上触发告警且存在可修补漏洞时，"
                        "应触发高阶反制例外并优先选择 PatchNode。"
                    )
            return
        if decision.action_type != "Monitor":
            raise LLMDecisionError(
                "蓝方 SOP 要求：对于 source_action=Recon 或 severity=WARN 的告警，"
                "必须使用 Monitor。若同一节点连续两轮及以上触发告警，才允许升级为 PatchNode。"
            )

    def _fallback_decide(
        self,
        state: WorldState,
        recent_logs: Iterable[SecurityAlert] | None = None,
        *,
        sop_alert: SecurityAlert | None = None,
        allow_sop_override: bool = False,
    ) -> AgentDecision:
        nodes = state.network_nodes
        monitor_only_alert = sop_alert if sop_alert is not None else self._find_monitor_only_alert(recent_logs)

        if monitor_only_alert is not None:
            target = monitor_only_alert.target if monitor_only_alert.target in nodes else "network"
            if allow_sop_override and target in nodes:
                vuln_id = _pick_best_vuln_id(nodes[target].vulnerabilities)
                if vuln_id:
                    return AgentDecision(
                        agent_type="Blue",
                        thought=(
                            f"{target.upper()} 已连续两轮触发 Recon/WARN 告警，"
                            "触发高阶反制例外，升级处置并优先修补高价值漏洞。"
                        ),
                        action_type="PatchNode",
                        target=target,
                        vuln_id=vuln_id,
                        payload=f"触发连续攻击例外，优先修补 {target} 的 vuln_id={vuln_id}",
                    )
            return AgentDecision(
                agent_type="Blue",
                thought=(
                    "最新告警属于 Recon 或 WARN 级别。根据 SOP，蓝方此时必须执行 "
                    "Monitor，避免高扰动修补影响业务稳定性。"
                ),
                action_type="Monitor",
                target=target,
                payload=f"针对 {target} 提升监控与告警灵敏度，保持业务端口持续可用",
            )

        if recent_logs:
            for alert in reversed(list(recent_logs)):
                if not alert.target or alert.target not in nodes:
                    continue

                target_node = nodes[alert.target]
                if target_node.status == "Compromised":
                    return AgentDecision(
                        agent_type="Blue",
                        thought=f"{alert.target.upper()} 已失陷，必须优先恢复。",
                        action_type="RestoreNode",
                        target=alert.target,
                        payload=f"恢复 {alert.target} 到干净基线",
                    )

                vuln_id = _pick_best_vuln_id(target_node.vulnerabilities)
                if vuln_id:
                    return AgentDecision(
                        agent_type="Blue",
                        thought=f"上一阶段安全告警指向 {alert.target.upper()}，优先修补高价值漏洞。",
                        action_type="PatchNode",
                        target=alert.target,
                        vuln_id=vuln_id,
                        payload=f"修补 {alert.target} 的 vuln_id={vuln_id}",
                    )

        for node_name in ("db", "app", "web"):
            if nodes[node_name].status == "Compromised":
                return AgentDecision(
                    agent_type="Blue",
                    thought=f"{node_name.upper()} 已失陷，必须优先隔离并恢复。",
                    action_type="RestoreNode",
                    target=node_name,
                    payload=f"隔离 {node_name} 并从干净快照恢复",
                )

        for node_name in ("app", "web", "db"):
            vuln_id = _pick_best_vuln_id(nodes[node_name].vulnerabilities)
            if nodes[node_name].status == "Normal" and vuln_id:
                return AgentDecision(
                    agent_type="Blue",
                    thought=f"{node_name.upper()} 仍存在已知高价值漏洞，应立即修补。",
                    action_type="PatchNode",
                    target=node_name,
                    vuln_id=vuln_id,
                    payload=f"修补 {node_name} 上的 vuln_id={vuln_id}",
                )

        return AgentDecision(
            agent_type="Blue",
            thought="当前未观察到需要立刻处置的严重异常，继续保持全局监控。",
            action_type="Monitor",
            target="network",
            payload="审查告警并维持监控覆盖",
        )
