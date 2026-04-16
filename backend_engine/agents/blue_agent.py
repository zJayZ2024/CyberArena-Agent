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
    def __init__(self) -> None:
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "blue_defender.md"
        super().__init__(
            agent_name="Blue",
            agent_type="Blue",
            prompt_path=prompt_path,
            max_retries=3,
        )

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

        try:
            decision = super().decide(
                state,
                context_markdown,
                allowed_targets=allowed_targets,
            )
            self._validate_alert_sop(decision, recent_logs=recent_logs)
            return decision
        except Exception as exc:
            print(f"[BlueAgent] LLM 决策失败，回退到规则策略：{exc}")
            return self._fallback_decide(state, recent_logs=recent_logs)

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

    def _validate_alert_sop(
        self,
        decision: AgentDecision,
        recent_logs: Iterable[SecurityAlert] | None = None,
    ) -> None:
        alert = self._find_monitor_only_alert(recent_logs)
        if alert is None:
            return
        if decision.action_type != "Monitor":
            raise LLMDecisionError(
                "蓝方 SOP 要求：对于 source_action=Recon 或 severity=WARN 的告警，"
                "必须使用 Monitor，禁止选择 PatchNode 或其他高扰动动作。"
            )

    def _fallback_decide(
        self,
        state: WorldState,
        recent_logs: Iterable[SecurityAlert] | None = None,
    ) -> AgentDecision:
        nodes = state.network_nodes
        monitor_only_alert = self._find_monitor_only_alert(recent_logs)

        if monitor_only_alert is not None:
            target = monitor_only_alert.target if monitor_only_alert.target in nodes else "network"
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
