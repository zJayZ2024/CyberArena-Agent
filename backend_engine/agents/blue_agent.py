from pathlib import Path
from typing import Iterable

from backend_engine.agents.llm_agent import BaseLLMAgent, LLMDecisionError
from backend_engine.core.models import AgentDecision, SecurityAlert, WorldState


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
            return super().decide(
                state,
                context_markdown,
                allowed_targets=allowed_targets,
            )
        except Exception as exc:
            print(f"[BlueAgent] LLM 决策失败，回退到规则策略：{exc}")
            return self._fallback_decide(state, recent_logs=recent_logs)

    def _fallback_decide(
        self,
        state: WorldState,
        recent_logs: Iterable[SecurityAlert] | None = None,
    ) -> AgentDecision:
        nodes = state.network_nodes

        if recent_logs:
            for alert in reversed(list(recent_logs)):
                if not alert.target or alert.target not in nodes:
                    continue

                target_node = nodes[alert.target]
                if alert.source_action != "Recon" and (
                    target_node.vulnerabilities or target_node.status == "Compromised"
                ):
                    return AgentDecision(
                        agent_type="Blue",
                        thought=(
                            f"上一阶段安全告警指向 {alert.target.upper()}，"
                            "应立刻围绕受击节点进行遏制和修复。"
                        ),
                        action_type="RestoreNode" if target_node.status == "Compromised" else "PatchNode",
                        target=alert.target,
                        payload=f"根据安全告警优先响应 {alert.target} 的异常活动",
                    )

                if alert.source_action == "Recon":
                    return AgentDecision(
                        agent_type="Blue",
                        thought=f"{alert.target.upper()} 出现侦察痕迹，先提升对该节点的监控与告警等级。",
                        action_type="Monitor",
                        target=alert.target,
                        payload=f"针对 {alert.target} 的侦察告警执行重点监控",
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
            if nodes[node_name].status == "Normal" and nodes[node_name].vulnerabilities:
                return AgentDecision(
                    agent_type="Blue",
                    thought=f"{node_name.upper()} 仍存在已知弱点，应立即修补加固。",
                    action_type="PatchNode",
                    target=node_name,
                    payload=f"修补 {node_name} 上最优先的漏洞",
                )

        return AgentDecision(
            agent_type="Blue",
            thought="当前未观察到需要立即处置的严重异常，继续保持全局监控。",
            action_type="Monitor",
            target="network",
            payload="审查告警并维持监控覆盖",
        )
