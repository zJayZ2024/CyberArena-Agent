from __future__ import annotations

from typing import Any

from backend_engine.core.models import AgentDecision, VulnerabilityInfo, WorldState


def _vulnerability_score(value: VulnerabilityInfo | dict[str, Any]) -> int:
    if isinstance(value, VulnerabilityInfo):
        return value.score
    if isinstance(value, dict):
        raw_score = value.get("score", 0)
        if isinstance(raw_score, (int, float)):
            return int(raw_score)
    return 0


def _pick_best_vuln_id(vulnerabilities: dict[str, VulnerabilityInfo | dict[str, Any]]) -> str | None:
    if not vulnerabilities:
        return None
    vuln_id, _ = max(vulnerabilities.items(), key=lambda item: (_vulnerability_score(item[1]), item[0]))
    return vuln_id


def _infer_vuln_type(vuln_id: str | None) -> str:
    if not vuln_id:
        return "Unknown"
    lowered = vuln_id.lower()
    if any(tag in lowered for tag in ("rce", "log4shell", "spring4shell", "struts2", "eternalblue", "samba")):
        return "RCE"
    if any(tag in lowered for tag in ("auth_bypass", "authbypass", "zerologon", "sessionhijack")):
        return "AuthBypass"
    if any(tag in lowered for tag in ("sqli", "injection", "sql")):
        return "Injection"
    return "Unknown"


class BlueAgent:
    agent_name = "Blue"

    def __init__(self) -> None:
        self._last_recon_target: str | None = None
        self._last_recon_turn: int | None = None
        self._recon_streak = 0

    def decide(self, state: WorldState, red_action: AgentDecision | None = None) -> AgentDecision:
        nodes = state.network_nodes

        for node_name in ("db", "storage", "app", "web", "fw"):
            if node_name in nodes and nodes[node_name].status in {"Compromised", "Down"}:
                vuln_id = _pick_best_vuln_id(nodes[node_name].vulnerabilities)
                return AgentDecision(
                    agent_type="Blue",
                    thought=f"{node_name.upper()} 已失陷或下线，按应急预案先恢复业务并清理高风险漏洞。",
                    action_type="RestoreNode",
                    target=node_name,
                    vuln_id=vuln_id,
                    payload=f"从干净快照恢复 {node_name}，并修补 vuln_id={vuln_id}" if vuln_id else f"从干净快照恢复 {node_name}",
                )

        if red_action and red_action.target and red_action.target in nodes:
            target = red_action.target
            target_node = nodes[target]

            if red_action.action_type == "Recon":
                self._update_recon_streak(state.turn, target)
                if self._recon_streak >= 2:
                    vuln_id = _pick_best_vuln_id(target_node.vulnerabilities)
                    vuln_type = _infer_vuln_type(vuln_id)
                    if vuln_id and vuln_type != "Unknown":
                        return AgentDecision(
                            agent_type="Blue",
                            thought=f"{target.upper()} 连续遭到侦察，已识别漏洞类型为 {vuln_type}，升级为定向修补。",
                            action_type="PatchNode",
                            target=target,
                            vuln_id=vuln_id,
                            payload=f"触发连续侦察处置，修补 {target} 的 {vuln_type} 漏洞 vuln_id={vuln_id}",
                        )
                return AgentDecision(
                    agent_type="Blue",
                    thought="检测到侦察行为，先保持监控与取证，等待更明确攻击迹象。",
                    action_type="Monitor",
                    target=target,
                    payload=f"针对 {target} 提升日志采集与告警灵敏度",
                )

            self._reset_recon_streak(state.turn)

            vuln_id = red_action.vuln_id if red_action.vuln_id in target_node.vulnerabilities else None
            if not vuln_id:
                vuln_id = _pick_best_vuln_id(target_node.vulnerabilities)
            vuln_type = _infer_vuln_type(vuln_id)

            if red_action.action_type == "ExfiltrateDatabase":
                return AgentDecision(
                    agent_type="Blue",
                    thought=f"检测到针对 {target.upper()} 的数据窃取行为，立即隔离以阻断外传通道。",
                    action_type="Isolate",
                    target=target,
                    vuln_id=vuln_id,
                    payload=f"紧急隔离 {target}，阻断基于 {vuln_type} 漏洞的数据外流",
                )

            if vuln_id and vuln_type == "RCE":
                return AgentDecision(
                    agent_type="Blue",
                    thought=f"已确认攻击利用的是 {vuln_type} 类型漏洞，优先隔离 {target} 进行遏制。",
                    action_type="Isolate",
                    target=target,
                    vuln_id=vuln_id,
                    payload=f"隔离 {target} 并阻断 vuln_id={vuln_id} 对应的远程执行链路",
                )

            if vuln_id and vuln_type in {"AuthBypass", "Injection"}:
                return AgentDecision(
                    agent_type="Blue",
                    thought=f"已识别 {vuln_type} 类型漏洞，执行定向修补并收敛攻击面。",
                    action_type="PatchNode",
                    target=target,
                    vuln_id=vuln_id,
                    payload=f"修补 {target} 的 vuln_id={vuln_id}，并执行认证/输入校验加固",
                )

            return AgentDecision(
                agent_type="Blue",
                thought="漏洞类型仍不明确，暂以监控优先，避免误操作。",
                action_type="Monitor",
                target=target,
                payload=f"持续监控 {target} 并补充漏洞类型研判",
            )

        self._reset_recon_streak(state.turn)
        for node_name in ("web", "app", "storage", "db", "fw"):
            if node_name not in nodes or nodes[node_name].status != "Normal":
                continue
            vuln_id = _pick_best_vuln_id(nodes[node_name].vulnerabilities)
            vuln_type = _infer_vuln_type(vuln_id)
            if vuln_id and vuln_type != "Unknown":
                return AgentDecision(
                    agent_type="Blue",
                    thought=f"{node_name.upper()} 存在已识别的 {vuln_type} 漏洞，进行预防性修补。",
                    action_type="PatchNode",
                    target=node_name,
                    vuln_id=vuln_id,
                    payload=f"预防性修补 {node_name} 的 vuln_id={vuln_id}",
                )

        return AgentDecision(
            agent_type="Blue",
            thought="当前无高置信风险，保持全局监控。",
            action_type="Monitor",
            target="network",
            payload="审查告警并维持监控覆盖",
        )

    def _reset_recon_streak(self, current_turn: int) -> None:
        self._last_recon_target = None
        self._last_recon_turn = current_turn
        self._recon_streak = 0

    def _update_recon_streak(self, current_turn: int, target: str) -> None:
        if (
            self._last_recon_target == target
            and self._last_recon_turn is not None
            and current_turn == self._last_recon_turn + 1
        ):
            self._recon_streak += 1
        else:
            self._recon_streak = 1
        self._last_recon_target = target
        self._last_recon_turn = current_turn
