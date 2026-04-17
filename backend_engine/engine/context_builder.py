from __future__ import annotations

from typing import Any

from backend_engine.core.models import ActionLog, SecurityAlert, VulnerabilityInfo, WorldState
from backend_engine.engine.actions import PERIMETER_KEYWORDS, list_legal_actions


def _format_ports(ports: list[int]) -> str:
    if not ports:
        return "无"
    return ", ".join(str(port) for port in ports)


def _format_single_vulnerability(vuln_id: str, vulnerability: VulnerabilityInfo | dict[str, Any] | str) -> str:
    if isinstance(vulnerability, str):
        return vuln_id
    if isinstance(vulnerability, VulnerabilityInfo):
        return (
            f"{vuln_id}"
            f"(severity={vulnerability.severity}, score={vulnerability.score}, "
            f"exploit={vulnerability.exploit_prob:.2f}, patch={vulnerability.patch_prob:.2f})"
        )
    severity = vulnerability.get("severity", "Unknown")
    score = vulnerability.get("score", "?")
    exploit_prob = vulnerability.get("exploit_prob", "?")
    patch_prob = vulnerability.get("patch_prob", "?")
    return f"{vuln_id}(severity={severity}, score={score}, exploit={exploit_prob}, patch={patch_prob})"


def _format_vulnerabilities(vulnerabilities: Any) -> str:
    if not vulnerabilities:
        return "无"
    if isinstance(vulnerabilities, list):
        return ", ".join(vulnerabilities)
    if isinstance(vulnerabilities, dict):
        return ", ".join(
            _format_single_vulnerability(vuln_id, vulnerability)
            for vuln_id, vulnerability in sorted(vulnerabilities.items())
        )
    return str(vulnerabilities)


def _is_internal_node(node_name: str) -> bool:
    lowered = node_name.lower()
    if lowered == "internet":
        return False
    return not any(keyword in lowered for keyword in PERIMETER_KEYWORDS)


def _derive_initial_visible_nodes(state: WorldState) -> set[str]:
    visible_nodes = set(state.red_visible_nodes)
    if visible_nodes:
        return visible_nodes
    for node_name in state.network_nodes:
        lowered = node_name.lower()
        if lowered == "internet" or any(keyword in lowered for keyword in PERIMETER_KEYWORDS):
            visible_nodes.add(node_name)
    return visible_nodes


def _format_action_catalog(agent_type: str) -> list[str]:
    actions = list_legal_actions(agent_type, locale="zh")
    if not actions:
        return ["- 当前无合法动作。"]
    return [f"- `{row['action_type']}`: {row['summary']}" for row in actions]


def _format_recent_log_entry(entry: Any) -> str:
    if isinstance(entry, SecurityAlert):
        prefix = f"[{entry.severity}]"
        if entry.target:
            return f"- {prefix} {entry.target}: {entry.message}"
        return f"- {prefix} {entry.message}"
    if isinstance(entry, ActionLog):
        return f"- [{entry.agent_type}] `{entry.action_type}`: {entry.referee_result}"
    if isinstance(entry, str):
        return f"- {entry}"
    if isinstance(entry, dict):
        agent_type = entry.get("agent_type", "Unknown")
        action_type = entry.get("action_type", entry.get("type", "Event"))
        detail = (
            entry.get("referee_result")
            or entry.get("message")
            or entry.get("summary")
            or entry.get("content")
            or "无详细信息"
        )
        return f"- [{agent_type}] `{action_type}`: {detail}"
    return f"- {str(entry)}"


def _blue_priority_from_alerts(recent_logs: list[Any]) -> str:
    has_crit = False
    has_warn = False
    for row in recent_logs:
        if isinstance(row, SecurityAlert):
            if row.severity == "CRIT":
                has_crit = True
            elif row.severity == "WARN":
                has_warn = True
    if has_crit:
        return "P0"
    if has_warn:
        return "P1"
    return "P2"


def build_red_context(state: WorldState) -> str:
    visible_nodes = _derive_initial_visible_nodes(state)
    recon_targets = set(state.red_recon_nodes)
    controlled_nodes = {
        node_name
        for node_name, node in state.network_nodes.items()
        if node.status == "Compromised"
    }
    anchored_nodes = [node_name for node_name in state.red_anchored_nodes if node_name in state.network_nodes]
    core_assets = [node_name for node_name in state.core_assets if node_name in state.network_nodes] or ["db"]
    visible_nodes |= controlled_nodes
    visible_nodes |= recon_targets

    hidden_internal_count = sum(
        1
        for node_name in state.network_nodes
        if node_name not in visible_nodes and _is_internal_node(node_name)
    )

    lines = [
        "# 红方感知上下文",
        "",
        "## 当前目标",
        f"- 核心资产：{', '.join(core_assets)}",
        "- 决策优先级：战局胜利 > 回合得分",
        "- 命令协议：只能使用候选中给出的真实 raw_command。",
        f"- 胜负锁定：{state.winner_locked} ({state.winner_side or '未锁定'})",
        f"- 锁定原因：{state.winner_reason or '无'}",
        "",
        "## 当前态势",
        f"- 当前回合：{state.turn}",
        f"- 已控制节点数：{len(controlled_nodes)}",
        f"- 已侦察节点数：{len(recon_targets)}",
        f"- 已扎根节点：{', '.join(sorted(anchored_nodes)) if anchored_nodes else '无'}",
        "",
        "## 已控制节点",
    ]

    if controlled_nodes:
        for node_name in sorted(controlled_nodes):
            node = state.network_nodes[node_name]
            lines.extend(
                [
                    f"### `{node_name}`",
                    f"- 状态：{node.status}",
                    f"- 已发现暴露服务：{_format_ports(state.red_known_services.get(node_name, node.exposed_ports))}",
                    f"- 已知漏洞：{_format_vulnerabilities(state.red_known_vulnerabilities.get(node_name, node.vulnerabilities))}",
                    f"- 扎根状态：{'是' if node_name in anchored_nodes else '否'}",
                ]
            )
    else:
        lines.append("- 暂无已控制节点。")

    lines.extend(["", "## 已发现节点"])
    discovered_only = sorted(visible_nodes - controlled_nodes)
    if discovered_only:
        for node_name in discovered_only:
            node = state.network_nodes[node_name]
            status = node.status if node_name in recon_targets else "未知"
            vulnerabilities = state.red_known_vulnerabilities.get(node_name, {}) if node_name in recon_targets else {}
            lines.extend(
                [
                    f"### `{node_name}`",
                    f"- 可见来源：{'Recon' if node_name in recon_targets else '边界视野/相邻扩展'}",
                    f"- 状态：{status}",
                    f"- 已发现暴露服务：{_format_ports(state.red_known_services.get(node_name, []))}",
                    f"- 已知漏洞：{_format_vulnerabilities(vulnerabilities)}",
                ]
            )
    else:
        lines.append("- 暂无除已控制节点外的额外发现。")

    lines.extend(["", "## 战争迷雾"])
    if hidden_internal_count > 0:
        lines.append(f"- 仍有 {hidden_internal_count} 个未探索内网节点处于战争迷雾。")
    else:
        lines.append("- 当前快照下不存在额外未探索内网节点。")

    lines.extend(["", "## 可用动作"])
    lines.extend(_format_action_catalog("Red"))
    return "\n".join(lines)


def build_blue_context(state: WorldState, recent_logs: list[Any]) -> str:
    core_assets = [node_name for node_name in state.core_assets if node_name in state.network_nodes] or ["db"]
    priority_stage = _blue_priority_from_alerts(recent_logs)
    lines = [
        "# 蓝方感知上下文",
        "",
        "## 系统总览",
        f"- 当前回合：{state.turn}",
        f"- 系统健康度：{state.system_health}",
        f"- 暴露度：{state.exposure_level}",
        f"- 红方得分：{state.red_score}",
        f"- 蓝方得分：{state.blue_score}",
        f"- 核心资产：{', '.join(core_assets)}",
        f"- 当前优先级阶段：{priority_stage}",
        "- 规则协议：只能使用候选中给出的 defense_rule。",
        f"- 胜负锁定：{state.winner_locked} ({state.winner_side or '未锁定'})",
        "",
        "## 全局拓扑（蓝方可见）",
    ]

    for node_name, node in sorted(state.network_nodes.items()):
        risk_level = "LOW"
        if node.status == "Compromised":
            risk_level = "CRIT"
        elif node.status == "Down":
            risk_level = "WARN"
        elif node_name in core_assets:
            risk_level = "ELEVATED"

        confirmed_map = state.blue_known_vulnerabilities.get(node_name, {})
        confirmed_vulns = sorted(
            vuln_id for vuln_id in confirmed_map.keys()
            if isinstance(vuln_id, str) and vuln_id
        ) if isinstance(confirmed_map, dict) else []
        pending_count = max(0, len(node.vulnerabilities) - len(confirmed_vulns))
        lines.extend(
            [
                f"### `{node_name}`",
                f"- 状态：{node.status}",
                f"- 风险等级：{risk_level}",
                f"- 暴露服务：{_format_ports(node.exposed_ports)}",
                f"- 已确认漏洞：{', '.join(confirmed_vulns) if confirmed_vulns else '无'}",
                f"- 待确认漏洞数：{pending_count}",
                f"- 是否已监控：{'是' if node_name in state.blue_monitored_nodes else '否'}",
            ]
        )

    lines.extend(["", "## 上一回合安全告警"])
    if recent_logs:
        lines.extend(_format_recent_log_entry(entry) for entry in recent_logs)
    else:
        lines.append("- 上一回合无新增安全告警。")

    lines.extend(["", "## 可用动作"])
    lines.extend(_format_action_catalog("Blue"))
    return "\n".join(lines)
