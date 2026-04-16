from __future__ import annotations

from typing import Any

from backend_engine.core.models import AgentDecision, VulnerabilityInfo, WorldState

DATABASE_KEYWORDS = ("db", "database", "mysql", "postgres", "sql")


def _vulnerability_score(value: VulnerabilityInfo | dict[str, Any]) -> int:
    if isinstance(value, VulnerabilityInfo):
        return value.score
    if isinstance(value, dict):
        raw_score = value.get("score", 0)
        if isinstance(raw_score, (int, float)):
            return int(raw_score)
    return 0


def _vulnerability_exploit_prob(value: VulnerabilityInfo | dict[str, Any]) -> float:
    if isinstance(value, VulnerabilityInfo):
        return float(value.exploit_prob)
    if isinstance(value, dict):
        raw_prob = value.get("exploit_prob", 0.0)
        if isinstance(raw_prob, (int, float)):
            return float(raw_prob)
    return 0.0


def _pick_best_vuln_id(vulnerabilities: dict[str, VulnerabilityInfo | dict[str, Any]]) -> str | None:
    if not vulnerabilities:
        return None
    vuln_id, _ = max(
        vulnerabilities.items(),
        key=lambda item: (
            _vulnerability_score(item[1]) * _vulnerability_exploit_prob(item[1]),
            _vulnerability_score(item[1]),
            item[0],
        ),
    )
    return vuln_id


def _is_database_node(node_name: str) -> bool:
    lowered = node_name.lower()
    return any(keyword in lowered for keyword in DATABASE_KEYWORDS)


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


def _build_attack_payload(vuln_type: str, vuln_id: str, target: str, action: str) -> str:
    if action == "ExfiltrateDatabase":
        if vuln_type == "Injection":
            return f"利用 vuln_id={vuln_id} 构造 SQL 注入链路，对 {target} 执行分批数据导出"
        if vuln_type == "AuthBypass":
            return f"利用 vuln_id={vuln_id} 绕过认证并窃取 {target} 的敏感数据"
        return f"利用 vuln_id={vuln_id} 获取 {target} 高权限访问并执行数据导出"

    if vuln_type == "RCE":
        return f"利用 vuln_id={vuln_id} 在 {target} 触发远程代码执行并建立持久据点"
    if vuln_type == "AuthBypass":
        return f"利用 vuln_id={vuln_id} 绕过 {target} 的认证边界并横向渗透"
    if vuln_type == "Injection":
        return f"利用 vuln_id={vuln_id} 发起注入攻击，进入 {target} 执行命令与数据访问"
    return f"继续对 {target} 侦察并确认 vuln_id={vuln_id} 的可利用漏洞类型"


class RedAgent:
    agent_name = "Red"

    def decide(self, state: WorldState) -> AgentDecision:
        nodes = state.network_nodes
        recon_nodes = set(state.red_recon_nodes)

        if "web" in nodes and nodes["web"].status != "Compromised":
            if "web" not in recon_nodes:
                return AgentDecision(
                    agent_type="Red",
                    thought="先完成对 web 的侦察，明确漏洞类型后再制定攻击手法。",
                    action_type="Recon",
                    target="web",
                    payload="侦察 web 的端口、服务指纹和漏洞类型",
                )

            vuln_id = _pick_best_vuln_id(nodes["web"].vulnerabilities)
            vuln_type = _infer_vuln_type(vuln_id)
            if vuln_id and vuln_type != "Unknown":
                return AgentDecision(
                    agent_type="Red",
                    thought=f"已确认 web 上 {vuln_id} 属于 {vuln_type} 类型，执行对应的外网利用链。",
                    action_type="ExploitService",
                    target="web",
                    vuln_id=vuln_id,
                    payload=_build_attack_payload(vuln_type, vuln_id, "web", "ExploitService"),
                )
            return AgentDecision(
                agent_type="Red",
                thought="web 漏洞类型未确认，继续侦察以避免盲打。",
                action_type="Recon",
                target="web",
                payload="继续分析 web 漏洞类型并收集可利用证据",
            )

        if "web" in nodes and nodes["web"].status == "Compromised" and "app" in nodes and nodes["app"].status != "Compromised":
            if "app" not in recon_nodes:
                return AgentDecision(
                    agent_type="Red",
                    thought="已拿到 web 据点，先对 app 做内网侦察并识别漏洞类型。",
                    action_type="Recon",
                    target="app",
                    payload="通过 web 跳板侦察 app 的漏洞类型与可达性",
                )

            vuln_id = _pick_best_vuln_id(nodes["app"].vulnerabilities)
            vuln_type = _infer_vuln_type(vuln_id)
            if vuln_id and vuln_type != "Unknown":
                return AgentDecision(
                    agent_type="Red",
                    thought=f"已识别 app 上 {vuln_id} 为 {vuln_type}，按对应横向手法实施渗透。",
                    action_type="LateralMove",
                    target="app",
                    vuln_id=vuln_id,
                    payload=_build_attack_payload(vuln_type, vuln_id, "app", "LateralMove"),
                )
            return AgentDecision(
                agent_type="Red",
                thought="app 漏洞类型未确认，继续侦察，避免误用利用链。",
                action_type="Recon",
                target="app",
                payload="补充侦察 app 并确认漏洞类型",
            )

        if "app" in nodes and nodes["app"].status == "Compromised" and "storage" in nodes and nodes["storage"].status != "Compromised":
            if "storage" not in recon_nodes:
                return AgentDecision(
                    agent_type="Red",
                    thought="进入应用层后，先侦察 storage，确认漏洞类型再决定横移战术。",
                    action_type="Recon",
                    target="storage",
                    payload="侦察 storage 的 SMB/文件服务并识别漏洞类型",
                )

            vuln_id = _pick_best_vuln_id(nodes["storage"].vulnerabilities)
            vuln_type = _infer_vuln_type(vuln_id)
            if vuln_id and vuln_type != "Unknown":
                return AgentDecision(
                    agent_type="Red",
                    thought=f"已确认 storage 上 {vuln_id} 为 {vuln_type} 类型，实施针对性横向入侵。",
                    action_type="LateralMove",
                    target="storage",
                    vuln_id=vuln_id,
                    payload=_build_attack_payload(vuln_type, vuln_id, "storage", "LateralMove"),
                )
            return AgentDecision(
                agent_type="Red",
                thought="storage 漏洞类型未确认，继续侦察。",
                action_type="Recon",
                target="storage",
                payload="补充侦察 storage 并确认漏洞类型",
            )

        if "app" in nodes and nodes["app"].status == "Compromised" and "db" in nodes:
            if "db" not in recon_nodes:
                return AgentDecision(
                    agent_type="Red",
                    thought="在数据窃取前先侦察 db，确认数据库漏洞的具体类型。",
                    action_type="Recon",
                    target="db",
                    payload="侦察 db 的认证与注入类漏洞类型",
                )

            vuln_id = _pick_best_vuln_id(nodes["db"].vulnerabilities)
            vuln_type = _infer_vuln_type(vuln_id)
            if vuln_id and vuln_type != "Unknown":
                return AgentDecision(
                    agent_type="Red",
                    thought=f"已确认 db 上 {vuln_id} 的类型为 {vuln_type}，按对应路径执行数据导出。",
                    action_type="ExfiltrateDatabase",
                    target="db",
                    vuln_id=vuln_id,
                    payload=_build_attack_payload(vuln_type, vuln_id, "db", "ExfiltrateDatabase"),
                )
            return AgentDecision(
                agent_type="Red",
                thought="db 漏洞类型不明确，继续侦察避免低效攻击。",
                action_type="Recon",
                target="db",
                payload="继续侦察 db 并确认漏洞类型",
            )

        for node_name, node in nodes.items():
            if node_name == "internet" or node.status == "Down":
                continue
            if node_name not in recon_nodes and (node.status != "Compromised" or _is_database_node(node_name)):
                return AgentDecision(
                    agent_type="Red",
                    thought=f"当前链路不完整，先补充侦察 {node_name} 的漏洞类型。",
                    action_type="Recon",
                    target=node_name,
                    payload=f"补充侦察 {node_name} 并确认漏洞类型",
                )

        fallback_target = "web" if "web" in nodes else next(iter(nodes.keys()), "internet")
        return AgentDecision(
            agent_type="Red",
            thought="暂无可执行利用链，持续侦察并更新漏洞类型情报。",
            action_type="Recon",
            target=fallback_target,
            payload=f"继续侦察 {fallback_target}",
        )
