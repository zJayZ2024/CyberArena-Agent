from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Literal

from backend_engine.core.models import AgentDecision, NetworkNode, WorldState

AgentType = Literal["Red", "Blue"]
Locale = Literal["en", "zh"]

PERIMETER_KEYWORDS = (
    "web",
    "fw",
    "firewall",
    "gateway",
    "proxy",
    "edge",
    "vpn",
    "mail",
    "dmz",
)
DATABASE_KEYWORDS = ("db", "database", "mysql", "postgres", "sql")


@dataclass(slots=True, frozen=True)
class ActionExample:
    target: str | None
    payload: str
    rationale: str

    def as_dict(self) -> dict[str, str | None]:
        return {
            "target": self.target,
            "payload": self.payload,
            "rationale": self.rationale,
        }


@dataclass(slots=True, frozen=True)
class ActionDescriptor:
    action_type: str
    agent_type: AgentType
    summary: str
    description: str
    requires_target: bool
    target_hint: str
    payload_hint: str
    preconditions: tuple[str, ...] = ()
    judgement_logic: tuple[str, ...] = ()
    examples: tuple[ActionExample, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "agent_type": self.agent_type,
            "summary": self.summary,
            "description": self.description,
            "requires_target": self.requires_target,
            "target_hint": self.target_hint,
            "payload_hint": self.payload_hint,
            "preconditions": list(self.preconditions),
            "judgement_logic": list(self.judgement_logic),
            "examples": [example.as_dict() for example in self.examples],
        }


@dataclass(slots=True)
class ActionResult:
    success: bool
    message: str
    effect: str = "none"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ActionContext:
    state: WorldState
    decision: AgentDecision
    locale: Locale = "en"
    opposing_decision: AgentDecision | None = None

    def text(self, *, en: str, zh: str) -> str:
        return zh if self.locale == "zh" else en

    def result(
        self,
        *,
        success: bool,
        effect: str,
        en: str,
        zh: str,
        metadata: Dict[str, Any] | None = None,
    ) -> ActionResult:
        base_metadata = {
            "action_type": self.decision.action_type,
            "agent_type": self.decision.agent_type,
            "target": self.decision.target,
        }
        if metadata:
            base_metadata.update(metadata)
        return ActionResult(
            success=success,
            message=self.text(en=en, zh=zh),
            effect=effect,
            metadata=base_metadata,
        )

    def get_node(self, node_name: str) -> NetworkNode | None:
        return self.state.network_nodes.get(node_name)

    def any_compromised(self, *node_names: str) -> bool:
        for node_name in node_names:
            node = self.get_node(node_name)
            if node is not None and node.status == "Compromised":
                return True
        return False

    def any_compromised_except(self, excluded_target: str | None = None) -> bool:
        for node_name, node in self.state.network_nodes.items():
            if node_name == excluded_target:
                continue
            if node.status == "Compromised":
                return True
        return False


class BaseAction(ABC):
    action_type: str
    agent_type: AgentType
    summary_en: str
    summary_zh: str
    description_en: str
    description_zh: str
    target_hint_en: str = "Use a node name that exists in world_state.network_nodes."
    target_hint_zh: str = "目标必须是 world_state.network_nodes 中存在的节点名。"
    payload_hint_en: str = "Briefly describe the intended technique, indicator, or command family."
    payload_hint_zh: str = "简要描述计划采用的技术、载荷特征或命令类型。"
    preconditions_en: tuple[str, ...] = ()
    preconditions_zh: tuple[str, ...] = ()
    judgement_logic_en: tuple[str, ...] = ()
    judgement_logic_zh: tuple[str, ...] = ()
    examples_en: tuple[ActionExample, ...] = ()
    examples_zh: tuple[ActionExample, ...] = ()
    requires_target: bool = True
    virtual_targets: tuple[str, ...] = ()

    def descriptor(self, locale: Locale = "en") -> ActionDescriptor:
        if locale == "zh":
            return ActionDescriptor(
                action_type=self.action_type,
                agent_type=self.agent_type,
                summary=self.summary_zh,
                description=self.description_zh,
                requires_target=self.requires_target,
                target_hint=self.target_hint_zh,
                payload_hint=self.payload_hint_zh,
                preconditions=self.preconditions_zh,
                judgement_logic=self.judgement_logic_zh,
                examples=self.examples_zh,
            )

        return ActionDescriptor(
            action_type=self.action_type,
            agent_type=self.agent_type,
            summary=self.summary_en,
            description=self.description_en,
            requires_target=self.requires_target,
            target_hint=self.target_hint_en,
            payload_hint=self.payload_hint_en,
            preconditions=self.preconditions_en,
            judgement_logic=self.judgement_logic_en,
            examples=self.examples_en,
        )

    def validate(self, context: ActionContext) -> ActionResult | None:
        if context.decision.agent_type != self.agent_type:
            return context.result(
                success=False,
                effect="rejected",
                en=(
                    f"Illegal actor for action {self.action_type}: "
                    f"{context.decision.agent_type} cannot use it"
                ),
                zh=f"非法执行方：动作 {self.action_type} 只能由 {self.agent_type} 使用",
            )

        target = context.decision.target
        if self.requires_target and not target:
            return context.result(
                success=False,
                effect="rejected",
                en=f"Action {self.action_type} requires a target node",
                zh=f"动作 {self.action_type} 必须指定目标节点",
            )

        if not target:
            return None

        if target in self.virtual_targets:
            return None

        if target not in context.state.network_nodes:
            return context.result(
                success=False,
                effect="rejected",
                en=f"Unknown target: {target}",
                zh=f"未知目标：{target}",
            )

        return None

    @abstractmethod
    def execute(self, context: ActionContext) -> ActionResult:
        raise NotImplementedError

    def _require_target(self, context: ActionContext) -> tuple[str | None, NetworkNode | None, ActionResult | None]:
        target = context.decision.target
        if not target:
            return None, None, context.result(
                success=False,
                effect="rejected",
                en="No target selected",
                zh="未选择目标",
            )

        node = context.state.network_nodes.get(target)
        if node is None:
            return target, None, context.result(
                success=False,
                effect="rejected",
                en=f"Unknown target: {target}",
                zh=f"未知目标：{target}",
            )

        return target, node, None

    def _reject_wrong_target_family(
        self,
        context: ActionContext,
        *,
        target: str,
        en: str,
        zh: str,
    ) -> ActionResult:
        return context.result(
            success=False,
            effect="rejected",
            en=f"{target} is not a valid target for {self.action_type}. {en}",
            zh=f"{target} 不是 {self.action_type} 的合法目标。{zh}",
        )


class ActionRegistry:
    def __init__(self) -> None:
        self._actions: Dict[str, BaseAction] = {}

    def register(self, action: BaseAction) -> BaseAction:
        if action.action_type in self._actions:
            raise ValueError(f"Duplicate action registration: {action.action_type}")
        self._actions[action.action_type] = action
        return action

    def get(self, action_type: str) -> BaseAction | None:
        return self._actions.get(action_type)

    def describe(self, action_type: str, *, locale: Locale = "en") -> dict[str, Any] | None:
        action = self.get(action_type)
        if action is None:
            return None
        return action.descriptor(locale).as_dict()

    def resolve(
        self,
        state: WorldState,
        decision: AgentDecision,
        *,
        locale: Locale = "en",
        opposing_decision: AgentDecision | None = None,
    ) -> ActionResult:
        action = self.get(decision.action_type)
        if action is None:
            return ActionResult(
                success=False,
                message=(
                    f"Illegal action: {decision.action_type}"
                    if locale == "en"
                    else f"非法动作：{decision.action_type}"
                ),
                effect="rejected",
                metadata={
                    "action_type": decision.action_type,
                    "agent_type": decision.agent_type,
                    "target": decision.target,
                },
            )

        context = ActionContext(
            state=state,
            decision=decision,
            locale=locale,
            opposing_decision=opposing_decision,
        )
        validation_error = action.validate(context)
        if validation_error is not None:
            return validation_error
        return action.execute(context)

    def list_actions(self, agent_type: AgentType, *, locale: Locale = "en") -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for action in self._actions.values():
            if action.agent_type != agent_type:
                continue
            rows.append(action.descriptor(locale).as_dict())
        return sorted(rows, key=lambda row: row["action_type"])

    def all(self) -> Iterable[BaseAction]:
        return self._actions.values()


def _is_perimeter_target(node_name: str) -> bool:
    lowered = node_name.lower()
    return any(keyword in lowered for keyword in PERIMETER_KEYWORDS)


def _is_database_target(node_name: str) -> bool:
    lowered = node_name.lower()
    return any(keyword in lowered for keyword in DATABASE_KEYWORDS)


ACTION_REGISTRY = ActionRegistry()


def list_legal_actions(agent_type: AgentType, *, locale: Locale = "en") -> list[dict[str, Any]]:
    return ACTION_REGISTRY.list_actions(agent_type, locale=locale)


def describe_action(action_type: str, *, locale: Locale = "en") -> dict[str, Any] | None:
    return ACTION_REGISTRY.describe(action_type, locale=locale)


def _register(cls):
    ACTION_REGISTRY.register(cls())
    return cls


@_register
class ReconAction(BaseAction):
    action_type = "Recon"
    agent_type = "Red"
    summary_en = "Gather intelligence on a node without directly changing ownership."
    summary_zh = "对目标节点进行侦察，不直接改变控制权。"
    description_en = (
        "Low-impact reconnaissance used to observe services, status, and likely weaknesses "
        "before committing to exploitation."
    )
    description_zh = "低影响侦察动作，用于在正式攻击前收集服务暴露、节点状态和潜在弱点。"
    preconditions_en = (
        "The target must exist in world_state.network_nodes.",
        "Recon can be used against defended or normal nodes.",
    )
    preconditions_zh = (
        "目标必须存在于 world_state.network_nodes 中。",
        "侦察可以针对普通态或防御态节点执行。",
    )
    judgement_logic_en = (
        "Recon never compromises the target by itself.",
        "The referee returns observations in metadata without mutating the topology.",
    )
    judgement_logic_zh = (
        "侦察本身不会直接拿下目标。",
        "裁判会把观察结果写入 metadata，但不会修改拓扑状态。",
    )
    examples_en = (
        ActionExample(
            target="web",
            payload="Quiet HTTP fingerprinting and banner collection",
            rationale="Probe the public web tier before selecting an exploit path.",
        ),
    )
    examples_zh = (
        ActionExample(
            target="web",
            payload="低噪声 HTTP 指纹识别与 Banner 收集",
            rationale="先摸清公网 Web 的服务特征，再决定下一步攻击路径。",
        ),
    )

    def execute(self, context: ActionContext) -> ActionResult:
        target, node, error = self._require_target(context)
        if error is not None or target is None or node is None:
            return error  # type: ignore[return-value]

        return context.result(
            success=True,
            effect="intel",
            en=(
                f"Recon completed against {target}; services and exposure were observed "
                "without changing node ownership"
            ),
            zh=f"已完成对 {target} 的侦察；已获得服务暴露信息，但未改变节点控制权",
            metadata={
                "observed_status": node.status,
                "observed_ports": list(node.exposed_ports),
                "vulnerability_count": len(node.vulnerabilities),
                "suspected_vulnerabilities": list(node.vulnerabilities),
            },
        )


@_register
class ExploitServiceAction(BaseAction):
    action_type = "ExploitService"
    agent_type = "Red"
    summary_en = "Exploit an internet-facing service on a perimeter node."
    summary_zh = "利用边界节点上的对外服务漏洞。"
    description_en = (
        "Directly attack an exposed service. This is intended for initial access against "
        "public-facing assets, not for internal pivoting."
    )
    description_zh = "直接攻击对外暴露的服务。该动作用于初始突破，不用于内网横移。"
    preconditions_en = (
        "The target must be a perimeter node such as web, firewall, proxy, or gateway.",
        "The target must expose at least one port.",
        "The target must still have exploitable vulnerabilities.",
    )
    preconditions_zh = (
        "目标必须是边界节点，例如 web、firewall、proxy、gateway。",
        "目标必须存在对外暴露端口。",
        "目标仍需存在可利用漏洞。",
    )
    judgement_logic_en = (
        "If the node is already defended, the attack is blocked.",
        "If the node is already compromised, the action is redundant and fails.",
        "On success, the node becomes Compromised.",
    )
    judgement_logic_zh = (
        "若节点已处于 Defended，则攻击被拦截。",
        "若节点已处于 Compromised，则该动作属于重复攻击并失败。",
        "成功后节点状态变为 Compromised。",
    )
    examples_en = (
        ActionExample(
            target="web",
            payload="Exploit CVE-WEB-2026-0001 via the public HTTP service",
            rationale="Use a public service vulnerability for initial access.",
        ),
    )
    examples_zh = (
        ActionExample(
            target="web",
            payload="通过公网 HTTP 服务利用 CVE-WEB-2026-0001",
            rationale="利用公网服务漏洞建立初始据点。",
        ),
    )

    def execute(self, context: ActionContext) -> ActionResult:
        target, node, error = self._require_target(context)
        if error is not None or target is None or node is None:
            return error  # type: ignore[return-value]

        if not _is_perimeter_target(target):
            return self._reject_wrong_target_family(
                context,
                target=target,
                en="Use LateralMove for internal assets after gaining a foothold.",
                zh="若要打内网资产，请先建立据点并使用 LateralMove。",
            )

        if node.status == "Down":
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} is down; there is no live service to exploit",
                zh=f"{target} 当前处于下线状态，没有可利用的在线服务",
            )

        if node.status == "Compromised":
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} is already compromised; choose a different action",
                zh=f"{target} 已经失陷，请选择其他动作",
            )

        if node.status == "Defended":
            return context.result(
                success=False,
                effect="blocked",
                en=f"Attack on {target} was blocked by existing defenses",
                zh=f"针对 {target} 的攻击被现有防御拦截",
            )

        if not node.exposed_ports:
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} exposes no service that can be directly targeted",
                zh=f"{target} 没有可被直接攻击的暴露服务",
            )

        if not node.vulnerabilities:
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} has no exploitable vulnerabilities",
                zh=f"{target} 当前不存在可利用漏洞",
            )

        node.status = "Compromised"
        return context.result(
            success=True,
            effect="compromise",
            en=f"{target} was successfully compromised through exposed services",
            zh=f"{target} 已通过对外服务漏洞被成功攻破",
            metadata={"used_vulnerability": node.vulnerabilities[0]},
        )


@_register
class LateralMoveAction(BaseAction):
    action_type = "LateralMove"
    agent_type = "Red"
    summary_en = "Pivot from an existing foothold into another node."
    summary_zh = "利用已建立的据点向其他节点横向移动。"
    description_en = (
        "Move deeper into the network after the initial breach. This action models reuse "
        "of credentials, trust paths, or internal reachability."
    )
    description_zh = "在初始突破后继续向内网推进，模拟凭证复用、信任链利用或内部可达性。"
    preconditions_en = (
        "At least one pivot foothold must already be Compromised.",
        "The target must still have exploitable weakness or trust exposure.",
        "The target cannot already be Down.",
    )
    preconditions_zh = (
        "必须已经存在至少一个可用的 Compromised 据点。",
        "目标仍需保留可被利用的弱点或信任暴露。",
        "目标不能已经处于 Down 状态。",
    )
    judgement_logic_en = (
        "If there is no foothold, the pivot fails.",
        "If the target is defended, the movement is blocked.",
        "On success, the target becomes Compromised.",
    )
    judgement_logic_zh = (
        "若没有据点，横移失败。",
        "若目标已被防御加固，横移会被阻断。",
        "成功后目标状态变为 Compromised。",
    )
    examples_en = (
        ActionExample(
            target="app",
            payload="Reuse stolen web credentials to access the internal app tier",
            rationale="Pivot from the web foothold into the next trust zone.",
        ),
    )
    examples_zh = (
        ActionExample(
            target="app",
            payload="复用从 web 节点窃取的凭证进入内部 app 层",
            rationale="从已控 web 据点横移到下一层信任区域。",
        ),
    )

    prerequisites: Dict[str, tuple[str, ...]] = {
        "app": ("web",),
        "db": ("app", "web"),
        "fw": ("web",),
    }

    def execute(self, context: ActionContext) -> ActionResult:
        target, node, error = self._require_target(context)
        if error is not None or target is None or node is None:
            return error  # type: ignore[return-value]

        if target.lower() == "internet":
            return self._reject_wrong_target_family(
                context,
                target=target,
                en="Use Recon for observation, not LateralMove, against the internet node.",
                zh="对 internet 节点应使用 Recon 做观察，而不是 LateralMove。",
            )

        if node.status == "Down":
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} is down and cannot be used for lateral movement",
                zh=f"{target} 当前处于下线状态，无法作为横移目标",
            )

        if node.status == "Compromised":
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} is already compromised; lateral movement would be redundant",
                zh=f"{target} 已经失陷，重复横移没有意义",
            )

        if node.status == "Defended":
            return context.result(
                success=False,
                effect="blocked",
                en=f"Lateral movement toward {target} was blocked by defenses",
                zh=f"朝向 {target} 的横向移动被防御拦截",
            )

        required_nodes = self.prerequisites.get(target, ())
        if required_nodes:
            foothold_available = context.any_compromised(*required_nodes)
        else:
            foothold_available = context.any_compromised_except(target)

        if not foothold_available:
            return context.result(
                success=False,
                effect="failed",
                en=f"No compromised foothold is available to pivot into {target}",
                zh=f"当前没有可用于横移进入 {target} 的失陷据点",
            )

        if not node.vulnerabilities:
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} has no internal weakness left to exploit for pivoting",
                zh=f"{target} 已无可供横移利用的内部弱点",
            )

        node.status = "Compromised"
        return context.result(
            success=True,
            effect="compromise",
            en=f"Lateral movement succeeded and {target} is now compromised",
            zh=f"横向移动成功，{target} 已失陷",
            metadata={"pivot_path": list(required_nodes) or ["any_compromised_node"]},
        )


@_register
class ExfiltrateDatabaseAction(BaseAction):
    action_type = "ExfiltrateDatabase"
    agent_type = "Red"
    summary_en = "Use an application foothold to access and exfiltrate database data."
    summary_zh = "基于应用层据点访问并导出数据库数据。"
    description_en = (
        "A goal-oriented action that turns application compromise into database access and "
        "data theft. It is intentionally narrower than generic exploitation."
    )
    description_zh = "一个目标导向动作：把应用层据点转化为数据库访问与数据窃取。"
    preconditions_en = (
        "The target must be a database node.",
        "The application tier must already be Compromised.",
        "The database must not already be in a defended state.",
    )
    preconditions_zh = (
        "目标必须是数据库节点。",
        "应用层必须已经处于 Compromised 状态。",
        "数据库不能已经处于防御加固状态。",
    )
    judgement_logic_en = (
        "Without an app-tier foothold, exfiltration fails.",
        "If the database is defended, the action is blocked.",
        "A successful exfiltration marks the database as Compromised if it was not already.",
    )
    judgement_logic_zh = (
        "若没有 app 层据点，数据导出失败。",
        "若数据库处于 Defended，则动作被拦截。",
        "导出成功后，若数据库此前未失陷，则其状态被标记为 Compromised。",
    )
    examples_en = (
        ActionExample(
            target="db",
            payload="Abuse trusted app-to-db connectivity to dump customer records",
            rationale="Convert an app foothold into direct business-impacting theft.",
        ),
    )
    examples_zh = (
        ActionExample(
            target="db",
            payload="滥用 app 到 db 的信任连接导出客户记录",
            rationale="把应用层据点转化为直接的数据窃取结果。",
        ),
    )

    def execute(self, context: ActionContext) -> ActionResult:
        target, node, error = self._require_target(context)
        if error is not None or target is None or node is None:
            return error  # type: ignore[return-value]

        if not _is_database_target(target):
            return self._reject_wrong_target_family(
                context,
                target=target,
                en="This action is only legal for database assets.",
                zh="该动作只能针对数据库资产。",
            )

        app = context.state.network_nodes.get("app")
        if app is None or app.status != "Compromised":
            return context.result(
                success=False,
                effect="failed",
                en="Database exfiltration requires a compromised application tier",
                zh="数据库导出必须以已失陷的应用层为前提",
            )

        if node.status == "Down":
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} is down; no live data channel is available",
                zh=f"{target} 当前处于下线状态，无法建立有效的数据通道",
            )

        if node.status == "Defended":
            return context.result(
                success=False,
                effect="blocked",
                en=f"Exfiltration against {target} was blocked by defenses",
                zh=f"针对 {target} 的数据导出被防御拦截",
            )

        if node.status != "Compromised" and not node.vulnerabilities:
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} has no remaining data-path weakness to exploit",
                zh=f"{target} 已无可利用的数据通路弱点",
            )

        node.status = "Compromised"
        return context.result(
            success=True,
            effect="exfiltration",
            en=f"Data access and exfiltration through {target} succeeded",
            zh=f"已成功通过 {target} 完成数据访问与导出",
            metadata={"data_access": "granted"},
        )


@_register
class PatchNodeAction(BaseAction):
    action_type = "PatchNode"
    agent_type = "Blue"
    summary_en = "Patch a node to reduce exposure and harden it."
    summary_zh = "修补节点以降低暴露面并完成加固。"
    description_en = (
        "Apply defensive remediation to remove at least part of the attack surface. "
        "Patching is best used before a node is fully lost."
    )
    description_zh = "执行防御性修复，削减至少一部分攻击面。补丁更适合在节点完全失陷前使用。"
    preconditions_en = (
        "The target must be a real node in the topology.",
        "Patching is most useful on normal or partially exposed assets.",
    )
    preconditions_zh = (
        "目标必须是拓扑中的真实节点。",
        "补丁动作更适合用于正常态或仍存在暴露面的资产。",
    )
    judgement_logic_en = (
        "The node is moved into Defended state.",
        "One known vulnerability is removed, if any remain.",
        "One exposed port is removed, if any remain.",
    )
    judgement_logic_zh = (
        "节点会进入 Defended 状态。",
        "若仍有漏洞，则移除一个已知漏洞。",
        "若仍有暴露端口，则收敛一个暴露端口。",
    )
    examples_en = (
        ActionExample(
            target="web",
            payload="Deploy the urgent web patch and close the weakest exposed service",
            rationale="Reduce initial-access probability before the next round.",
        ),
    )
    examples_zh = (
        ActionExample(
            target="web",
            payload="下发紧急 Web 补丁并关闭最危险的暴露服务",
            rationale="在下一回合前降低被初始突破的概率。",
        ),
    )

    def execute(self, context: ActionContext) -> ActionResult:
        target, node, error = self._require_target(context)
        if error is not None or target is None or node is None:
            return error  # type: ignore[return-value]

        if target.lower() == "internet":
            return self._reject_wrong_target_family(
                context,
                target=target,
                en="Patch concrete infrastructure nodes instead of the abstract internet node.",
                zh="应修补具体基础设施节点，而不是抽象的 internet 节点。",
            )

        if node.status == "Down":
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} is down; restore it before applying patches",
                zh=f"{target} 当前处于下线状态，请先恢复再修补",
            )

        removed_vulnerability = node.vulnerabilities[0] if node.vulnerabilities else None
        removed_port = node.exposed_ports[-1] if node.exposed_ports else None
        node.status = "Defended"
        if node.vulnerabilities:
            node.vulnerabilities = node.vulnerabilities[1:]
        if node.exposed_ports:
            node.exposed_ports = node.exposed_ports[:-1]

        return context.result(
            success=True,
            effect="hardening",
            en=f"{target} was patched and moved into a defended state",
            zh=f"{target} 已完成补丁修复并进入防御态",
            metadata={
                "removed_vulnerability": removed_vulnerability,
                "removed_port": removed_port,
            },
        )


@_register
class RestoreNodeAction(BaseAction):
    action_type = "RestoreNode"
    agent_type = "Blue"
    summary_en = "Restore a compromised node from a clean baseline."
    summary_zh = "将已失陷节点恢复到干净基线状态。"
    description_en = (
        "Use incident response to recover a damaged node. This action is intended for "
        "containment and service recovery after compromise."
    )
    description_zh = "通过应急处置恢复受损节点，适合在节点失陷后进行隔离、恢复与回收控制。"
    preconditions_en = (
        "The target should be compromised or down for restore to have clear value.",
        "Restore removes at least one remaining weakness when possible.",
    )
    preconditions_zh = (
        "恢复动作最适合用于已失陷或下线节点。",
        "若仍存在弱点，恢复会尽量一并清除至少一个。",
    )
    judgement_logic_en = (
        "The node is moved into Defended state.",
        "One vulnerability is removed, if any remain after recovery.",
        "Restore is valid even when the node is Down.",
    )
    judgement_logic_zh = (
        "节点会进入 Defended 状态。",
        "若恢复后仍存在漏洞，则移除一个漏洞。",
        "即使节点已 Down，也允许执行恢复动作。",
    )
    examples_en = (
        ActionExample(
            target="app",
            payload="Isolate the app host and restore it from a clean snapshot",
            rationale="Recover service while denying persistence to the attacker.",
        ),
    )
    examples_zh = (
        ActionExample(
            target="app",
            payload="隔离应用主机并从干净快照恢复",
            rationale="在恢复业务的同时剥夺攻击者的持续驻留能力。",
        ),
    )

    def execute(self, context: ActionContext) -> ActionResult:
        target, node, error = self._require_target(context)
        if error is not None or target is None or node is None:
            return error  # type: ignore[return-value]

        if target.lower() == "internet":
            return self._reject_wrong_target_family(
                context,
                target=target,
                en="Restore concrete infrastructure nodes instead of the abstract internet node.",
                zh="应恢复具体基础设施节点，而不是抽象的 internet 节点。",
            )

        if node.status not in {"Compromised", "Down"}:
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} is not compromised or down; PatchNode is the better choice",
                zh=f"{target} 当前既未失陷也未下线，优先使用 PatchNode 更合适",
            )

        removed_vulnerability = node.vulnerabilities[0] if node.vulnerabilities else None
        node.status = "Defended"
        if node.vulnerabilities:
            node.vulnerabilities = node.vulnerabilities[1:]

        return context.result(
            success=True,
            effect="restoration",
            en=f"{target} was restored and is now in a defended state",
            zh=f"{target} 已恢复并进入防御态",
            metadata={"removed_vulnerability": removed_vulnerability},
        )


@_register
class MonitorAction(BaseAction):
    action_type = "Monitor"
    agent_type = "Blue"
    summary_en = "Maintain monitoring coverage without changing topology ownership."
    summary_zh = "保持监控覆盖，不直接改变拓扑控制权。"
    description_en = (
        "Low-risk defensive posture action. It preserves situational awareness when no "
        "higher-impact repair or hardening step is needed."
    )
    description_zh = "低风险防守姿态动作。适合在没有更高优先级修复动作时维持态势感知。"
    requires_target = False
    virtual_targets = ("network", "all")
    target_hint_en = "Optional. Use a node name, 'network', or leave it empty."
    target_hint_zh = "可选。可填写节点名、'network'，或留空。"
    preconditions_en = (
        "No target is required.",
        "If a target is provided, it must be a valid node name or the virtual target 'network'.",
    )
    preconditions_zh = (
        "该动作不强制要求目标。",
        "若填写目标，则必须是合法节点名，或使用虚拟目标 'network'。",
    )
    judgement_logic_en = (
        "Monitor does not mutate node ownership or vulnerability state.",
        "The action succeeds as long as the target identifier is legal.",
    )
    judgement_logic_zh = (
        "Monitor 不会直接修改节点控制权或漏洞状态。",
        "只要目标标识合法，该动作就会成功。",
    )
    examples_en = (
        ActionExample(
            target="network",
            payload="Review alerts and keep telemetry collection active",
            rationale="Spend the round on visibility rather than changing infrastructure.",
        ),
    )
    examples_zh = (
        ActionExample(
            target="network",
            payload="审查告警并维持遥测采集链路",
            rationale="把本回合用于维持可观测性，而不是直接调整基础设施。",
        ),
    )

    def execute(self, context: ActionContext) -> ActionResult:
        target = context.decision.target or "network"
        if target not in self.virtual_targets and target not in context.state.network_nodes:
            return context.result(
                success=False,
                effect="rejected",
                en=f"Unknown monitoring target: {target}",
                zh=f"未知监控目标：{target}",
            )

        return context.result(
            success=True,
            effect="monitoring",
            en=f"Monitoring remained active for {target}; topology ownership was unchanged",
            zh=f"已持续对 {target} 保持监控；拓扑控制权未发生变化",
            metadata={"monitor_scope": target},
        )
