from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Literal

from backend_engine.core.models import AgentDecision, NetworkNode, VulnerabilityInfo, WorldState

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


def vulnerability_to_dict(vulnerability: VulnerabilityInfo) -> dict[str, Any]:
    return vulnerability.model_dump(mode="json")


def vulnerability_map_to_dict(vulnerabilities: dict[str, VulnerabilityInfo]) -> dict[str, dict[str, Any]]:
    return {
        vuln_id: vulnerability_to_dict(vulnerability)
        for vuln_id, vulnerability in vulnerabilities.items()
    }


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
            "vuln_id": self.decision.vuln_id,
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
    payload_hint_en: str = "Briefly describe the intended technique, indicator, command family, and vuln_id when required."
    payload_hint_zh: str = "简要描述计划采用的技术、载荷特征或命令类型；需要时写明 vuln_id。"
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

        target = self._normalize_target(context)
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

    def _normalize_target(self, context: ActionContext) -> str | None:
        target = context.decision.target
        if not target:
            return None
        if target in context.state.network_nodes or target in self.virtual_targets:
            return target

        for separator in ("@", "#", ":"):
            if separator not in target:
                continue
            node_name, vuln_id = target.split(separator, 1)
            if node_name not in context.state.network_nodes:
                continue
            context.decision.target = node_name
            if not context.decision.vuln_id and vuln_id:
                context.decision.vuln_id = vuln_id
            return node_name

        return target

    def _require_target(self, context: ActionContext) -> tuple[str | None, NetworkNode | None, ActionResult | None]:
        target = self._normalize_target(context)
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

    def _resolve_vulnerability(
        self,
        context: ActionContext,
        node: NetworkNode,
        *,
        require_explicit: bool,
        allow_auto_single: bool = True,
    ) -> tuple[str | None, VulnerabilityInfo | None, ActionResult | None]:
        if not node.vulnerabilities:
            return None, None, context.result(
                success=False,
                effect="failed",
                en="The target has no remaining vulnerabilities",
                zh="目标当前没有可操作的剩余漏洞",
            )

        explicit_vuln_id = context.decision.vuln_id
        if explicit_vuln_id:
            vulnerability = node.vulnerabilities.get(explicit_vuln_id)
            if vulnerability is None:
                return explicit_vuln_id, None, context.result(
                    success=False,
                    effect="failed",
                    en=f"Selected vuln_id {explicit_vuln_id} does not exist on the target",
                    zh=f"所选 vuln_id {explicit_vuln_id} 不存在于目标节点",
                )
            return explicit_vuln_id, vulnerability, None

        payload = context.decision.payload or ""
        matches = [vuln_id for vuln_id in node.vulnerabilities if vuln_id in payload]
        if len(matches) == 1:
            vuln_id = matches[0]
            context.decision.vuln_id = vuln_id
            return vuln_id, node.vulnerabilities[vuln_id], None

        if len(matches) > 1:
            return None, None, context.result(
                success=False,
                effect="rejected",
                en="Payload matches multiple vulnerabilities; specify exactly one vuln_id",
                zh="payload 同时命中了多个漏洞，请明确指定单个 vuln_id",
            )

        if allow_auto_single and len(node.vulnerabilities) == 1:
            vuln_id, vulnerability = next(iter(node.vulnerabilities.items()))
            context.decision.vuln_id = vuln_id
            return vuln_id, vulnerability, None

        if require_explicit:
            return None, None, context.result(
                success=False,
                effect="rejected",
                en="This action requires a vuln_id in payload, target decoration, or the vuln_id field",
                zh="该动作必须在 payload、带漏洞标识的 target，或 vuln_id 字段中明确指定漏洞",
            )

        vuln_id, vulnerability = max(
            node.vulnerabilities.items(),
            key=lambda item: (item[1].score, item[0]),
        )
        context.decision.vuln_id = vuln_id
        return vuln_id, vulnerability, None

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
                    "vuln_id": decision.vuln_id,
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
    description_zh = "低影响侦察动作，用于在正式攻击前收集服务、节点状态与潜在漏洞信息。"
    preconditions_en = (
        "The target must exist in world_state.network_nodes.",
        "Recon never changes ownership by itself.",
    )
    preconditions_zh = (
        "目标必须存在于 world_state.network_nodes 中。",
        "Recon 本身不会直接改变节点控制权。",
    )
    judgement_logic_en = (
        "The referee returns observations in metadata without mutating the topology.",
    )
    judgement_logic_zh = (
        "裁判会把观察结果写入 metadata，但不会直接修改拓扑状态。",
    )
    examples_en = (
        ActionExample(
            target="web",
            payload="Quiet HTTP fingerprinting for CVE-WEB-2026-0001",
            rationale="Collect concrete service and vulnerability data before exploitation.",
        ),
    )
    examples_zh = (
        ActionExample(
            target="web",
            payload="对 web 进行低噪声 HTTP 指纹识别，确认漏洞与版本信息",
            rationale="先拿到可执行情报，再进入利用阶段。",
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
                f"Recon completed against {target}; services and candidate vulnerabilities were observed "
                "without changing node ownership"
            ),
            zh=f"已完成对 {target} 的侦察；已获得服务与候选漏洞信息，但未改变节点控制权",
            metadata={
                "observed_status": node.status,
                "observed_ports": list(node.exposed_ports),
                "vulnerability_count": len(node.vulnerabilities),
                "suspected_vulnerabilities": vulnerability_map_to_dict(node.vulnerabilities),
                "score_value": 0,
            },
        )


@_register
class ExploitServiceAction(BaseAction):
    action_type = "ExploitService"
    agent_type = "Red"
    summary_en = "Exploit an internet-facing service on a perimeter node."
    summary_zh = "利用边界节点上的对外服务漏洞。"
    description_en = (
        "Directly attack an exposed service on a perimeter node. The action must specify the "
        "concrete vuln_id to exploit."
    )
    description_zh = "直接攻击边界节点上的对外暴露服务。动作必须明确指定要利用的 vuln_id。"
    preconditions_en = (
        "The target must be a perimeter node such as web, firewall, proxy, or gateway.",
        "The target must expose at least one port.",
        "A concrete vuln_id must be selected from the node's vulnerability map.",
    )
    preconditions_zh = (
        "目标必须是边界节点，例如 web、firewall、proxy 或 gateway。",
        "目标必须存在对外暴露端口。",
        "必须从节点漏洞字典中明确选定一个 vuln_id。",
    )
    judgement_logic_en = (
        "After precondition validation, the referee decides whether the technique is technically feasible.",
        "If approved, the node is marked as Compromised.",
    )
    judgement_logic_zh = (
        "通过前置校验后，由语义裁判判断该利用链是否技术可行。",
        "裁判批准成功后，目标节点进入 Compromised。",
    )
    examples_en = (
        ActionExample(
            target="web",
            payload="Exploit vuln_id=CVE-WEB-2026-0001 through the public HTTP service",
            rationale="Use a specific vulnerability for initial access.",
        ),
    )
    examples_zh = (
        ActionExample(
            target="web",
            payload="利用 vuln_id=CVE-WEB-2026-0001 攻击公网 HTTP 服务",
            rationale="明确指定漏洞，建立首个据点。",
        ),
    )

    def validate(self, context: ActionContext) -> ActionResult | None:
        base_error = super().validate(context)
        if base_error is not None:
            return base_error

        target, node, error = self._require_target(context)
        if error is not None or target is None or node is None:
            return error

        if not _is_perimeter_target(target):
            return self._reject_wrong_target_family(
                context,
                target=target,
                en="Use LateralMove for internal assets after gaining a foothold.",
                zh="内部资产应在建立据点后使用 LateralMove。",
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

        if not node.exposed_ports:
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} exposes no service that can be directly targeted",
                zh=f"{target} 没有可被直接攻击的暴露服务",
            )

        vuln_id, vulnerability, vuln_error = self._resolve_vulnerability(
            context,
            node,
            require_explicit=True,
        )
        if vuln_error is not None or vuln_id is None or vulnerability is None:
            return vuln_error

        return None

    def execute(self, context: ActionContext) -> ActionResult:
        target = context.decision.target
        if not target or target not in context.state.network_nodes:
            return context.result(
                success=False,
                effect="rejected",
                en="Execution failed: invalid target after validation",
                zh="执行失败：校验后目标无效",
            )
        node = context.state.network_nodes[target]
        vuln_id = context.decision.vuln_id
        vulnerability = node.vulnerabilities.get(vuln_id) if vuln_id else None
        if vuln_id is None or vulnerability is None:
            return context.result(
                success=False,
                effect="failed",
                en="Execution failed: validated vuln_id is missing",
                zh="执行失败：已校验漏洞在执行时不存在",
            )

        previous_status = node.status
        node.status = "Compromised"

        return context.result(
            success=True,
            effect="compromise",
            en=f"{target} was successfully compromised via vuln_id={vuln_id}",
            zh=f"{target} 已通过 vuln_id={vuln_id} 被成功攻破",
            metadata={
                "used_vulnerability": vulnerability_to_dict(vulnerability),
                "score_value": vulnerability.score,
                "previous_status": previous_status,
            },
        )


@_register
class LateralMoveAction(BaseAction):
    action_type = "LateralMove"
    agent_type = "Red"
    summary_en = "Pivot from an existing foothold into another node."
    summary_zh = "利用既有据点向其他节点横向移动。"
    description_en = (
        "Move deeper into the network after the initial breach. The move consumes a concrete "
        "vulnerability on the target node."
    )
    description_zh = "在初始突破后向内网推进。横移会利用目标节点上的一个具体漏洞。"
    preconditions_en = (
        "At least one pivot foothold must already be Compromised.",
        "The target cannot already be Down or Compromised.",
    )
    preconditions_zh = (
        "必须已经存在至少一个可用的 Compromised 据点。",
        "目标不能已是 Down 或 Compromised。",
    )
    judgement_logic_en = (
        "After precondition validation, the referee decides whether pivoting is technically feasible.",
        "If approved, the target becomes Compromised.",
    )
    judgement_logic_zh = (
        "通过前置校验后，由语义裁判判断横向移动是否技术可行。",
        "裁判批准成功后，目标进入 Compromised。",
    )
    examples_en = (
        ActionExample(
            target="app",
            payload="Reuse stolen web credentials and exploit DefaultAdminPassword on app",
            rationale="Pivot from the first foothold into the next tier.",
        ),
    )
    examples_zh = (
        ActionExample(
            target="app",
            payload="复用 web 据点拿到的凭据，并利用 DefaultAdminPassword 横向进入 app",
            rationale="从首个据点继续向内网推进。",
        ),
    )

    prerequisites: Dict[str, tuple[str, ...]] = {
        "app": ("web",),
        "db": ("app", "web"),
        "fw": ("web",),
    }

    def validate(self, context: ActionContext) -> ActionResult | None:
        base_error = super().validate(context)
        if base_error is not None:
            return base_error

        target, node, error = self._require_target(context)
        if error is not None or target is None or node is None:
            return error

        if target.lower() == "internet":
            return self._reject_wrong_target_family(
                context,
                target=target,
                en="Use Recon for observation, not LateralMove, against the internet node.",
                zh="对 internet 节点应使用 Recon 而不是 LateralMove。",
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

        required_nodes = self.prerequisites.get(target, ())
        foothold_available = (
            context.any_compromised(*required_nodes)
            if required_nodes
            else context.any_compromised_except(target)
        )
        if not foothold_available:
            return context.result(
                success=False,
                effect="failed",
                en=f"No compromised foothold is available to pivot into {target}",
                zh=f"当前没有可用于横移进入 {target} 的失陷据点",
            )

        vuln_id, vulnerability, vuln_error = self._resolve_vulnerability(
            context,
            node,
            require_explicit=False,
        )
        if vuln_error is not None or vuln_id is None or vulnerability is None:
            return vuln_error

        return None

    def execute(self, context: ActionContext) -> ActionResult:
        target = context.decision.target
        if not target or target not in context.state.network_nodes:
            return context.result(
                success=False,
                effect="rejected",
                en="Execution failed: invalid target after validation",
                zh="执行失败：校验后目标无效",
            )
        node = context.state.network_nodes[target]
        vuln_id = context.decision.vuln_id
        vulnerability = node.vulnerabilities.get(vuln_id) if vuln_id else None
        if vuln_id is None or vulnerability is None:
            return context.result(
                success=False,
                effect="failed",
                en="Execution failed: validated vuln_id is missing",
                zh="执行失败：已校验漏洞在执行时不存在",
            )
        required_nodes = self.prerequisites.get(target, ())
        previous_status = node.status
        node.status = "Compromised"

        return context.result(
            success=True,
            effect="compromise",
            en=f"Lateral movement succeeded via vuln_id={vuln_id}; {target} is now compromised",
            zh=f"已通过 vuln_id={vuln_id} 横移成功，{target} 现已失陷",
            metadata={
                "used_vulnerability": vulnerability_to_dict(vulnerability),
                "score_value": vulnerability.score,
                "previous_status": previous_status,
                "pivot_path": list(required_nodes) or ["any_compromised_node"],
            },
        )


@_register
class ExfiltrateDatabaseAction(BaseAction):
    action_type = "ExfiltrateDatabase"
    agent_type = "Red"
    summary_en = "Use an application foothold to access and exfiltrate database data."
    summary_zh = "基于应用层据点访问并导出数据库数据。"
    description_en = (
        "A goal-oriented action that turns application compromise into database access and data theft. "
        "It consumes a specific database vulnerability."
    )
    description_zh = "一个目标导向动作：把应用层据点转化为数据库访问与数据窃取，并利用一个具体数据库漏洞。"
    preconditions_en = (
        "The target must be a database node.",
        "The application tier must already be Compromised.",
    )
    preconditions_zh = (
        "目标必须是数据库节点。",
        "应用层必须已经是 Compromised。",
    )
    judgement_logic_en = (
        "After precondition validation, the referee decides whether the exfiltration path is technically feasible.",
        "If approved, the database is marked as Compromised when needed.",
    )
    judgement_logic_zh = (
        "通过前置校验后，由语义裁判判断数据外传链路是否技术可行。",
        "裁判批准成功后，数据库在必要时进入 Compromised。",
    )
    examples_en = (
        ActionExample(
            target="db",
            payload="Use OpenReplicaAccess to dump customer records from db",
            rationale="Convert the foothold into direct business impact.",
        ),
    )
    examples_zh = (
        ActionExample(
            target="db",
            payload="利用 OpenReplicaAccess 从 db 导出客户记录",
            rationale="把既有据点转化为直接业务损害。",
        ),
    )

    def validate(self, context: ActionContext) -> ActionResult | None:
        base_error = super().validate(context)
        if base_error is not None:
            return base_error

        target, node, error = self._require_target(context)
        if error is not None or target is None or node is None:
            return error

        if not _is_database_target(target):
            return self._reject_wrong_target_family(
                context,
                target=target,
                en="This action is only legal for database assets.",
                zh="该动作只适用于数据库资产。",
            )

        app = context.state.network_nodes.get("app")
        if app is None or app.status != "Compromised":
            return context.result(
                success=False,
                effect="failed",
                en="Database exfiltration requires a compromised application tier",
                zh="数据库导出必须建立在应用层已失陷的前提上",
            )

        if node.status == "Down":
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} is down; no live data channel is available",
                zh=f"{target} 当前处于下线状态，无法建立有效数据通道",
            )

        vuln_id, vulnerability, vuln_error = self._resolve_vulnerability(
            context,
            node,
            require_explicit=False,
        )
        if vuln_error is not None or vuln_id is None or vulnerability is None:
            return vuln_error

        return None

    def execute(self, context: ActionContext) -> ActionResult:
        target = context.decision.target
        if not target or target not in context.state.network_nodes:
            return context.result(
                success=False,
                effect="rejected",
                en="Execution failed: invalid target after validation",
                zh="执行失败：校验后目标无效",
            )
        node = context.state.network_nodes[target]
        vuln_id = context.decision.vuln_id
        vulnerability = node.vulnerabilities.get(vuln_id) if vuln_id else None
        if vuln_id is None or vulnerability is None:
            return context.result(
                success=False,
                effect="failed",
                en="Execution failed: validated vuln_id is missing",
                zh="执行失败：已校验漏洞在执行时不存在",
            )
        previous_status = node.status
        if node.status != "Compromised":
            node.status = "Compromised"

        return context.result(
            success=True,
            effect="exfiltration",
            en=f"Data access and exfiltration through {target} succeeded via vuln_id={vuln_id}",
            zh=f"已通过 vuln_id={vuln_id} 成功完成 {target} 的数据访问与导出",
            metadata={
                "used_vulnerability": vulnerability_to_dict(vulnerability),
                "score_value": vulnerability.score,
                "previous_status": previous_status,
                "data_access": "granted",
            },
        )


@_register
class PatchNodeAction(BaseAction):
    action_type = "PatchNode"
    agent_type = "Blue"
    summary_en = "Patch a specific vulnerability while keeping the service online."
    summary_zh = "修补指定漏洞，同时保持业务端口在线。"
    description_en = (
        "Apply a targeted remediation to one specific vulnerability. The action must identify "
        "the concrete vuln_id to patch."
    )
    description_zh = "对单个具体漏洞执行修补。动作必须明确指出要修补的 vuln_id。"
    preconditions_en = (
        "The target must be a real node in the topology.",
        "The action requires a concrete vuln_id when multiple vulnerabilities exist.",
    )
    preconditions_zh = (
        "目标必须是拓扑中的真实节点。",
        "当节点存在多个漏洞时，必须明确指定 vuln_id。",
    )
    judgement_logic_en = (
        "After precondition validation, the referee decides whether the patch operation is technically effective.",
        "If approved, only the selected vulnerability is removed.",
        "Exposed ports are preserved.",
    )
    judgement_logic_zh = (
        "通过前置校验后，由语义裁判判断修补动作是否技术有效。",
        "裁判批准成功时只会移除选中的漏洞。",
        "业务暴露端口会被保留。",
    )
    examples_en = (
        ActionExample(
            target="web",
            payload="Patch vuln_id=CVE-WEB-2026-0001 while keeping 80/443 online",
            rationale="Remove a high-value weakness without cutting off business traffic.",
        ),
    )
    examples_zh = (
        ActionExample(
            target="web",
            payload="修补 vuln_id=CVE-WEB-2026-0001，同时保持 80/443 端口在线",
            rationale="消除高价值漏洞，同时不影响业务流量。",
        ),
    )

    def validate(self, context: ActionContext) -> ActionResult | None:
        base_error = super().validate(context)
        if base_error is not None:
            return base_error

        target, node, error = self._require_target(context)
        if error is not None or target is None or node is None:
            return error

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
                en=f"{target} is down; bring it back before patching",
                zh=f"{target} 当前处于下线状态，请先恢复再修补",
            )

        vuln_id, vulnerability, vuln_error = self._resolve_vulnerability(
            context,
            node,
            require_explicit=True,
        )
        if vuln_error is not None or vuln_id is None or vulnerability is None:
            return vuln_error

        return None

    def execute(self, context: ActionContext) -> ActionResult:
        target = context.decision.target
        if not target or target not in context.state.network_nodes:
            return context.result(
                success=False,
                effect="rejected",
                en="Execution failed: invalid target after validation",
                zh="执行失败：校验后目标无效",
            )
        node = context.state.network_nodes[target]
        vuln_id = context.decision.vuln_id
        vulnerability = node.vulnerabilities.get(vuln_id) if vuln_id else None
        if vuln_id is None or vulnerability is None:
            return context.result(
                success=False,
                effect="failed",
                en="Execution failed: validated vuln_id is missing",
                zh="执行失败：已校验漏洞在执行时不存在",
            )
        previous_status = node.status
        node.vulnerabilities.pop(vuln_id, None)

        return context.result(
            success=True,
            effect="hardening",
            en=f"{target} was successfully patched for vuln_id={vuln_id}",
            zh=f"{target} 已成功完成 vuln_id={vuln_id} 的修补",
            metadata={
                "patched_vulnerability": vulnerability_to_dict(vulnerability),
                "score_value": vulnerability.score,
                "previous_status": previous_status,
                "preserved_ports": list(node.exposed_ports),
            },
        )


@_register
class RestoreNodeAction(BaseAction):
    action_type = "RestoreNode"
    agent_type = "Blue"
    summary_en = "Restore a compromised or down node back to a clean normal state."
    summary_zh = "将失陷或下线节点恢复到干净的 Normal 状态。"
    description_en = (
        "Use incident response to recover a damaged node. Restore can optionally remove one "
        "remaining vulnerability while returning the node to service."
    )
    description_zh = "通过应急响应恢复受损节点。恢复动作可在必要时一并清理一个漏洞，并让节点回到服务状态。"
    preconditions_en = (
        "The target should be Compromised or Down.",
    )
    preconditions_zh = (
        "目标应处于 Compromised 或 Down。",
    )
    judgement_logic_en = (
        "The node is returned to Normal.",
        "One remaining vulnerability may be removed when available.",
    )
    judgement_logic_zh = (
        "节点会被恢复到 Normal。",
        "若仍有漏洞，可一并移除一个。",
    )
    examples_en = (
        ActionExample(
            target="app",
            payload="Restore app from clean snapshot and remove DefaultAdminPassword",
            rationale="Recover service while reducing the chance of immediate re-entry.",
        ),
    )
    examples_zh = (
        ActionExample(
            target="app",
            payload="从干净快照恢复 app，并顺带清理 DefaultAdminPassword",
            rationale="恢复业务并降低被立即再次打穿的概率。",
        ),
    )

    def validate(self, context: ActionContext) -> ActionResult | None:
        base_error = super().validate(context)
        if base_error is not None:
            return base_error

        target, node, error = self._require_target(context)
        if error is not None or target is None or node is None:
            return error

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

        if node.vulnerabilities:
            _, _, vuln_error = self._resolve_vulnerability(
                context,
                node,
                require_explicit=False,
                allow_auto_single=False,
            )
            if vuln_error is not None:
                return vuln_error

        return None

    def execute(self, context: ActionContext) -> ActionResult:
        target = context.decision.target
        if not target or target not in context.state.network_nodes:
            return context.result(
                success=False,
                effect="rejected",
                en="Execution failed: invalid target after validation",
                zh="执行失败：校验后目标无效",
            )
        node = context.state.network_nodes[target]

        previous_status = node.status
        removed_vulnerability = None
        score_value = 0
        if node.vulnerabilities:
            vuln_id, vulnerability, vuln_error = self._resolve_vulnerability(
                context,
                node,
                require_explicit=False,
                allow_auto_single=False,
            )
            if vuln_error is None and vuln_id is not None and vulnerability is not None:
                removed_vulnerability = vulnerability_to_dict(vulnerability)
                score_value = vulnerability.score
                node.vulnerabilities.pop(vuln_id, None)

        node.status = "Normal"
        return context.result(
            success=True,
            effect="restoration",
            en=f"{target} was restored and returned to a normal state",
            zh=f"{target} 已恢复并回到 Normal 状态",
            metadata={
                "removed_vulnerability": removed_vulnerability,
                "score_value": score_value,
                "previous_status": previous_status,
            },
        )


@_register
class IsolateAction(BaseAction):
    action_type = "Isolate"
    agent_type = "Blue"
    summary_en = "Isolate a node immediately by taking it offline."
    summary_zh = "立即隔离节点，将其下线。"
    description_en = (
        "Emergency containment action. Isolation prioritizes stopping the attack path over "
        "business continuity."
    )
    description_zh = "紧急遏制动作。隔离优先阻断攻击路径，而不是维持业务连续性。"
    preconditions_en = (
        "The target must be a real node in the topology.",
        "Isolation cannot be applied to the abstract internet node.",
    )
    preconditions_zh = (
        "目标必须是拓扑中的真实节点。",
        "不能对抽象的 internet 节点执行隔离。",
    )
    judgement_logic_en = (
        "The target is moved to Down state immediately.",
        "If a vuln_id is provided, it can be used for interception matching and score attribution.",
    )
    judgement_logic_zh = (
        "目标会立即进入 Down 状态。",
        "若提供 vuln_id，可用于拦截匹配与计分归属。",
    )
    examples_en = (
        ActionExample(
            target="web",
            payload="Isolate web to stop exploitation of CVE-WEB-2026-0001",
            rationale="Trade availability for immediate containment.",
        ),
    )
    examples_zh = (
        ActionExample(
            target="web",
            payload="隔离 web，阻断对 CVE-WEB-2026-0001 的利用",
            rationale="用可用性换取即时遏制。",
        ),
    )

    def validate(self, context: ActionContext) -> ActionResult | None:
        base_error = super().validate(context)
        if base_error is not None:
            return base_error

        target, node, error = self._require_target(context)
        if error is not None or target is None or node is None:
            return error

        if target.lower() == "internet":
            return self._reject_wrong_target_family(
                context,
                target=target,
                en="Isolate concrete infrastructure nodes instead of the abstract internet node.",
                zh="应隔离具体基础设施节点，而不是抽象的 internet 节点。",
            )

        if node.status == "Down":
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} is already down",
                zh=f"{target} 当前已经处于 Down 状态",
            )

        if context.decision.vuln_id and context.decision.vuln_id not in node.vulnerabilities:
            return context.result(
                success=False,
                effect="failed",
                en=f"Selected vuln_id {context.decision.vuln_id} does not exist on the target",
                zh=f"所选 vuln_id {context.decision.vuln_id} 不存在于目标节点",
            )

        return None

    def execute(self, context: ActionContext) -> ActionResult:
        target = context.decision.target
        if not target or target not in context.state.network_nodes:
            return context.result(
                success=False,
                effect="rejected",
                en="Execution failed: invalid target after validation",
                zh="执行失败：校验后目标无效",
            )
        node = context.state.network_nodes[target]

        score_value = 0
        if context.decision.vuln_id and context.decision.vuln_id in node.vulnerabilities:
            score_value = node.vulnerabilities[context.decision.vuln_id].score
        elif node.vulnerabilities and len(node.vulnerabilities) == 1:
            vuln_id, vulnerability = next(iter(node.vulnerabilities.items()))
            context.decision.vuln_id = vuln_id
            score_value = vulnerability.score

        previous_status = node.status
        node.status = "Down"
        return context.result(
            success=True,
            effect="isolation",
            en=f"{target} was isolated and taken offline",
            zh=f"{target} 已被隔离并下线",
            metadata={
                "score_value": score_value,
                "previous_status": previous_status,
            },
        )


@_register
class MonitorAction(BaseAction):
    action_type = "Monitor"
    agent_type = "Blue"
    summary_en = "Maintain monitoring coverage without changing topology ownership."
    summary_zh = "维持监控覆盖，不直接改变拓扑状态。"
    description_en = (
        "Low-risk defensive posture action. It preserves situational awareness when no higher-impact "
        "repair or containment step is needed."
    )
    description_zh = "低风险防守动作。在不需要更高影响修复或遏制时，用于维持态势感知。"
    requires_target = False
    virtual_targets = ("network", "all")
    target_hint_en = "Optional. Use a node name, 'network', or leave it empty."
    target_hint_zh = "可选。可填写节点名、network，或留空。"
    preconditions_en = (
        "No target is required.",
        "If a target is provided, it must be a valid node name or the virtual target 'network'.",
    )
    preconditions_zh = (
        "该动作不强制要求目标。",
        "若填写目标，则必须是合法节点名，或使用虚拟目标 network。",
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
            rationale="Spend the round on visibility rather than infrastructure changes.",
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
            zh=f"已持续对 {target} 保持监控；拓扑状态未发生变化",
            metadata={"monitor_scope": target, "score_value": 0},
        )
