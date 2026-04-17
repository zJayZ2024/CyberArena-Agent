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


def _build_network_adjacency(state: WorldState) -> dict[str, set[str]]:
    adjacency: dict[str, set[str]] = {node_name: set() for node_name in state.network_nodes}
    for edge in state.edges:
        if edge.source not in state.network_nodes or edge.target not in state.network_nodes:
            continue
        adjacency[edge.source].add(edge.target)
        adjacency[edge.target].add(edge.source)
    return adjacency


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

    preferred_pivots: Dict[str, tuple[str, ...]] = {
        "app": ("web", "fw"),
        "db": ("app", "storage", "web"),
        "storage": ("app", "web"),
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

        adjacency = _build_network_adjacency(context.state)
        compromised_nodes = {
            node_name
            for node_name, row in context.state.network_nodes.items()
            if row.status == "Compromised" and node_name != target
        }
        candidate_pivots = [node_name for node_name in adjacency.get(target, set()) if node_name in compromised_nodes]
        if not candidate_pivots:
            return context.result(
                success=False,
                effect="failed",
                en=f"No continuous compromised pivot chain reaches {target}",
                zh=f"当前不存在可达 {target} 的连续失陷跳板链路",
            )

        if target.lower() == "db" and not any(node_name in {"app", "storage"} for node_name in candidate_pivots):
            return context.result(
                success=False,
                effect="failed",
                en="Pivoting into db requires compromised intermediate foothold on app/storage path",
                zh="横移进入 db 需要 app/storage 路径上的有效失陷中间跳板",
            )

        selected_pivot = self._select_pivot_source(target=target, candidates=candidate_pivots)
        if selected_pivot and "pivot_source=" not in (context.decision.payload or ""):
            context.decision.payload = f"{context.decision.payload} | pivot_source={selected_pivot}".strip()

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
        adjacency = _build_network_adjacency(context.state)
        compromised_nodes = {
            node_name
            for node_name, row in context.state.network_nodes.items()
            if row.status == "Compromised" and node_name != target
        }
        candidate_pivots = [node_name for node_name in adjacency.get(target, set()) if node_name in compromised_nodes]
        if not candidate_pivots:
            return context.result(
                success=False,
                effect="failed",
                en=f"No compromised pivot is available to reach {target} at execution time",
                zh=f"执行阶段不存在可用于到达 {target} 的失陷跳板",
            )

        pivot_source = self._select_pivot_source(target=target, candidates=candidate_pivots)
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
                "pivot_source": pivot_source,
                "pivot_candidates": sorted(candidate_pivots),
            },
        )

    def _select_pivot_source(self, *, target: str, candidates: list[str]) -> str:
        if not candidates:
            return ""
        preferred = self.preferred_pivots.get(target, ())
        for node_name in preferred:
            if node_name in candidates:
                return node_name
        return sorted(candidates)[0]


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
class AnchorFootholdAction(BaseAction):
    action_type = "AnchorFoothold"
    agent_type = "Red"
    summary_en = "Establish persistence on a compromised pivot node."
    summary_zh = "在已控制的跳板节点上建立持久化扎根。"
    description_en = (
        "Use persistence techniques on an already compromised node so temporary restoration "
        "cannot fully remove re-entry capability."
    )
    description_zh = "在已失陷跳板上植入持久化机制，避免普通恢复动作完全切断后续再进入能力。"
    preconditions_en = (
        "The target must already be Compromised.",
        "Core objective nodes are not valid persistence targets.",
    )
    preconditions_zh = (
        "目标必须已经处于 Compromised 状态。",
        "核心目标节点不作为扎根目标。",
    )
    judgement_logic_en = (
        "Successful anchoring records persistence metadata on the target node.",
    )
    judgement_logic_zh = (
        "扎根成功后会在目标节点记录持久化标记。",
    )
    examples_zh = (
        ActionExample(
            target="app",
            payload="在 app 部署持久化后门并建立再进入触发器",
            rationale="防止蓝方普通恢复后立刻失去推进链路。",
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
                en="Anchor persistence on an internal foothold instead of internet.",
                zh="应在内部跳板节点扎根，而不是 internet。",
            )

        if target in context.state.core_assets:
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} is a core objective node and is not suitable for foothold anchoring",
                zh=f"{target} 是核心目标节点，不适合作为扎根跳板",
            )

        if node.status != "Compromised":
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} is not compromised yet; anchoring requires existing control",
                zh=f"{target} 尚未失陷，无法执行扎根",
            )

        if target in context.state.red_anchored_nodes:
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} is already anchored",
                zh=f"{target} 已存在扎根标记",
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
        if target not in context.state.red_anchored_nodes:
            context.state.red_anchored_nodes.append(target)
        return context.result(
            success=True,
            effect="persistence",
            en=f"Persistence foothold anchored on {target}",
            zh=f"已在 {target} 建立持久化扎根",
            metadata={
                "anchored": True,
                "score_value": 8,
            },
        )


@_register
class ReactivateFootholdAction(BaseAction):
    action_type = "ReactivateFoothold"
    agent_type = "Red"
    summary_en = "Reactivate control through an anchored foothold."
    summary_zh = "通过已扎根跳板重新激活控制权。"
    description_en = "Recover control at low cost when a previously anchored node has been cleaned but not deeply restored."
    description_zh = "当蓝方仅做普通恢复时，通过保留扎根低成本恢复控制权。"
    preconditions_en = (
        "The target must have an anchored foothold.",
        "The node cannot be Down.",
    )
    preconditions_zh = (
        "目标必须存在扎根标记。",
        "目标不能处于 Down。",
    )
    judgement_logic_en = (
        "Successful reactivation moves the target back to Compromised.",
    )
    judgement_logic_zh = (
        "重激活成功后目标恢复为 Compromised。",
    )
    examples_zh = (
        ActionExample(
            target="app",
            payload="触发 app 扎根后门恢复会话控制",
            rationale="在被普通恢复后快速重返关键跳板。",
        ),
    )

    def validate(self, context: ActionContext) -> ActionResult | None:
        base_error = super().validate(context)
        if base_error is not None:
            return base_error

        target, node, error = self._require_target(context)
        if error is not None or target is None or node is None:
            return error

        if target not in context.state.red_anchored_nodes:
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} has no anchored foothold",
                zh=f"{target} 不存在可重激活的扎根",
            )

        if node.status == "Down":
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} is down and cannot reactivate foothold",
                zh=f"{target} 当前下线，无法重激活扎根",
            )

        if node.status == "Compromised":
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} is already compromised",
                zh=f"{target} 已处于失陷状态，无需重激活",
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
        previous_status = node.status
        node.status = "Compromised"
        return context.result(
            success=True,
            effect="compromise",
            en=f"Anchored foothold on {target} was reactivated",
            zh=f"{target} 扎根已重激活，控制权恢复",
            metadata={
                "previous_status": previous_status,
                "anchored_reactivation": True,
                "score_value": 10,
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

        known_vuln_map = context.state.blue_known_vulnerabilities.get(target, {})
        if not isinstance(known_vuln_map, dict):
            known_vuln_map = {}
        known_vuln_ids = [vuln_id for vuln_id in known_vuln_map.keys() if vuln_id in node.vulnerabilities]
        if not known_vuln_ids:
            return context.result(
                success=False,
                effect="failed",
                en=f"No confirmed vulnerabilities on {target}; use Monitor or PreventivePatch first",
                zh=f"{target} 暂无已确认漏洞，请先 Monitor 或改用 PreventivePatch",
            )

        if context.decision.vuln_id:
            if context.decision.vuln_id not in known_vuln_ids:
                return context.result(
                    success=False,
                    effect="failed",
                    en=f"vuln_id {context.decision.vuln_id} is not confirmed for {target}",
                    zh=f"vuln_id={context.decision.vuln_id} 尚未在 {target} 被蓝方确认",
                )
        else:
            chosen_vuln_id = max(
                known_vuln_ids,
                key=lambda vuln_id: (node.vulnerabilities[vuln_id].score, vuln_id),
            )
            context.decision.vuln_id = chosen_vuln_id

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
                "patch_mode": "confirmed",
            },
        )


@_register
class PreventivePatchAction(BaseAction):
    action_type = "PreventivePatch"
    agent_type = "Blue"
    summary_en = "Perform preventive hardening when no active critical threat exists."
    summary_zh = "在平静窗口执行预防性修补与加固。"
    description_en = "Proactive hardening on a node without relying on confirmed vuln intelligence."
    description_zh = "在无活跃高危威胁时，对未完全确认漏洞细节的节点执行预防性加固。"
    preconditions_en = (
        "The target must be a real node and not Down.",
        "The node must still have vulnerabilities to harden.",
    )
    preconditions_zh = (
        "目标必须是有效节点且不能处于 Down。",
        "目标仍需存在可加固漏洞。",
    )
    judgement_logic_en = (
        "Preventive patch removes one vulnerability and applies lower score efficiency.",
    )
    judgement_logic_zh = (
        "预防性修补会移除一个漏洞，但记分效率较低。",
    )
    examples_zh = (
        ActionExample(
            target="storage",
            payload="在低威胁窗口对 storage 做预防性加固",
            rationale="降低潜在暴露面，但成本高于精准修补。",
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
                en="Preventively patch concrete infrastructure nodes instead of internet.",
                zh="预防性修补应作用于具体基础设施节点，而非 internet。",
            )

        if node.status == "Down":
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} is down; restore first before preventive patching",
                zh=f"{target} 当前下线，请先恢复后再执行预防性修补",
            )

        if not node.vulnerabilities:
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} has no remaining vulnerabilities",
                zh=f"{target} 当前没有可处理的剩余漏洞",
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
        if not node.vulnerabilities:
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} has no remaining vulnerabilities",
                zh=f"{target} 当前没有可处理的剩余漏洞",
            )

        if context.decision.vuln_id and context.decision.vuln_id in node.vulnerabilities:
            vuln_id = context.decision.vuln_id
            vulnerability = node.vulnerabilities[vuln_id]
        else:
            vuln_id, vulnerability = max(
                node.vulnerabilities.items(),
                key=lambda item: (item[1].score, item[0]),
            )
            context.decision.vuln_id = vuln_id

        previous_status = node.status
        node.vulnerabilities.pop(vuln_id, None)
        return context.result(
            success=True,
            effect="hardening",
            en=f"Preventive patch executed on {target} for vuln_id={vuln_id}",
            zh=f"已在 {target} 执行预防性修补，处理 vuln_id={vuln_id}",
            metadata={
                "patched_vulnerability": vulnerability_to_dict(vulnerability),
                "score_value": vulnerability.score,
                "previous_status": previous_status,
                "patch_mode": "preventive",
                "score_multiplier": 0.5,
                "score_multiplier_reason": "preventive_patch_low_yield",
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
        anchor_persisted = target in context.state.red_anchored_nodes
        return context.result(
            success=True,
            effect="restoration",
            en=f"{target} was restored and returned to a normal state",
            zh=f"{target} 已恢复并回到 Normal 状态",
            metadata={
                "removed_vulnerability": removed_vulnerability,
                "score_value": score_value,
                "previous_status": previous_status,
                "anchor_persisted": anchor_persisted,
            },
        )


@_register
class DeepRestoreAction(BaseAction):
    action_type = "DeepRestore"
    agent_type = "Blue"
    summary_en = "Perform heavy recovery to remove persistence and restore node integrity."
    summary_zh = "执行重度恢复，清除持久化并恢复节点完整性。"
    description_en = "High-cost remediation that clears anchored footholds and performs deeper cleanup."
    description_zh = "高成本处置动作，可清除红方扎根并完成深度恢复。"
    preconditions_en = (
        "The target must be a real infrastructure node.",
        "Use this action when compromise, downtime, or persistence risk exists.",
    )
    preconditions_zh = (
        "目标必须是有效基础设施节点。",
        "适用于存在失陷、下线或扎根残留风险的场景。",
    )
    judgement_logic_en = (
        "Node returns to Normal.",
        "Anchored foothold on target is removed when present.",
    )
    judgement_logic_zh = (
        "节点回到 Normal。",
        "若目标存在扎根，则会被彻底清除。",
    )
    examples_zh = (
        ActionExample(
            target="app",
            payload="对 app 执行深度恢复并轮换关键凭据",
            rationale="针对重复入侵风险进行彻底清理。",
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
                en="DeepRestore applies to concrete infrastructure nodes.",
                zh="DeepRestore 仅适用于具体基础设施节点。",
            )

        has_anchor = target in context.state.red_anchored_nodes
        if node.status == "Normal" and not has_anchor:
            return context.result(
                success=False,
                effect="failed",
                en=f"{target} has no compromise or persistence risk requiring DeepRestore",
                zh=f"{target} 当前无失陷或扎根风险，不需要 DeepRestore",
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
        previous_status = node.status

        removed_vulnerabilities: list[dict[str, Any]] = []
        score_value = 0
        if node.vulnerabilities:
            ranked = sorted(
                node.vulnerabilities.items(),
                key=lambda item: (item[1].score, item[0]),
                reverse=True,
            )[:2]
            for vuln_id, vulnerability in ranked:
                removed_vulnerabilities.append(vulnerability_to_dict(vulnerability))
                score_value += int(vulnerability.score)
                node.vulnerabilities.pop(vuln_id, None)

        removed_anchor = False
        if target in context.state.red_anchored_nodes:
            context.state.red_anchored_nodes = [
                node_name for node_name in context.state.red_anchored_nodes if node_name != target
            ]
            removed_anchor = True
            score_value += 10

        node.status = "Normal"
        return context.result(
            success=True,
            effect="restoration",
            en=f"DeepRestore completed on {target}; persistence removed={removed_anchor}",
            zh=f"{target} 深度恢复完成；扎根清除={removed_anchor}",
            metadata={
                "removed_vulnerabilities": removed_vulnerabilities,
                "removed_anchor": removed_anchor,
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
            metadata={"monitor_scope": target, "score_value": 0, "intel_gain": False},
        )
