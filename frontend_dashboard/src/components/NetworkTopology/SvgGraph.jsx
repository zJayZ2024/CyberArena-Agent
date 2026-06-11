import { useEffect, useState } from "react";
import AnimatedEdge from "./AnimatedEdge";
import NetworkNode from "./NetworkNode";
import {
  GRAPH_VIEW,
  IconAlert,
  IconTerminal,
  T,
  buildNodeConfigs,
  buildZoneConfigs,
  resolveNodeIcon,
} from "./constants";
import { translateAction, translatePhase } from "../../utils/localization";

function Base({ x, y, label, sublabel, score, color, bg, glowColor, Icon }) {
  return (
    <g transform={`translate(${x},${y})`}>
      <rect x={-44} y={-70} width={88} height={140} rx={8} fill={bg} stroke={color} strokeWidth={1} strokeDasharray="4 2" opacity={0.85} style={{ filter: `drop-shadow(0 0 12px ${glowColor})` }} />
      <text x={0} y={-52} textAnchor="middle" fontFamily={T.fontMono} fontSize={8} fill={color} letterSpacing="1" fontWeight="600">{label}</text>
      <circle r={26} cx={0} cy={0} fill={bg} stroke={color} strokeWidth={2.5} style={{ filter: `drop-shadow(0 0 10px ${glowColor})` }} />
      <foreignObject x={-10} y={-16} width={20} height={20} style={{ pointerEvents: "none", overflow: "visible" }}>
        <div xmlns="http://www.w3.org/1999/xhtml" style={{ display: "flex", alignItems: "center", justifyContent: "center", width: "100%", height: "100%" }}>
          <Icon size={16} color={color} />
        </div>
      </foreignObject>
      <text y={12} textAnchor="middle" fontFamily={T.fontMono} fontSize={8} fill={color} fontWeight="600">{sublabel}</text>
      <rect x={-24} y={34} width={48} height={18} rx={4} fill={`${color}18`} stroke={color} strokeWidth="0.8" />
      <text x={0} y={47} textAnchor="middle" fontFamily={T.fontMono} fontSize={9} fill={color} fontWeight="700">{score} 分</text>
    </g>
  );
}

function normalizeEdges(edges = []) {
  const normalized = [];
  const seen = new Set();

  const add = (source, target) => {
    const src = String(source || "").trim();
    const dst = String(target || "").trim();
    if (!src || !dst || src === dst) {
      return;
    }
    const key = src < dst ? `${src}|${dst}` : `${dst}|${src}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    normalized.push({ source: src, target: dst });
  };

  if (Array.isArray(edges)) {
    edges.forEach((edge) => {
      if (!edge) {
        return;
      }
      if (Array.isArray(edge) && edge.length >= 2) {
        add(edge[0], edge[1]);
        return;
      }
      if (typeof edge === "object") {
        add(edge.source, edge.target);
      }
    });
  }
  return normalized;
}

function extractRoundGraph(roundItem) {
  const ws = roundItem?.world_state ?? {};
  const nodeRows = Array.isArray(ws.nodes) ? ws.nodes : [];
  const networkNodes = ws.network_nodes ?? roundItem?.network_nodes ?? {};
  const zoneConfigs = buildZoneConfigs(nodeRows);
  const nodeConfigs = buildNodeConfigs(nodeRows, networkNodes, zoneConfigs);
  const nodeIds = Object.keys(nodeConfigs);
  const edges = normalizeEdges(ws.edges ?? roundItem?.edges ?? []).filter((edge) => nodeConfigs[edge.source] && nodeConfigs[edge.target]);

  const statusById = {};
  nodeIds.forEach((nodeId) => {
    const rowStatus = nodeRows.find((row) => row.id === nodeId)?.status;
    const netStatus = networkNodes?.[nodeId]?.status;
    statusById[nodeId] = rowStatus || netStatus || "Normal";
  });

  return {
    ws,
    nodeRows,
    networkNodes,
    nodeConfigs,
    zoneConfigs,
    nodeIds,
    edges,
    statusById,
  };
}

function findActionMetadata(roundItem, agentType) {
  const logs = Array.isArray(roundItem?.action_logs) ? roundItem.action_logs : [];
  return logs.find((log) => log?.agent_type === agentType || log?.metadata?.agent_type === agentType)?.metadata ?? {};
}

function extractAttackGraph(roundItem) {
  const redMetadata = findActionMetadata(roundItem, "Red");
  const refereeMetadata = findActionMetadata(roundItem, "Referee");
  const detailed = roundItem?.metadata?.attack_graph
    ?? roundItem?.judge_result?.metadata?.attack_graph
    ?? roundItem?.red_action?.metadata?.attack_graph
    ?? redMetadata?.attack_graph
    ?? refereeMetadata?.red_result?.attack_graph
    ?? {};
  const progress = roundItem?.referee_flow?.attack_graph_progress
    ?? refereeMetadata?.referee_flow?.attack_graph_progress
    ?? {};
  const graph = { ...detailed, ...progress };
  const sourceCandidates = Array.isArray(graph.source_candidates) ? graph.source_candidates : [];
  const source = graph.source || roundItem?.red_action?.pivot_source || sourceCandidates[0] || "";
  const target = graph.target || roundItem?.red_action?.target_node || roundItem?.red_action?.target || "";
  const interaction = roundItem?.referee_flow?.same_turn_conflict
    ?? refereeMetadata?.interaction
    ?? roundItem?.judge_result?.metadata?.interaction
    ?? {};

  return {
    ...graph,
    source,
    target,
    source_candidates: sourceCandidates,
    progressed: typeof graph.progressed === "boolean" ? graph.progressed : roundItem?.judge_result?.success === true,
    allowed: typeof graph.allowed === "boolean" ? graph.allowed : true,
    hard_interrupt: !!(interaction?.hard_interrupt || interaction?.type === "hard_interrupt"),
  };
}

function attackGraphEdge(attackGraph, graph, internetCfg) {
  const source = attackGraph?.source;
  const target = attackGraph?.target;
  const a = source === "internet" ? internetCfg : graph.nodeConfigs[source];
  const b = target === "internet" ? internetCfg : graph.nodeConfigs[target];
  return a && b && source !== target ? { a, b, source, target } : null;
}

function attackEdgeStyle(attackGraph) {
  const persistence = /persistence/i.test(String(attackGraph?.phase || ""))
    || /reactivate|anchor/i.test(String(attackGraph?.action_type || ""));
  if (attackGraph?.allowed === false) {
    return { color: T.amber, dasharray: "3 5", animated: false, markerId: "aa" };
  }
  if (persistence) {
    return { color: T.purple, dasharray: "7 4", animated: true, markerId: "ap" };
  }
  if (attackGraph?.progressed) {
    return { color: T.red, dasharray: "12 2", animated: true, markerId: "ar" };
  }
  return { color: T.red, dasharray: "2 6", animated: false, markerId: "ar" };
}

function conditionRows(attackGraph) {
  const rows = [];
  const add = (group, label, value, active = value === true) => {
    if (value === undefined || value === null || value === "" || (Array.isArray(value) && !value.length)) {
      return;
    }
    rows.push({ group, label, active, value });
  };
  add("目标条件", "服务开放", attackGraph.service_open);
  add("目标条件", "已知凭据", attackGraph.credential_known);
  add("目标条件", "存在可复用 Token", attackGraph.reusable_token);
  add("目标条件", "使用目标漏洞", attackGraph.target_vulnerability);
  add("阻断条件", "活动阻断项", attackGraph.active_blockers, false);
  add("推进结果", "允许推进", attackGraph.allowed);
  add("推进结果", "成功层级", attackGraph.success_level, attackGraph.success_level !== "none");
  return rows;
}

function extractCommandText(action = {}, fallback = "本回合没有可用的命令载荷。") {
  const candidates = [
    action?.payload,
    action?.rule_or_code,
    action?.command,
    action?.cmd,
    action?.script,
    action?.reasoning,
  ];
  const found = candidates.find((v) => typeof v === "string" && v.trim());
  return found ? found.trim() : fallback;
}

function splitZoneLabelLines(label = "") {
  const text = String(label || "").trim();
  if (!text) {
    return [];
  }
  if (text.includes(" - ")) {
    return text
      .split(" - ")
      .map((part) => part.trim())
      .filter(Boolean);
  }
  return [text];
}

function splitZoneNoteLines(note = "") {
  const text = String(note || "").trim();
  if (!text) {
    return [];
  }

  const parts = text
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean);

  if (!parts.length) {
    return [];
  }

  return parts.map((part, index) => (index < parts.length - 1 ? `${part};` : part));
}

function wrapTextLines(lines = [], maxChars = 28) {
  const wrapped = [];

  lines.forEach((line) => {
    const words = String(line || "")
      .trim()
      .split(/\s+/)
      .filter(Boolean);
    if (!words.length) {
      return;
    }

    let current = words[0];
    for (let i = 1; i < words.length; i += 1) {
      const next = `${current} ${words[i]}`;
      if (next.length <= maxChars) {
        current = next;
      } else {
        wrapped.push(current);
        current = words[i];
      }
    }
    wrapped.push(current);
  });

  return wrapped;
}

function SvgGraph({ round, rounds, idx, hoveredNode, onHoverNode, toast }) {
  const [flowDetail, setFlowDetail] = useState(null);
  const graph = extractRoundGraph(round);
  const ws = graph.ws;
  const roundTurn = Number(round?.round ?? round?.turn ?? ws?.round);
  const turnNumber = Number.isFinite(roundTurn)
    ? roundTurn
    : Number(idx ?? 0);
  const allowTurnActions = Number.isFinite(turnNumber) ? turnNumber > 0 : true;
  const score = ws.score ?? { red: 0, blue: 0 };
  const totalRounds = (() => {
    const fromCurrent = Number(
      round?.total_rounds
      ?? round?.totalRounds
      ?? ws?.total_rounds
      ?? ws?.totalRounds,
    );
    if (Number.isFinite(fromCurrent) && fromCurrent > 0) {
      return fromCurrent;
    }

    const fromList = (Array.isArray(rounds) ? rounds : [])
      .map((item) => Number(
        item?.total_rounds
        ?? item?.totalRounds
        ?? item?.world_state?.total_rounds
        ?? item?.world_state?.totalRounds,
      ))
      .find((value) => Number.isFinite(value) && value > 0);
    if (typeof fromList === "number") {
      return fromList;
    }

    const turns = (Array.isArray(rounds) ? rounds : [])
      .map((item) => Number(item?.round ?? item?.turn ?? item?.world_state?.round))
      .filter((value) => Number.isFinite(value) && value >= 0);
    if (turns.length) {
      return Math.max(...turns);
    }

    return Math.max((Array.isArray(rounds) ? rounds.length : 1) - 1, 1);
  })();
  const displayRound = Number.isFinite(turnNumber)
    ? Math.min(Math.max(Math.round(turnNumber), 0), totalRounds)
    : 0;
  const displayPhase = translatePhase(ws.red_phase || "recon");
  const framePhaseLabel = round?.__frame_phase_label;
  const attackGraph = extractAttackGraph(round);
  const targetNode = attackGraph.target || round?.red_action?.target_node || round?.red_action?.target;
  const defendNode = round?.blue_action?.target || round?.blue_action?.target_node;
  const hasCurrentRedAction = !!(allowTurnActions && attackGraph.source && targetNode);
  const hasCurrentBlueAction = !!(
    allowTurnActions
    && defendNode
    && graph.nodeConfigs[defendNode]
    && (round?.blue_action?.type || round?.blue_action?.action_type)
  );
  const specialEvent = ws.special_event;
  const stateChanges = Array.isArray(round?.referee_flow?.state_changes)
    ? round.referee_flow.state_changes
    : [];
  const changedNodeIds = new Set(
    round?.__frame_phase === "start"
      ? []
      : stateChanges.map((change) => change?.node ?? change?.target).filter(Boolean),
  );

  const nodeStatus = (id) => graph.statusById[id] ?? "Normal";
  const nodeData = (id) => graph.nodeRows.find((node) => node.id === id) ?? {};
  const externalZoneCfg = graph.zoneConfigs.find((zone) => zone.id === "external");
  const internetCfg = externalZoneCfg
    ? {
        id: "internet",
        x: Math.round(externalZoneCfg.x + externalZoneCfg.w * 0.52),
        y: Math.round(externalZoneCfg.y + externalZoneCfg.h * 0.54),
      }
    : { id: "internet", x: Math.round(GRAPH_VIEW.zoneX + 56), y: GRAPH_VIEW.baseY };
  const InternetIcon = resolveNodeIcon("internet", "external");
  const internetColor = T.grayDim;

  const currentAttackEdge = hasCurrentRedAction ? attackGraphEdge(attackGraph, graph, internetCfg) : null;
  const currentAttackStyle = attackEdgeStyle(attackGraph);
  const historicalAttackEdges = (Array.isArray(rounds) ? rounds : [])
    .slice(0, Math.max(0, Number(idx) + 1))
    .map((item) => extractAttackGraph(item))
    .filter((item) => item.progressed)
    .map((item) => ({ item, edge: attackGraphEdge(item, graph, internetCfg) }))
    .filter(({ edge }, index, list) => edge && list.findIndex((other) => other.edge?.source === edge.source && other.edge?.target === edge.target) === index)
    .filter(({ edge }) => edge && !(attackGraph.progressed && edge.source === currentAttackEdge?.source && edge.target === currentAttackEdge?.target));
  const defendTargetCfg = hasCurrentBlueAction ? graph.nodeConfigs[defendNode] : null;
  const defEdge = defendTargetCfg
    ? { x1: GRAPH_VIEW.blueBaseX, y1: GRAPH_VIEW.baseY, x2: defendTargetCfg.x, y2: defendTargetCfg.y }
    : null;
  const persistentInternetLink = {
    x1: GRAPH_VIEW.redBaseX + 30,
    y1: GRAPH_VIEW.baseY,
    x2: internetCfg.x - 22,
    y2: internetCfg.y,
  };

  useEffect(() => {
    setFlowDetail(null);
  }, [idx, round?.round, round?.turn]);

  const openAttackFlowDetail = () => {
    if (!hasCurrentRedAction) {
      return;
    }
    setFlowDetail({
      type: "攻击路径",
      start: attackGraph.source,
      target: targetNode,
      route: `${attackGraph.source} -> ${targetNode}`,
      payload: extractCommandText(round?.red_action),
      color: currentAttackStyle.color,
      attackGraph: {
        ...attackGraph,
        source_state: graph.networkNodes?.[attackGraph.source]?.red_state,
      },
    });
  };
  const openDefenseFlowDetail = () => {
    if (!hasCurrentBlueAction) {
      return;
    }
    setFlowDetail({
      type: "防御路径",
      start: "蓝方基地",
      target: defendNode,
      route: `蓝方基地 -> ${defendNode}`,
      payload: extractCommandText(round?.blue_action),
      color: T.blue,
    });
  };

  return (
    <div style={{ position: "relative", width: "100%", height: "100%", background: "transparent", overflow: "hidden" }}>
      <style>{`
        @keyframes cyberFlow { to { stroke-dashoffset: -18; } }
        @keyframes cyberPulseRed { 0%,100% { filter: drop-shadow(0 0 5px rgba(255,107,122,.4)); } 50% { filter: drop-shadow(0 0 16px rgba(255,107,122,.9)); } }
        @keyframes cyberPulseAmber { 0%,100% { filter: drop-shadow(0 0 4px rgba(255,204,85,.3)); } 50% { filter: drop-shadow(0 0 12px rgba(255,204,85,.8)); } }
        @keyframes cyberPulseGreen { 0%,100% { filter: drop-shadow(0 0 4px rgba(52,224,141,.3)); } 50% { filter: drop-shadow(0 0 12px rgba(52,224,141,.7)); } }
        @keyframes cyberSpin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        @keyframes cyberBlink { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
        @keyframes stateDeltaPulse { 0%,100% { opacity: .35; transform: scale(.94); } 50% { opacity: 1; transform: scale(1.08); } }
      `}</style>

      {specialEvent && <div style={{ position: "absolute", top: 0, left: 0, right: 0, background: `${T.amber}20`, borderBottom: `1px solid ${T.amber}55`, padding: "5px 12px", display: "flex", alignItems: "center", gap: 8, zIndex: 15, fontFamily: T.fontMono, fontSize: 11 }}>
        <IconAlert size={12} color={T.amber} />
        <span style={{ color: T.amber, fontWeight: 600, animation: "cyberBlink 1s ease infinite" }}>
          {specialEvent === "zero_day" ? "告警：检测到零日利用，未修补向量活跃" : specialEvent === "ddos" ? "告警：DDoS 饱和，蓝方行动点减半" : "告警：情报泄露，红方已掌握当前防御蓝图"}
        </span>
      </div>}

      {hasCurrentRedAction && (
        <button
          type="button"
          onClick={openAttackFlowDetail}
          style={{
            position: "absolute",
            top: specialEvent ? 34 : 6,
            left: "50%",
            transform: "translateX(-50%)",
            width: 430,
            padding: "6px 10px",
            display: "grid",
            gridTemplateColumns: "1fr auto",
            gap: "2px 12px",
            textAlign: "left",
            background: `${T.bgPanel}f2`,
            border: `1px solid ${currentAttackStyle.color}88`,
            borderLeft: `3px solid ${currentAttackStyle.color}`,
            borderRadius: 7,
            color: T.grayText,
            fontFamily: T.fontMono,
            cursor: "pointer",
            zIndex: 24,
            boxShadow: `0 8px 24px ${currentAttackStyle.color}18`,
          }}
        >
          <span style={{ fontSize: 9, color: currentAttackStyle.color, letterSpacing: 0.7 }}>
            {attackGraph.phase || "Attack Graph"} · {attackGraph.technique || round?.red_action?.technique || round?.red_action?.action_type}
          </span>
          <span style={{ gridRow: "span 2", alignSelf: "center", fontSize: 8, color: attackGraph.hard_interrupt ? T.amber : attackGraph.progressed ? T.green : attackGraph.allowed === false ? T.amber : T.red }}>
            {attackGraph.hard_interrupt ? "硬中断" : attackGraph.progressed ? "已推进" : attackGraph.allowed === false ? "已阻断" : "未推进"}
          </span>
          <span style={{ fontSize: 10, color: "#f0f4ff" }}>
            {attackGraph.source} → {attackGraph.target}
            {attackGraph.result ? <span style={{ marginLeft: 8, color: T.grayDim }}>结果：{attackGraph.result}</span> : null}
          </span>
        </button>
      )}

      <div style={{ position: "absolute", top: specialEvent ? 78 : 50, left: "50%", transform: `translateX(-50%) translateY(${toast.visible ? 0 : -8}px)`, background: `${T.bgPanel}f0`, border: `1px solid ${toast.color}`, borderRadius: 6, padding: "5px 14px", fontFamily: T.fontMono, fontSize: 11, color: toast.color, pointerEvents: "none", whiteSpace: "nowrap", boxShadow: `0 0 12px ${toast.color}44`, transition: "opacity .4s,transform .4s", opacity: toast.visible ? 1 : 0, zIndex: 20 }}>
        {toast.text}
      </div>

      <svg viewBox={`0 0 ${GRAPH_VIEW.width} ${GRAPH_VIEW.height}`} width="100%" height="100%" style={{ display: "block", width: "100%", height: "100%" }} preserveAspectRatio="xMidYMid meet">
        <defs>
          <pattern id="sl" width="1" height="3" patternUnits="userSpaceOnUse"><line x1="0" y1="0" x2="1" y2="0" stroke="#fff" strokeWidth="0.4" opacity="0.012" /></pattern>
          <marker id="ar" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M1 1L9 5L1 9" fill="none" stroke={T.red} strokeWidth="1.5" /></marker>
          <marker id="ab" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M1 1L9 5L1 9" fill="none" stroke={T.blue} strokeWidth="1.5" /></marker>
          <marker id="aa" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M1 1L9 5L1 9" fill="none" stroke={T.amber} strokeWidth="1.5" /></marker>
          <marker id="ap" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M1 1L9 5L1 9" fill="none" stroke={T.purple} strokeWidth="1.5" /></marker>
        </defs>
        <rect width={GRAPH_VIEW.width} height={GRAPH_VIEW.height} fill="url(#sl)" />

        {graph.zoneConfigs.map((zone) => {
          const labelLines = wrapTextLines(splitZoneLabelLines(zone.label), 24);
          const noteLines = wrapTextLines(splitZoneNoteLines(zone.note), 30);
          const labelStartY = zone.y + 14;
          const noteStartY = labelStartY + labelLines.length * 10 + 2;
          const labelFontSize = 8;
          const labelTracking = "1.5";

          return (
            <g key={zone.id}>
              <rect x={zone.x} y={zone.y} width={zone.w} height={zone.h} rx={6} fill={zone.bg} stroke={zone.color} strokeWidth="0.5" strokeDasharray="5 3" opacity={0.85} />
              {labelLines.map((line, index) => (
                <text
                  key={`${zone.id}-label-${index}`}
                  x={zone.x + zone.w / 2}
                  y={labelStartY + index * 9}
                  textAnchor="middle"
                  fontFamily={T.fontMono}
                  fontSize={labelFontSize}
                  fill={zone.color}
                  letterSpacing={labelTracking}
                  fontWeight="600"
                  opacity="0.75"
                >
                  {line}
                </text>
              ))}
              {noteLines.map((line, index) => (
                <text
                  key={`${zone.id}-note-${index}`}
                  x={zone.x + zone.w / 2}
                  y={noteStartY + index * 8}
                  textAnchor="middle"
                  fontFamily={T.fontMono}
                  fontSize={6}
                  fill={zone.color}
                  letterSpacing="0.35"
                  opacity="0.62"
                >
                  {line}
                </text>
              ))}
            </g>
          );
        })}
        {graph.edges.map((edge) => {
          const a = graph.nodeConfigs[edge.source];
          const b = graph.nodeConfigs[edge.target];
          if (!a || !b) {
            return null;
          }
          return <line key={`${edge.source}-${edge.target}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={T.gray} strokeWidth="0.8" opacity={0.36} />;
        })}
        <line x1={persistentInternetLink.x1} y1={persistentInternetLink.y1} x2={persistentInternetLink.x2} y2={persistentInternetLink.y2} stroke={T.redDim} strokeWidth="1.2" strokeDasharray="6 3" opacity="0.85" />
        {historicalAttackEdges.map(({ item, edge }) => (
          <AnimatedEdge
            key={`history-${edge.source}-${edge.target}`}
            x1={edge.a.x}
            y1={edge.a.y}
            x2={edge.b.x}
            y2={edge.b.y}
            color={attackEdgeStyle(item).color}
            dasharray={attackEdgeStyle(item).dasharray}
            markerId={attackEdgeStyle(item).markerId}
            opacity={0.35}
            animated={false}
            strokeWidth={1.2}
            endPadding={24}
          />
        ))}
        {currentAttackEdge && (
          <AnimatedEdge
            x1={currentAttackEdge.a.x}
            y1={currentAttackEdge.a.y}
            x2={currentAttackEdge.b.x}
            y2={currentAttackEdge.b.y}
            color={currentAttackStyle.color}
            dasharray={currentAttackStyle.dasharray}
            speed={0.38}
            markerId={currentAttackStyle.markerId}
            opacity={0.95}
            animated={currentAttackStyle.animated}
            interrupt={attackGraph.hard_interrupt}
            onClick={openAttackFlowDetail}
            title="查看真实 Attack Graph 步骤"
            endPadding={24}
          />
        )}
        {defEdge && <AnimatedEdge x1={defEdge.x1} y1={defEdge.y1} x2={defEdge.x2} y2={defEdge.y2} color={T.blue} dasharray="7 3" speed={0.55} markerId="ab" opacity={0.85} onClick={openDefenseFlowDetail} title="查看防御路径详情" endPadding={24} />}
        <g transform={`translate(${internetCfg.x},${internetCfg.y})`}>
          <circle r={24} cx={0} cy={0} fill="#111a2e" stroke={internetColor} strokeWidth="1.8" />
          <circle r={30} cx={0} cy={0} fill="none" stroke={internetColor} strokeWidth="0.9" strokeDasharray="3 3" opacity="0.7" />
          <foreignObject x={-10} y={-16} width={20} height={20} style={{ pointerEvents: "none", overflow: "visible" }}>
            <div xmlns="http://www.w3.org/1999/xhtml" style={{ display: "flex", alignItems: "center", justifyContent: "center", width: "100%", height: "100%" }}>
              <InternetIcon size={14} color={internetColor} />
            </div>
          </foreignObject>
          <text y={9} textAnchor="middle" fontFamily={T.fontMono} fontSize={8} fill={internetColor} fontWeight="700">互联网</text>
        </g>
        {Object.values(graph.nodeConfigs).map((cfg) => {
          const nd = nodeData(cfg.id);
          return <NetworkNode key={cfg.id} cfg={cfg} status={nodeStatus(cfg.id)} nodeState={graph.networkNodes?.[cfg.id] ?? nd} atkCnt={nd.attack_count ?? 0} defCnt={nd.defense_count ?? 0} isTarget={hasCurrentRedAction && cfg.id === targetNode} isDefended={hasCurrentBlueAction && cfg.id === defendNode} isChanged={changedNodeIds.has(cfg.id)} hovered={hoveredNode === cfg.id} onHover={onHoverNode} onClick={() => {}} />;
        })}
        <Base x={GRAPH_VIEW.redBaseX} y={GRAPH_VIEW.baseY} label="红方基地" sublabel="攻击者" score={score.red} color={T.red} bg={T.redBg} glowColor={T.redGlow} Icon={IconTerminal} />
        <Base x={GRAPH_VIEW.blueBaseX} y={GRAPH_VIEW.baseY} label="蓝方基地" sublabel="防守者" score={score.blue} color={T.blue} bg={T.blueBg} glowColor={T.blueGlow} Icon={resolveNodeIcon("fw", "dmz")} />
        <g transform={`translate(${GRAPH_VIEW.width / 2},0)`}>
          <rect x={-104} y={0} width={208} height={18} rx={4} fill={T.bgPanel} stroke={T.border} strokeWidth="0.5" />
          <text x={0} y={13} textAnchor="middle" fontFamily={T.fontMono} fontSize={8} fill={T.grayText} letterSpacing="1">
            {`回合 ${displayRound} / ${totalRounds} - ${displayPhase}${framePhaseLabel ? ` · ${framePhaseLabel}` : ""}`}
          </text>
        </g>
        <g transform={`translate(${Math.floor(GRAPH_VIEW.width / 2) - 120},${GRAPH_VIEW.height - 20})`}>
          <text fontFamily={T.fontMono} fontSize={7} fill={T.grayDim} x={0} y={0}>可用性</text>
          <rect x={34} y={-8} width={100} height={7} rx={2} fill={T.bgPanel} stroke={T.border} strokeWidth="0.5" />
          <rect x={34} y={-8} width={100 * (ws.availability ?? 1)} height={7} rx={2} fill={T.green} opacity="0.7" />
          <text fontFamily={T.fontMono} fontSize={7} fill={T.green} x={138} y={0}>{Math.round((ws.availability ?? 1) * 100)}%</text>
        </g>
        <g transform={`translate(${Math.floor(GRAPH_VIEW.width / 2) + 80},${GRAPH_VIEW.height - 32})`}>
          {[[T.red, true, "攻击"], [T.blue, false, "防御"], [T.gray, false, "网络"]].map(([color, dashed, label], i) => <g key={`${label}-${i}`} transform={`translate(${i * 90},0)`}><line x1={0} y1={8} x2={20} y2={8} stroke={color} strokeWidth={1.2} strokeDasharray={dashed ? "4 2" : "none"} opacity="0.8" /><text x={24} y={12} fontFamily={T.fontMono} fontSize={7} fill={T.grayDim}>{label}</text></g>)}
        </g>
      </svg>
      {flowDetail && (
        <div style={{ position: "absolute", right: 14, bottom: 14, width: 320, background: `${T.bgPanel}f5`, border: `1px solid ${flowDetail.color}`, borderRadius: 8, padding: 10, zIndex: 40, boxShadow: `0 0 16px ${flowDetail.color}33` }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, marginBottom: 8 }}>
            <div style={{ fontFamily: T.fontMono, fontSize: 11, color: flowDetail.color, fontWeight: 700, letterSpacing: 0.6 }}>{flowDetail.type}</div>
            <button type="button" onClick={() => setFlowDetail(null)} style={{ fontFamily: T.fontMono, fontSize: 10, color: T.grayText, background: "transparent", border: `1px solid ${T.border}`, borderRadius: 4, padding: "2px 8px", cursor: "pointer" }}>
              关闭
            </button>
          </div>
          {flowDetail.attackGraph ? (
            <>
              <div style={{ fontFamily: T.fontMono, fontSize: 10, color: T.grayText, lineHeight: 1.65 }}>
                <div>攻击步骤：<span style={{ color: "#f0f4ff" }}>{flowDetail.route}</span></div>
                {flowDetail.attackGraph.technique ? <div>技术：<span style={{ color: T.red }}>{flowDetail.attackGraph.technique}</span></div> : null}
                {flowDetail.attackGraph.phase ? <div>阶段：<span style={{ color: T.purple }}>{flowDetail.attackGraph.phase}</span></div> : null}
              </div>
              <div style={{ marginTop: 8, display: "grid", gap: 6, maxHeight: 210, overflowY: "auto" }}>
                {flowDetail.attackGraph.source_state ? (
                  <div style={{ background: T.bg, border: `1px solid ${T.border}`, borderRadius: 5, padding: "6px 8px" }}>
                    <div style={{ marginBottom: 3, fontFamily: T.fontMono, fontSize: 8, color: T.grayDim, letterSpacing: 0.7 }}>来源控制能力</div>
                    {[
                      ["Session", flowDetail.attackGraph.source_state.session_active],
                      ["Foothold", flowDetail.attackGraph.source_state.foothold],
                      ["Persistence", flowDetail.attackGraph.source_state.persistence],
                    ].filter(([, active]) => active).map(([label]) => (
                      <div key={label} style={{ fontFamily: T.fontMono, fontSize: 9, color: T.green, lineHeight: 1.55 }}>✓ {label}</div>
                    ))}
                  </div>
                ) : null}
                {Object.entries(conditionRows(flowDetail.attackGraph).reduce((groups, row) => {
                  groups[row.group] = [...(groups[row.group] || []), row];
                  return groups;
                }, {})).map(([group, rows]) => (
                  <div key={group} style={{ background: T.bg, border: `1px solid ${T.border}`, borderRadius: 5, padding: "6px 8px" }}>
                    <div style={{ marginBottom: 3, fontFamily: T.fontMono, fontSize: 8, color: T.grayDim, letterSpacing: 0.7 }}>{group}</div>
                    {rows.map((row) => (
                      <div key={row.label} style={{ fontFamily: T.fontMono, fontSize: 9, color: row.active ? T.green : T.grayText, lineHeight: 1.55 }}>
                        {row.active ? "✓" : "○"} {row.label}
                        {typeof row.value === "string" ? `：${row.value}` : Array.isArray(row.value) ? `：${row.value.join("、")}` : ""}
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            </>
          ) : (
            <>
              <div style={{ fontFamily: T.fontMono, fontSize: 10, color: T.grayText, lineHeight: 1.6 }}>
                <div>起点：<span style={{ color: "#f0f4ff" }}>{flowDetail.start}</span></div>
                <div>目标：<span style={{ color: "#f0f4ff" }}>{flowDetail.target}</span></div>
                <div>路径：<span style={{ color: "#f0f4ff" }}>{flowDetail.route}</span></div>
              </div>
              <div style={{ marginTop: 8, fontFamily: T.fontMono, fontSize: 10, color: T.grayDim }}>载荷 / 命令</div>
              <pre style={{ marginTop: 4, marginBottom: 0, maxHeight: 120, overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word", background: T.bg, border: `1px solid ${T.border}`, borderRadius: 6, padding: 8, fontFamily: T.fontMono, fontSize: 10, color: "#f0f4ff" }}>
                {flowDetail.payload}
              </pre>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default SvgGraph;

