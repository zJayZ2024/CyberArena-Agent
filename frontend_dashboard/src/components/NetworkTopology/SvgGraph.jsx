import AnimatedEdge from "./AnimatedEdge";
import NetworkNode from "./NetworkNode";
import NodeDetailPanel from "./NodeDetailPanel";
import { ICONS, IconAlert, IconTerminal, MULTI_HOP, NODE_CONFIGS, STATIC_EDGES, STATUS_STYLES, T, ZONE_CONFIGS } from "./constants";

function EdgeLabel({ x, y, text, color, bg }) {
  const w = Math.max(text.length * 5.5 + 16, 52);
  return (
    <g transform={`translate(${x - w / 2},${y - 9})`}>
      <rect width={w} height={16} rx={3} fill={bg} stroke={color} strokeWidth="0.7" />
      <text x={w / 2} y={11} textAnchor="middle" fontFamily={T.fontMono} fontSize={8} fill={color}>{text}</text>
    </g>
  );
}

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
      <text x={0} y={47} textAnchor="middle" fontFamily={T.fontMono} fontSize={9} fill={color} fontWeight="700">{score} pts</text>
    </g>
  );
}

function Tooltip({ cfg, status, atkCnt, defCnt }) {
  const st = STATUS_STYLES[status] || STATUS_STYLES.normal;
  const lines = [`Zone:     ${cfg.zone.toUpperCase()}`, `Ports:    ${cfg.ports.join(", ") || "none"}`, `Status:   ${st.label}`, `Attacks:  ${atkCnt}   Defenses: ${defCnt}`, ...cfg.vulns.map((v) => `Vuln: ${v}`)];
  const w = 188;
  const lh = 14;
  const pad = 10;
  const h = lines.length * lh + pad * 2 + 22;
  const tipX = cfg.x > 560 ? cfg.x - 210 : cfg.x + 34;
  const tipY = cfg.y - h / 2;

  return (
    <g transform={`translate(${tipX},${tipY})`} style={{ pointerEvents: "none" }}>
      <rect width={w} height={h} rx={6} fill={T.bgPanel} stroke={st.border} strokeWidth="1" opacity="0.97" />
      <rect width={w} height={20} rx={6} fill={`${st.border}20`} />
      <rect width={w} height={4} y={16} fill={T.bgPanel} />
      <text x={pad} y={14} fontFamily={T.fontMono} fontSize={9} fill={st.border} fontWeight="700">{cfg.label} - {cfg.id.replace("_", " ")}</text>
      {lines.map((line, index) => <text key={`${line}-${index}`} x={pad} y={pad + 24 + index * lh} fontFamily={T.fontMono} fontSize={8} fill={line.startsWith("Vuln") ? T.amber : T.grayText}>{line}</text>)}
    </g>
  );
}

function SvgGraph({ round, rounds, idx, hoveredNode, onHoverNode, showThought, onCloseThought, onOpenThought, toast }) {
  const ws = round?.world_state ?? {};
  const score = ws.score ?? { red: 0, blue: 0 };
  const targetNode = round?.red_action?.target_node;
  const defendNode = round?.blue_action?.target;
  const specialEvent = ws.special_event;

  const nodeStatus = (id) => ws.nodes?.find((node) => node.id === id)?.status ?? "normal";
  const nodeData = (id) => ws.nodes?.find((node) => node.id === id) ?? {};
  const activePath = MULTI_HOP[targetNode] ?? [];
  const attackEdges = activePath.slice(0, -1).map((_, i) => ({ a: NODE_CONFIGS[activePath[i]], b: NODE_CONFIGS[activePath[i + 1]] })).filter((edge) => edge.a && edge.b);
  const defTarget = NODE_CONFIGS[defendNode];
  const defEdge = defTarget ? { x1: 710, y1: 190, x2: defTarget.x, y2: defTarget.y } : null;

  const ghostPaths = [];
  rounds.slice(0, idx).forEach((item) => {
    if (!item?.judge_result?.success) {
      return;
    }
    const path = MULTI_HOP[item.red_action?.target_node] ?? [];
    path.slice(0, -1).forEach((_, i) => {
      const a = NODE_CONFIGS[path[i]];
      const b = NODE_CONFIGS[path[i + 1]];
      if (a && b) {
        ghostPaths.push({ x1: a.x, y1: a.y, x2: b.x, y2: b.y, key: `g${item.round}-${i}` });
      }
    });
  });

  return (
    <div style={{ position: "relative", background: T.bg, borderRadius: 10, border: `1px solid ${T.border}`, overflow: "hidden" }}>
      <style>{`
        @keyframes cyberFlow { to { stroke-dashoffset: -18; } }
        @keyframes cyberPulseRed { 0%,100% { filter: drop-shadow(0 0 5px rgba(239,68,68,.4)); } 50% { filter: drop-shadow(0 0 16px rgba(239,68,68,.9)); } }
        @keyframes cyberPulseAmber { 0%,100% { filter: drop-shadow(0 0 4px rgba(245,158,11,.3)); } 50% { filter: drop-shadow(0 0 12px rgba(245,158,11,.8)); } }
        @keyframes cyberPulseGreen { 0%,100% { filter: drop-shadow(0 0 4px rgba(34,197,94,.3)); } 50% { filter: drop-shadow(0 0 12px rgba(34,197,94,.7)); } }
        @keyframes cyberSpin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        @keyframes cyberBlink { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
      `}</style>

      {specialEvent && <div style={{ position: "absolute", top: 0, left: 0, right: 0, background: `${T.amber}20`, borderBottom: `1px solid ${T.amber}55`, padding: "5px 12px", display: "flex", alignItems: "center", gap: 8, zIndex: 15, fontFamily: T.fontMono, fontSize: 11 }}>
        <IconAlert size={12} color={T.amber} />
        <span style={{ color: T.amber, fontWeight: 600, animation: "cyberBlink 1s ease infinite" }}>
          {specialEvent === "zero_day" ? "ALERT ZERO-DAY EXPLOIT DETECTED - UNPATCHED VECTOR ACTIVE" : specialEvent === "ddos" ? "ALERT DDoS SATURATION - BLUE AGENT ACTION POINTS HALVED" : "ALERT INTEL LEAK - RED AGENT HAS CURRENT DEFENSE BLUEPRINT"}
        </span>
      </div>}

      <div style={{ position: "absolute", top: specialEvent ? 36 : 10, left: "50%", transform: `translateX(-50%) translateY(${toast.visible ? 0 : -8}px)`, background: `${T.bgPanel}f0`, border: `1px solid ${toast.color}`, borderRadius: 6, padding: "5px 14px", fontFamily: T.fontMono, fontSize: 11, color: toast.color, pointerEvents: "none", whiteSpace: "nowrap", boxShadow: `0 0 12px ${toast.color}44`, transition: "opacity .4s,transform .4s", opacity: toast.visible ? 1 : 0, zIndex: 20 }}>
        {toast.text}
      </div>

      {showThought && <NodeDetailPanel round={round} onClose={onCloseThought} />}

      <svg viewBox="0 0 800 380" width="100%" height="auto" style={{ display: "block" }} preserveAspectRatio="xMidYMid meet">
        <defs>
          <pattern id="sl" width="1" height="3" patternUnits="userSpaceOnUse"><line x1="0" y1="0" x2="1" y2="0" stroke="#fff" strokeWidth="0.4" opacity="0.012" /></pattern>
          <marker id="ar" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M1 1L9 5L1 9" fill="none" stroke={T.red} strokeWidth="1.5" /></marker>
          <marker id="ab" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M1 1L9 5L1 9" fill="none" stroke={T.blue} strokeWidth="1.5" /></marker>
          <marker id="ag" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M1 1L9 5L1 9" fill="none" stroke={T.gray} strokeWidth="1" /></marker>
        </defs>
        <rect width="800" height="380" fill="url(#sl)" />

        {Object.values(ZONE_CONFIGS).map((zone) => <g key={zone.label}><rect x={zone.x} y={zone.y} width={zone.w} height={zone.h} rx={6} fill={zone.bg} stroke={zone.color} strokeWidth="0.5" strokeDasharray="5 3" opacity={0.85} /><text x={zone.x + zone.w / 2} y={zone.y + 14} textAnchor="middle" fontFamily={T.fontMono} fontSize={8} fill={zone.color} letterSpacing="1.5" fontWeight="600" opacity="0.75">{zone.label}</text></g>)}
        {STATIC_EDGES.map(([from, to]) => {
          const a = NODE_CONFIGS[from];
          const b = NODE_CONFIGS[to];
          if (!a || !b) {
            return null;
          }
          return <line key={`${from}-${to}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={T.gray} strokeWidth="0.8" opacity="0.35" />;
        })}
        {ghostPaths.map((path) => <line key={path.key} x1={path.x1} y1={path.y1} x2={path.x2} y2={path.y2} stroke={T.red} strokeWidth="1" strokeDasharray="3 5" opacity="0.2" />)}
        <line x1={90} y1={190} x2={144} y2={190} stroke={T.redDim} strokeWidth="1" strokeDasharray="4 3" opacity="0.5" markerEnd="url(#ag)" />
        <line x1={658} y1={190} x2={616} y2={190} stroke={T.blueDim} strokeWidth="1" strokeDasharray="4 3" opacity="0.5" markerEnd="url(#ag)" />
        {attackEdges.map(({ a, b }, i) => <AnimatedEdge key={`${a.id}-${b.id}-${i}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} color={T.red} dasharray="6 3" speed={0.38} markerId="ar" opacity={0.9} />)}
        {attackEdges.length > 0 && round?.red_action?.technique_id && (() => {
          const last = attackEdges[attackEdges.length - 1];
          return <EdgeLabel x={(last.a.x + last.b.x) / 2} y={(last.a.y + last.b.y) / 2 - 18} text={`${round.red_action.technique_id} · ${round.red_action.technique?.split(" ")[0]}`} color={T.red} bg={T.redBg} />;
        })()}
        {defEdge && <>
          <AnimatedEdge x1={defEdge.x1} y1={defEdge.y1} x2={defEdge.x2} y2={defEdge.y2} color={T.blue} dasharray="7 3" speed={0.55} markerId="ab" opacity={0.85} />
          <EdgeLabel x={(defEdge.x1 + defEdge.x2) / 2} y={(defEdge.y1 + defEdge.y2) / 2 + 20} text={round?.blue_action?.type?.replace("_", " ").toUpperCase() ?? "DEFENSE"} color={T.blue} bg={T.blueBg} />
        </>}
        {Object.values(NODE_CONFIGS).map((cfg) => {
          const nd = nodeData(cfg.id);
          return <NetworkNode key={cfg.id} cfg={cfg} status={nodeStatus(cfg.id)} atkCnt={nd.attack_count ?? 0} defCnt={nd.defense_count ?? 0} isTarget={cfg.id === targetNode} isDefended={cfg.id === defendNode && nodeStatus(cfg.id) === "defended"} hovered={hoveredNode === cfg.id} onHover={onHoverNode} onClick={onOpenThought} />;
        })}
        {hoveredNode && NODE_CONFIGS[hoveredNode] && (() => {
          const cfg = NODE_CONFIGS[hoveredNode];
          const nd = nodeData(hoveredNode);
          return <Tooltip cfg={cfg} status={nodeStatus(hoveredNode)} atkCnt={nd.attack_count ?? 0} defCnt={nd.defense_count ?? 0} />;
        })()}
        <Base x={50} y={190} label="RED BASE" sublabel="ATTACKER" score={score.red} color={T.red} bg={T.redBg} glowColor={T.redGlow} Icon={IconTerminal} />
        <Base x={750} y={190} label="BLUE BASE" sublabel="DEFENDER" score={score.blue} color={T.blue} bg={T.blueBg} glowColor={T.blueGlow} Icon={ICONS.firewall} />
        <g transform="translate(400,8)">
          <rect x={-60} y={0} width={120} height={18} rx={4} fill={T.bgPanel} stroke={T.border} strokeWidth="0.5" />
          <text x={0} y={13} textAnchor="middle" fontFamily={T.fontMono} fontSize={8} fill={T.grayText} letterSpacing="1">ROUND {ws.round ?? 1} / {rounds.length} · {ws.red_phase?.toUpperCase()}</text>
        </g>
        <g transform="translate(274,368)">
          <text fontFamily={T.fontMono} fontSize={7} fill={T.grayDim} x={0} y={0}>AVAIL</text>
          <rect x={34} y={-8} width={100} height={7} rx={2} fill={T.bgPanel} stroke={T.border} strokeWidth="0.5" />
          <rect x={34} y={-8} width={100 * (ws.availability ?? 1)} height={7} rx={2} fill={T.green} opacity="0.7" />
          <text fontFamily={T.fontMono} fontSize={7} fill={T.green} x={138} y={0}>{Math.round((ws.availability ?? 1) * 100)}%</text>
        </g>
        <g transform="translate(470,356)">
          {[[T.red, true, "Attack"], [T.blue, false, "Defense"], [T.gray, false, "Network"]].map(([color, dashed, label], i) => <g key={`${label}-${i}`} transform={`translate(${i * 90},0)`}><line x1={0} y1={8} x2={20} y2={8} stroke={color} strokeWidth={1.2} strokeDasharray={dashed ? "4 2" : "none"} opacity="0.8" /><text x={24} y={12} fontFamily={T.fontMono} fontSize={7} fill={T.grayDim}>{label}</text></g>)}
        </g>
      </svg>
    </div>
  );
}

export default SvgGraph;
