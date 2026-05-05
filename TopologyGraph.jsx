/**
 * TopologyGraph.jsx
 * ─────────────────────────────────────────────────────────────────
 * CyberArena Red-vs-Blue Network Topology Visualiser
 *
 * REUSABLE API
 * ────────────
 * Props:
 *   roundData   {RoundResult}   – current round from simulation.json
 *   allRounds   {RoundResult[]} – full replay array (for path history)
 *   currentIdx  {number}        – index into allRounds (0-based)
 *
 * Exported helpers (re-use in other components):
 *   NODE_CONFIGS  – static node metadata (position, icon, zone, ports…)
 *   ZONE_CONFIGS  – zone metadata (label, color, bounds)
 *   getNodeStatus – (worldState, nodeId) => "normal"|"scanning"|"compromised"|"defended"
 *   STATUS_STYLES – status-to-CSS-vars mapping
 *
 * Dependencies (all in package.json already):
 *   react, lucide-react
 *   No extra charting lib needed – pure SVG.
 *
 * ─────────────────────────────────────────────────────────────────
 */

import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  Shield, Server, Database, Monitor, Globe,
  Cpu, Terminal, AlertTriangle, CheckCircle, Wifi
} from "lucide-react";

// ─── DESIGN TOKENS ────────────────────────────────────────────────
const T = {
  bg:          "#07090f",
  bgPanel:     "#0d1117",
  bgNode:      "#111827",
  border:      "#1f2937",
  borderDim:   "#161c26",

  red:         "#ef4444",
  redDim:      "#7f1d1d",
  redBg:       "#1a0a0a",
  redGlow:     "rgba(239,68,68,0.55)",

  blue:        "#3b82f6",
  blueDim:     "#1e3a5f",
  blueBg:      "#080f1c",
  blueGlow:    "rgba(59,130,246,0.55)",

  green:       "#22c55e",
  greenBg:     "#071510",
  greenGlow:   "rgba(34,197,94,0.45)",

  amber:       "#f59e0b",
  amberBg:     "#1a1000",

  gray:        "#374151",
  grayMid:     "#4b5563",
  grayText:    "#9ca3af",
  grayDim:     "#6b7280",

  fontMono:    "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
  fontUI:      "'Inter', 'DM Sans', system-ui, sans-serif",
};

// ─── ZONE DEFINITIONS ─────────────────────────────────────────────
// x/y in the 800×380 SVG coordinate space
export const ZONE_CONFIGS = {
  internet:  { label: "INTERNET",  x: 110, y: 15,  w: 120, h: 350, color: T.gray,    bg: "rgba(55,65,81,0.04)"  },
  dmz:       { label: "DMZ",       x: 250, y: 15,  w: 120, h: 350, color: T.blue,    bg: "rgba(59,130,246,0.04)" },
  internal:  { label: "INTERNAL",  x: 390, y: 15,  w: 120, h: 350, color: T.green,   bg: "rgba(34,197,94,0.04)"  },
  database:  { label: "DATABASE",  x: 530, y: 15,  w: 120, h: 350, color: T.amber,   bg: "rgba(245,158,11,0.04)" },
};

// ─── NODE DEFINITIONS ─────────────────────────────────────────────
export const NODE_CONFIGS = {
  web_server: {
    id: "web_server", label: "WEB",  sublabel: ":80/:443",
    zone: "dmz",      x: 310, y: 120,
    icon: Globe,      ports: [80, 443],
    vulns: ["SQLi-login", "CVE-2021-44228"],
    description: "Nginx 1.18 · PHP 7.4 · Exposed to DMZ",
  },
  dns_server: {
    id: "dns_server", label: "DNS",  sublabel: ":53",
    zone: "dmz",      x: 310, y: 250,
    icon: Wifi,       ports: [53],
    vulns: ["DNS-cache-poison"],
    description: "BIND 9.16 · DMZ resolver",
  },
  app_server: {
    id: "app_server", label: "APP",  sublabel: ":8080",
    zone: "internal", x: 450, y: 120,
    icon: Cpu,        ports: [8080, 8443],
    vulns: ["CVE-2023-1234"],
    description: "Tomcat 10 · Internal application tier",
  },
  admin_host: {
    id: "admin_host", label: "ADM",  sublabel: ":22",
    zone: "internal", x: 450, y: 250,
    icon: Monitor,    ports: [22, 3389],
    vulns: ["Weak-SSH-key"],
    description: "Admin workstation · Jump host",
  },
  database: {
    id: "database",   label: "DB",   sublabel: ":3306",
    zone: "database", x: 590, y: 190,
    icon: Database,   ports: [3306, 5432],
    vulns: ["SQLi-stored", "Unpatched-MySQL"],
    description: "MySQL 8.0 · Contains sensitive data · FINAL TARGET",
  },
  firewall: {
    id: "firewall",   label: "FW",   sublabel: "gateway",
    zone: "internet", x: 170, y: 190,
    icon: Shield,     ports: [],
    vulns: [],
    description: "pfSense 2.7 · Internet-facing gateway",
  },
};

// Static network edges (always visible, grey)
const STATIC_EDGES = [
  { from: "firewall",   to: "web_server"  },
  { from: "firewall",   to: "dns_server"  },
  { from: "web_server", to: "app_server"  },
  { from: "dns_server", to: "app_server"  },
  { from: "app_server", to: "database"    },
  { from: "app_server", to: "admin_host"  },
  { from: "admin_host", to: "database"    },
];

// ─── STATUS STYLES (reusable by VulnPanel, Timeline, etc.) ────────
export const STATUS_STYLES = {
  normal:      { border: T.blue,   bg: T.bgNode,  glow: "none",           dot: T.green, label: "ONLINE"      },
  scanning:    { border: T.amber,  bg: T.amberBg, glow: `0 0 10px ${T.amber}55`, dot: T.amber, label: "SCANNING"    },
  compromised: { border: T.red,    bg: T.redBg,   glow: `0 0 14px ${T.redGlow}`, dot: T.red,   label: "COMPROMISED" },
  defended:    { border: T.green,  bg: T.greenBg, glow: `0 0 10px ${T.greenGlow}`, dot: T.green, label: "HARDENED"  },
  patched:     { border: T.green,  bg: T.greenBg, glow: `0 0 8px ${T.greenGlow}`,  dot: T.green, label: "PATCHED"   },
};

// ─── HELPERS ──────────────────────────────────────────────────────
export function getNodeStatus(worldState, nodeId) {
  if (!worldState?.nodes) return "normal";
  const node = worldState.nodes.find((n) => n.id === nodeId);
  return node?.status ?? "normal";
}

function cx(...classes) { return classes.filter(Boolean).join(" "); }

// ─── MOCK DATA (used when no props supplied) ───────────────────────
const MOCK_WORLD_STATE = {
  round: 7,
  nodes: [
    { id: "web_server",  status: "compromised", attack_count: 3, defense_count: 1 },
    { id: "dns_server",  status: "normal",       attack_count: 0, defense_count: 0 },
    { id: "app_server",  status: "defended",     attack_count: 1, defense_count: 2 },
    { id: "admin_host",  status: "normal",       attack_count: 0, defense_count: 0 },
    { id: "database",    status: "scanning",     attack_count: 1, defense_count: 0 },
    { id: "firewall",    status: "normal",       attack_count: 0, defense_count: 1 },
  ],
  score: { red: 42, blue: 68 },
  red_phase: "Exploit",
  availability: 0.87,
  blue_action_points: 1,
  special_event: null,
};

const MOCK_ROUND = {
  round: 7,
  red_action: {
    technique: "SQL Injection",
    target_node: "database",
    technique_id: "T1190",
    payload: "' OR 1=1 --",
    reasoning: "Web server is compromised. Direct path to database via app_server lateral move. SQL injection exploits unpatched MySQL endpoint on port 3306. High success probability: patch_level 0.3, no IDS signature for this payload variant.",
  },
  judge_result: {
    success: true,
    damage: 25,
    logs: [
      "[CRIT] SQL injection attempt on /api/v2/users — payload detected",
      "[WARN] Unusual query volume: 1,240 req/s from 10.0.2.15",
      "[INFO] DB connection from APP_SERVER — flagged as suspicious",
    ],
    node_status_change: "scanning",
    success_prob: 0.72,
    narrative: "Red agent pivoted through compromised web_server, using stored credentials to reach the database tier via a crafted SQL payload targeting the unpatched login endpoint.",
  },
  blue_action: {
    type: "firewall_rule",
    target: "database",
    rule_or_code: "iptables -A INPUT -p tcp --dport 3306 -s 10.0.0.0/8 -j DROP\n# Block direct DB access from internal subnet",
    action_cost: 1,
    effectiveness: 0.65,
    reasoning: "Database is under active attack. Highest priority: isolate DB port 3306. Deploying firewall rule to drop internal subnet access — accept false positive risk to stop active exfiltration attempt.",
  },
  world_state: MOCK_WORLD_STATE,
};

// ─── SUB-COMPONENTS ───────────────────────────────────────────────

/** Animated flowing dash line for attack/defense edges */
function AnimatedEdge({ x1, y1, x2, y2, color, dasharray = "6 3", speed = 0.4, opacity = 0.9, markerId }) {
  const id = useRef(`edge-anim-${Math.random().toString(36).slice(2)}`).current;
  return (
    <g>
      <line
        x1={x1} y1={y1} x2={x2} y2={y2}
        stroke={color} strokeWidth="1.8"
        strokeDasharray={dasharray}
        markerEnd={`url(#${markerId})`}
        opacity={opacity}
        style={{ animation: `cyberFlowEdge ${speed}s linear infinite` }}
      />
    </g>
  );
}

/** Historical ghost path (already-compromised route) */
function GhostEdge({ x1, y1, x2, y2 }) {
  return (
    <line
      x1={x1} y1={y1} x2={x2} y2={y2}
      stroke={T.red} strokeWidth="1"
      strokeDasharray="3 5"
      opacity="0.25"
    />
  );
}

/** Single node circle with icon, status glow, badges */
function TopologyNode({ config, status, attackCount = 0, defenseCount = 0, isTarget, isDefended, onClick, hovered, onHover }) {
  const st = STATUS_STYLES[status] || STATUS_STYLES.normal;
  const Icon = config.icon;
  const pulseAnim = status === "scanning"     ? "cyberPulseAmber"
                  : status === "compromised"  ? "cyberPulseRed"
                  : status === "defended"     ? "cyberPulseGreen"
                  : "none";
  const r = 24;

  return (
    <g
      transform={`translate(${config.x}, ${config.y})`}
      onClick={onClick}
      onMouseEnter={() => onHover(config.id)}
      onMouseLeave={() => onHover(null)}
      style={{ cursor: "pointer" }}
    >
      {/* Outer glow ring — animated when active */}
      {status !== "normal" && (
        <circle
          r={r + 8} cx={0} cy={0}
          fill="none"
          stroke={st.border}
          strokeWidth="0.8"
          strokeDasharray="3 3"
          opacity="0.5"
          style={{ animation: `cyberSpin 6s linear infinite`, transformOrigin: "0 0" }}
        />
      )}

      {/* Main circle */}
      <circle
        r={r} cx={0} cy={0}
        fill={st.bg}
        stroke={st.border}
        strokeWidth={isTarget ? 2.5 : 1.8}
        style={{ filter: st.glow !== "none" ? `drop-shadow(${st.glow})` : "none",
                 animation: pulseAnim !== "none" ? `${pulseAnim} 1.8s ease-in-out infinite` : "none" }}
      />

      {/* Hover highlight */}
      {hovered && (
        <circle r={r} cx={0} cy={0} fill="white" opacity="0.04" />
      )}

      {/* Icon — rendered as foreignObject for lucide */}
      <foreignObject x={-10} y={-18} width={20} height={20} style={{ pointerEvents: "none" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", width: "100%", height: "100%" }}>
          <Icon size={14} color={st.border} strokeWidth={1.5} />
        </div>
      </foreignObject>

      {/* Label */}
      <text y={6} textAnchor="middle" fontFamily={T.fontMono} fontSize={9} fontWeight="600" fill={st.border}>{config.label}</text>
      <text y={16} textAnchor="middle" fontFamily={T.fontMono} fontSize={7} fill={T.grayDim}>{config.sublabel}</text>

      {/* Status dot (bottom right) */}
      <circle cx={18} cy={18} r={5} fill={T.bg} />
      <circle cx={18} cy={18} r={4} fill={st.dot} />

      {/* Attack count badge (top left, red) */}
      {attackCount > 0 && (
        <g transform="translate(-22, -22)">
          <circle r={7} cx={0} cy={0} fill={T.redBg} stroke={T.red} strokeWidth="0.8" />
          <text textAnchor="middle" y={3} fontFamily={T.fontMono} fontSize={7} fill={T.red} fontWeight="700">{attackCount}</text>
        </g>
      )}

      {/* Defense count badge (top right, blue) */}
      {defenseCount > 0 && (
        <g transform="translate(22, -22)">
          <circle r={7} cx={0} cy={0} fill={T.blueBg} stroke={T.blue} strokeWidth="0.8" />
          <text textAnchor="middle" y={3} fontFamily={T.fontMono} fontSize={7} fill={T.blue} fontWeight="700">{defenseCount}</text>
        </g>
      )}

      {/* "TARGET" label for current attack target */}
      {isTarget && (
        <g transform="translate(0, -38)">
          <rect x={-20} y={-8} width={40} height={14} rx={3} fill={T.redBg} stroke={T.red} strokeWidth="0.8" />
          <text textAnchor="middle" y={2} fontFamily={T.fontMono} fontSize={7} fill={T.red}>TARGET</text>
        </g>
      )}

      {/* "DEFENDED" label */}
      {isDefended && !isTarget && (
        <g transform="translate(0, -38)">
          <rect x={-22} y={-8} width={44} height={14} rx={3} fill={T.greenBg} stroke={T.green} strokeWidth="0.8" />
          <text textAnchor="middle" y={2} fontFamily={T.fontMono} fontSize={7} fill={T.green}>HARDENED</text>
        </g>
      )}
    </g>
  );
}

/** Base node (Red/Blue HQ) */
function BaseNode({ x, y, label, sublabel, score, color, bg, Icon, glowColor, isLeft }) {
  return (
    <g transform={`translate(${x}, ${y})`}>
      {/* Base container */}
      <rect
        x={-44} y={-70} width={88} height={140} rx={8}
        fill={bg} stroke={color} strokeWidth={1}
        strokeDasharray="4 2" opacity={0.85}
        style={{ filter: `drop-shadow(0 0 12px ${glowColor})` }}
      />
      <text
        x={0} y={-52} textAnchor="middle"
        fontFamily={T.fontMono} fontSize={8} fill={color}
        letterSpacing="1" fontWeight="600"
      >
        {label}
      </text>

      {/* Agent node */}
      <circle r={26} cx={0} cy={0}
        fill={bg} stroke={color} strokeWidth={2.5}
        style={{ filter: `drop-shadow(0 0 10px ${glowColor})` }}
      />
      <foreignObject x={-10} y={-16} width={20} height={20} style={{ pointerEvents: "none" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", width: "100%", height: "100%" }}>
          <Icon size={16} color={color} strokeWidth={1.5} />
        </div>
      </foreignObject>
      <text y={12} textAnchor="middle" fontFamily={T.fontMono} fontSize={8} fill={color} fontWeight="600">{sublabel}</text>

      {/* Score badge */}
      <rect x={-24} y={34} width={48} height={18} rx={4} fill={`${color}18`} stroke={color} strokeWidth="0.8" />
      <text x={0} y={47} textAnchor="middle" fontFamily={T.fontMono} fontSize={9} fill={color} fontWeight="700">{score} pts</text>
    </g>
  );
}

/** Floating edge label (MITRE tag or defense type) */
function EdgeLabel({ x, y, text, color, bg }) {
  const len = text.length;
  const w = Math.max(len * 5.5 + 12, 50);
  return (
    <g transform={`translate(${x - w / 2}, ${y - 9})`}>
      <rect width={w} height={16} rx={3} fill={bg} stroke={color} strokeWidth="0.6" />
      <text x={w / 2} y={11} textAnchor="middle" fontFamily={T.fontMono} fontSize={8} fill={color}>{text}</text>
    </g>
  );
}

/** Node hover tooltip */
function NodeTooltip({ config, status, attackCount, defenseCount, x, y }) {
  const st = STATUS_STYLES[status] || STATUS_STYLES.normal;
  const lines = [
    `Zone: ${config.zone.toUpperCase()}`,
    `Ports: ${config.ports.join(", ") || "none"}`,
    `Status: ${st.label}`,
    `Attacks: ${attackCount}  Defenses: ${defenseCount}`,
    ...config.vulns.map((v) => `CVE: ${v}`),
  ];
  const w = 180, lineH = 14, padY = 10, padX = 10;
  const h = lines.length * lineH + padY * 2 + 18;
  const tx = x + 32;
  const ty = y - h / 2;

  return (
    <g transform={`translate(${tx}, ${ty})`} style={{ pointerEvents: "none" }}>
      <rect width={w} height={h} rx={6} fill={T.bgPanel} stroke={st.border} strokeWidth="1" opacity="0.97" />
      {/* Header */}
      <rect width={w} height={20} rx={6} fill={`${st.border}22`} />
      <rect width={w} height={4} y={16} fill={T.bgPanel} />
      <text x={padX} y={14} fontFamily={T.fontMono} fontSize={9} fill={st.border} fontWeight="700">{config.description.split(" · ")[0]}</text>
      {lines.map((ln, i) => (
        <text key={i} x={padX} y={padY + 22 + i * lineH} fontFamily={T.fontMono} fontSize={8}
          fill={ln.startsWith("CVE") ? T.amber : T.grayText}>
          {ln}
        </text>
      ))}
    </g>
  );
}

/** Toast notification */
function Toast({ text, color, visible }) {
  return (
    <div style={{
      position: "absolute", top: 12, left: "50%", transform: "translateX(-50%)",
      background: `${T.bgPanel}f0`, border: `1px solid ${color}`,
      borderRadius: 6, padding: "6px 14px", fontFamily: T.fontMono, fontSize: 11,
      color, pointerEvents: "none", whiteSpace: "nowrap",
      boxShadow: `0 0 12px ${color}44`,
      transition: "opacity 0.4s ease, transform 0.4s ease",
      opacity: visible ? 1 : 0,
      transform: `translateX(-50%) translateY(${visible ? 0 : -8}px)`,
      zIndex: 20,
    }}>
      {text}
    </div>
  );
}

// ─── MAIN COMPONENT ───────────────────────────────────────────────
/**
 * TopologyGraph
 *
 * @param {object}  props.roundData   – current RoundResult (or null → uses mock)
 * @param {Array}   props.allRounds   – all rounds array (for history)
 * @param {number}  props.currentIdx  – current round index
 * @param {function} props.onNodeClick – (nodeId) => void
 */
export default function TopologyGraph({
  roundData = MOCK_ROUND,
  allRounds = [MOCK_ROUND],
  currentIdx = 0,
  onNodeClick,
}) {
  const [hoveredNode, setHoveredNode] = useState(null);
  const [toastVisible, setToastVisible] = useState(false);
  const [toastText, setToastText]   = useState("");
  const [toastColor, setToastColor] = useState(T.red);
  const prevRound = useRef(null);

  const worldState  = roundData?.world_state ?? MOCK_WORLD_STATE;
  const redAction   = roundData?.red_action  ?? MOCK_ROUND.red_action;
  const blueAction  = roundData?.blue_action ?? MOCK_ROUND.blue_action;
  const judgeResult = roundData?.judge_result;

  // Show toast when round changes
  useEffect(() => {
    if (prevRound.current === roundData?.round) return;
    prevRound.current = roundData?.round;

    const tech   = redAction?.technique ?? "";
    const target = redAction?.target_node ?? "";
    const tid    = redAction?.technique_id ?? "";
    if (tech) {
      const success = judgeResult?.success;
      setToastText(`R${worldState.round}: ${tid} ${tech} → ${target} ${success ? "✓" : "✗"}`);
      setToastColor(success ? T.red : T.grayDim);
      setToastVisible(true);
      setTimeout(() => setToastVisible(false), 3000);
    }
  }, [roundData]);

  // Build historical compromised paths (edges that were attacked before current round)
  const historicalAttacks = new Set();
  allRounds.slice(0, currentIdx).forEach((r) => {
    if (r?.judge_result?.success && r?.red_action?.target_node) {
      historicalAttacks.add(r.red_action.target_node);
    }
  });

  // Node status lookups
  const nodeStatus   = (id) => getNodeStatus(worldState, id);
  const nodeData     = (id) => worldState.nodes?.find((n) => n.id === id) ?? {};
  const targetNodeId = redAction?.target_node;
  const defendNodeId = blueAction?.target;

  // Edge midpoint helper
  const mid = (id1, id2) => {
    const a = NODE_CONFIGS[id1], b = NODE_CONFIGS[id2];
    if (!a || !b) return { mx: 0, my: 0 };
    return { mx: (a.x + b.x) / 2, my: (a.y + b.y) / 2 };
  };

  // Find attack path: trace from red_base through firewall → target
  const attackPath = targetNodeId ? ["firewall", targetNodeId] : [];
  // For multi-hop, use a simple lookup
  const multiHopPath = {
    database:   ["firewall", "web_server", "app_server", "database"],
    app_server: ["firewall", "web_server", "app_server"],
    admin_host: ["firewall", "web_server", "app_server", "admin_host"],
    web_server: ["firewall", "web_server"],
    dns_server: ["firewall", "dns_server"],
    firewall:   ["firewall"],
  };
  const activePath = multiHopPath[targetNodeId] ?? attackPath;

  // Build active attack edges
  const attackEdges = [];
  for (let i = 0; i < activePath.length - 1; i++) {
    const a = NODE_CONFIGS[activePath[i]];
    const b = NODE_CONFIGS[activePath[i + 1]];
    if (a && b) attackEdges.push({ x1: a.x, y1: a.y, x2: b.x, y2: b.y, id: `${activePath[i]}-${activePath[i+1]}` });
  }

  // Defense edge: blue base → defended node
  const defEdge = defendNodeId && NODE_CONFIGS[defendNodeId]
    ? { x1: 710, y1: 190, x2: NODE_CONFIGS[defendNodeId].x, y2: NODE_CONFIGS[defendNodeId].y }
    : null;

  const score = worldState.score ?? { red: 0, blue: 0 };

  // Special event banner
  const specialEvent = worldState.special_event;

  return (
    <div style={{
      position: "relative",
      background: T.bg,
      borderRadius: 10,
      border: `1px solid ${T.border}`,
      overflow: "hidden",
      fontFamily: T.fontUI,
      userSelect: "none",
    }}>
      {/* ── CSS keyframes injected once ── */}
      <style>{`
        @keyframes cyberFlowEdge  { to { stroke-dashoffset: -18; } }
        @keyframes cyberFlowBlue  { to { stroke-dashoffset: -16; } }
        @keyframes cyberPulseRed  {
          0%,100% { filter: drop-shadow(0 0 6px rgba(239,68,68,.4)); }
          50%      { filter: drop-shadow(0 0 16px rgba(239,68,68,.9)); }
        }
        @keyframes cyberPulseAmber {
          0%,100% { filter: drop-shadow(0 0 4px rgba(245,158,11,.3)); }
          50%      { filter: drop-shadow(0 0 12px rgba(245,158,11,.8)); }
        }
        @keyframes cyberPulseGreen {
          0%,100% { filter: drop-shadow(0 0 4px rgba(34,197,94,.3)); }
          50%      { filter: drop-shadow(0 0 12px rgba(34,197,94,.7)); }
        }
        @keyframes cyberSpin {
          from { transform: rotate(0deg); }
          to   { transform: rotate(360deg); }
        }
        @keyframes cyberBlink {
          0%,100%{opacity:1} 50%{opacity:0.3}
        }
      `}</style>

      {/* ── Special event banner ── */}
      {specialEvent && (
        <div style={{
          position: "absolute", top: 0, left: 0, right: 0,
          background: `${T.amber}22`, borderBottom: `1px solid ${T.amber}`,
          padding: "5px 12px", display: "flex", alignItems: "center", gap: 8,
          zIndex: 15, fontFamily: T.fontMono, fontSize: 11,
        }}>
          <AlertTriangle size={12} color={T.amber} />
          <span style={{ color: T.amber, fontWeight: 600, animation: "cyberBlink 1s ease infinite" }}>
            {specialEvent === "zero_day" ? "⚡ ZERO-DAY EXPLOIT DETECTED — UNPATCHED VECTOR ACTIVE"
            : specialEvent === "ddos"    ? "⚡ DDoS SATURATION — BLUE AGENT ACTION POINTS HALVED"
            :                             "⚡ INTEL LEAK — RED AGENT HAS CURRENT DEFENSE BLUEPRINT"}
          </span>
        </div>
      )}

      {/* ── Toast notification ── */}
      <Toast text={toastText} color={toastColor} visible={toastVisible} />

      {/* ── SVG canvas ── */}
      <svg
        viewBox="0 0 800 380"
        width="100%" height="auto"
        style={{ display: "block" }}
        preserveAspectRatio="xMidYMid meet"
      >
        {/* ── Defs ── */}
        <defs>
          {/* Scanline texture */}
          <pattern id="scanlines" width="1" height="3" patternUnits="userSpaceOnUse">
            <line x1="0" y1="0" x2="1" y2="0" stroke="#ffffff" strokeWidth="0.4" opacity="0.015" />
          </pattern>

          {/* Arrow markers */}
          <marker id="arrow-red" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto">
            <path d="M1 1L9 5L1 9" fill="none" stroke={T.red} strokeWidth="1.5" />
          </marker>
          <marker id="arrow-blue" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto">
            <path d="M1 1L9 5L1 9" fill="none" stroke={T.blue} strokeWidth="1.5" />
          </marker>
          <marker id="arrow-gray" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto">
            <path d="M1 1L9 5L1 9" fill="none" stroke={T.gray} strokeWidth="1" />
          </marker>
        </defs>

        {/* Scanlines overlay */}
        <rect width="800" height="380" fill="url(#scanlines)" />

        {/* ── Zone backgrounds ── */}
        {Object.values(ZONE_CONFIGS).map((z) => (
          <g key={z.label}>
            <rect x={z.x} y={z.y} width={z.w} height={z.h} rx={6}
              fill={z.bg} stroke={z.color} strokeWidth="0.5" strokeDasharray="5 3" opacity={0.8} />
            <text x={z.x + z.w / 2} y={z.y + 14} textAnchor="middle"
              fontFamily={T.fontMono} fontSize={8} fill={z.color}
              letterSpacing="1.5" fontWeight="600" opacity={0.7}>
              {z.label}
            </text>
          </g>
        ))}

        {/* ── Static network edges ── */}
        {STATIC_EDGES.map((e) => {
          const a = NODE_CONFIGS[e.from], b = NODE_CONFIGS[e.to];
          if (!a || !b) return null;
          return (
            <line key={`${e.from}-${e.to}`}
              x1={a.x} y1={a.y} x2={b.x} y2={b.y}
              stroke={T.gray} strokeWidth="0.8" opacity="0.4"
            />
          );
        })}

        {/* ── Historical ghost attack paths ── */}
        {allRounds.slice(0, currentIdx).map((r, i) => {
          const src = r?.red_action?.target_node;
          if (!src || !r?.judge_result?.success) return null;
          const path = multiHopPath[src] ?? [];
          return path.slice(0, -1).map((nodeId, j) => {
            const a = NODE_CONFIGS[nodeId], b = NODE_CONFIGS[path[j + 1]];
            if (!a || !b) return null;
            return <GhostEdge key={`ghost-${i}-${j}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} />;
          });
        })}

        {/* Red base → firewall connector */}
        <line x1={90} y1={190} x2={144} y2={190}
          stroke={T.redDim} strokeWidth="1" strokeDasharray="4 3" opacity="0.5"
          markerEnd="url(#arrow-gray)" />

        {/* Blue base → database connector */}
        <line x1={656} y1={190} x2={614} y2={190}
          stroke={T.blueDim} strokeWidth="1" strokeDasharray="4 3" opacity="0.5"
          markerEnd="url(#arrow-gray)" />

        {/* ── Active attack edges (animated) ── */}
        {attackEdges.map((e) => (
          <AnimatedEdge key={e.id}
            x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2}
            color={T.red} dasharray="6 3" speed={0.38}
            markerId="arrow-red" opacity={0.9} />
        ))}

        {/* Attack edge label (MITRE tag) */}
        {attackEdges.length > 0 && redAction?.technique_id && (() => {
          const last = attackEdges[attackEdges.length - 1];
          return (
            <EdgeLabel
              x={(last.x1 + last.x2) / 2}
              y={(last.y1 + last.y2) / 2 - 16}
              text={`${redAction.technique_id} · ${redAction.technique?.split(" ")[0]}`}
              color={T.red} bg={T.redBg}
            />
          );
        })()}

        {/* ── Active defense edge (animated blue) ── */}
        {defEdge && (
          <>
            <AnimatedEdge
              x1={defEdge.x1} y1={defEdge.y1} x2={defEdge.x2} y2={defEdge.y2}
              color={T.blue} dasharray="7 3" speed={0.55}
              markerId="arrow-blue" opacity={0.85} />
            <EdgeLabel
              x={(defEdge.x1 + defEdge.x2) / 2}
              y={(defEdge.y1 + defEdge.y2) / 2 + 18}
              text={blueAction?.type?.replace("_", " ").toUpperCase() ?? "DEFENSE"}
              color={T.blue} bg={T.blueBg}
            />
          </>
        )}

        {/* ── Network nodes ── */}
        {Object.values(NODE_CONFIGS).map((cfg) => {
          const nd = nodeData(cfg.id);
          const st = nodeStatus(cfg.id);
          return (
            <TopologyNode
              key={cfg.id}
              config={cfg}
              status={st}
              attackCount={nd.attack_count ?? 0}
              defenseCount={nd.defense_count ?? 0}
              isTarget={cfg.id === targetNodeId}
              isDefended={cfg.id === defendNodeId && st === "defended"}
              onClick={() => onNodeClick?.(cfg.id)}
              hovered={hoveredNode === cfg.id}
              onHover={setHoveredNode}
            />
          );
        })}

        {/* ── Hovered node tooltip ── */}
        {hoveredNode && NODE_CONFIGS[hoveredNode] && (() => {
          const cfg = NODE_CONFIGS[hoveredNode];
          const nd  = nodeData(hoveredNode);
          const st  = nodeStatus(hoveredNode);
          // keep tooltip inside viewport
          const tipX = cfg.x > 580 ? cfg.x - 220 : cfg.x;
          return (
            <NodeTooltip
              config={cfg} status={st}
              attackCount={nd.attack_count ?? 0}
              defenseCount={nd.defense_count ?? 0}
              x={tipX} y={cfg.y}
            />
          );
        })()}

        {/* ── Red base ── */}
        <BaseNode
          x={50} y={190}
          label="RED BASE" sublabel="ATTACKER"
          score={score.red}
          color={T.red} bg={T.redBg}
          glowColor={T.redGlow}
          Icon={Terminal}
          isLeft
        />

        {/* ── Blue base ── */}
        <BaseNode
          x={750} y={190}
          label="BLUE BASE" sublabel="DEFENDER"
          score={score.blue}
          color={T.blue} bg={T.blueBg}
          glowColor={T.blueGlow}
          Icon={Shield}
          isLeft={false}
        />

        {/* ── Round / phase badge ── */}
        <g transform="translate(400, 6)">
          <rect x={-60} y={0} width={120} height={18} rx={4}
            fill={T.bgPanel} stroke={T.border} strokeWidth="0.5" />
          <text x={0} y={12} textAnchor="middle"
            fontFamily={T.fontMono} fontSize={8} fill={T.grayText} letterSpacing="1">
            ROUND {worldState.round} / 20 · {worldState.red_phase?.toUpperCase()}
          </text>
        </g>

        {/* ── Availability meter (bottom) ── */}
        <g transform="translate(280, 368)">
          <text fontFamily={T.fontMono} fontSize={7} fill={T.grayDim} x={0} y={0}>AVAILABILITY</text>
          <rect x={70} y={-8} width={120} height={8} rx={2} fill={T.bgPanel} stroke={T.border} strokeWidth="0.5" />
          <rect x={70} y={-8} width={120 * (worldState.availability ?? 1)} height={8} rx={2} fill={T.green} opacity="0.7" />
          <text fontFamily={T.fontMono} fontSize={7} fill={T.green} x={196} y={0}>
            {Math.round((worldState.availability ?? 1) * 100)}%
          </text>
        </g>

        {/* ── Legend (bottom right) ── */}
        <g transform="translate(488, 355)">
          {[
            { color: T.red,   dash: true,  label: "Attack path"  },
            { color: T.blue,  dash: false, label: "Defense"      },
            { color: T.gray,  dash: false, label: "Network link" },
          ].map((lg, i) => (
            <g key={i} transform={`translate(${i * 96}, 0)`}>
              <line x1={0} y1={7} x2={22} y2={7}
                stroke={lg.color} strokeWidth={1.2}
                strokeDasharray={lg.dash ? "4 2" : "none"} opacity="0.8" />
              <text x={26} y={11} fontFamily={T.fontMono} fontSize={7} fill={T.grayDim}>{lg.label}</text>
            </g>
          ))}
        </g>
      </svg>

      {/* ── Phase progress bar (below SVG) ── */}
      <div style={{
        display: "flex", alignItems: "center", gap: 6,
        padding: "6px 14px",
        borderTop: `1px solid ${T.border}`,
        background: T.bgPanel,
      }}>
        {["Recon", "Weaponize", "Exploit", "LateralMove", "Exfiltrate"].map((phase) => {
          const phases = ["Recon", "Weaponize", "Exploit", "LateralMove", "Exfiltrate"];
          const current = phases.indexOf(worldState.red_phase ?? "Recon");
          const idx     = phases.indexOf(phase);
          const done    = idx < current;
          const active  = idx === current;
          return (
            <React.Fragment key={phase}>
              <div style={{
                flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 2,
              }}>
                <div style={{
                  height: 3, width: "100%", borderRadius: 2,
                  background: done ? T.red : active ? T.amber : T.border,
                  boxShadow: active ? `0 0 6px ${T.amber}` : "none",
                  transition: "background 0.5s ease",
                }} />
                <span style={{
                  fontFamily: T.fontMono, fontSize: 8,
                  color: done ? T.red : active ? T.amber : T.grayDim,
                  fontWeight: active ? 700 : 400,
                }}>
                  {phase}
                </span>
              </div>
              {idx < 4 && (
                <span style={{ color: T.border, fontSize: 10, marginBottom: 12 }}>›</span>
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}
