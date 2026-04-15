import { useState, useEffect, useRef } from "react";

// ─── Static "hardcoded" snapshot (swap with backend JSON) ───────────────────
const INITIAL_STATE = {
  round: 7,
  totalRounds: 20,
  redScore: 42,
  blueScore: 68,
  nodes: [
    // INTERNET zone
    { id: "attacker", label: "ATTACKER", type: "red_agent",  zone: "internet",  x: 112, y: 230, status: "compromised", port: null },
    { id: "fw",       label: "FW",       type: "firewall",   zone: "internet",  x: 230, y: 230, status: "normal",      port: ":firewall" },
    // DMZ zone
    { id: "web",      label: "WEB",      type: "web_server", zone: "dmz",       x: 370, y: 180, status: "compromised", port: null },
    { id: "dns",      label: "DNS",      type: "dns_server", zone: "dmz",       x: 370, y: 310, status: "normal",      port: ":53" },
    // INTERNAL zone
    { id: "app",      label: "APP",      type: "app_server", zone: "internal",  x: 510, y: 230, status: "defended",    port: null },
    // DATABASE zone
    { id: "db",       label: "DB",       type: "database",   zone: "database",  x: 650, y: 195, status: "compromised", port: null },
    { id: "adm",      label: "ADM",      type: "admin_host", zone: "database",  x: 650, y: 310, status: "normal",      port: ":ss" },
    // BLUE BASE
    { id: "defender", label: "DEFENDER", type: "blue_agent", zone: "blue_base", x: 820, y: 230, status: "defended",    port: null },
  ],
  edges: [
    // attack path (dashed red)
    { id: "e1", from: "attacker", to: "fw",      type: "attack", label: "T1190 • SQLi" },
    { id: "e2", from: "fw",       to: "web",     type: "attack", label: null },
    { id: "e3", from: "fw",       to: "dns",     type: "attack", label: null },
    { id: "e4", from: "web",      to: "app",     type: "attack", label: null },
    { id: "e5", from: "app",      to: "db",      type: "attack", label: null },
    // defense actions (dashed blue)
    { id: "e6", from: "defender", to: "db",      type: "defense", label: "DROP :3306" },
    // normal network links
    { id: "e7", from: "fw",       to: "web",     type: "network", label: null },
    { id: "e8", from: "fw",       to: "dns",     type: "network", label: null },
  ],
};

// ─── Node type → icon SVG path ───────────────────────────────────────────────
const NODE_ICONS = {
  web_server:  <><rect x="-10" y="-12" width="20" height="14" rx="2" strokeWidth="1.5" fill="none"/><line x1="-10" y1="-2" x2="10" y2="-2" strokeWidth="1"/><circle cx="0" cy="7" r="3" strokeWidth="1.5" fill="none"/><line x1="-4" y1="10" x2="4" y2="10" strokeWidth="1.5"/></>,
  database:    <><ellipse cx="0" cy="-8" rx="9" ry="4" strokeWidth="1.5" fill="none"/><line x1="-9" y1="-8" x2="-9" y2="8" strokeWidth="1.5"/><line x1="9" y1="-8" x2="9" y2="8" strokeWidth="1.5"/><ellipse cx="0" cy="8" rx="9" ry="4" strokeWidth="1.5" fill="none"/><path d="M-9,0 Q0,4 9,0" strokeWidth="1" fill="none"/></>,
  app_server:  <><rect x="-10" y="-10" width="20" height="20" rx="2" strokeWidth="1.5" fill="none"/><line x1="-6" y1="-4" x2="0" y2="-4" strokeWidth="1.5"/><line x1="-6" y1="0" x2="4" y2="0" strokeWidth="1.5"/><line x1="-6" y1="4" x2="2" y2="4" strokeWidth="1.5"/></>,
  dns_server:  <><rect x="-9" y="-9" width="18" height="18" rx="3" strokeWidth="1.5" fill="none"/><line x1="-5" y1="-3" x2="5" y2="-3" strokeWidth="1.5"/><line x1="-5" y1="2" x2="5" y2="2" strokeWidth="1.5"/><line x1="-5" y1="7" x2="2" y2="7" strokeWidth="1.2"/></>,
  firewall:    <><path d="M0,-13 L12,0 L0,13 L-12,0 Z" strokeWidth="1.5" fill="none"/><path d="M-4,-4 L0,0 L-4,4 M0,-4 L4,0 L0,4" strokeWidth="1.2" fill="none"/></>,
  admin_host:  <><rect x="-9" y="-12" width="18" height="14" rx="2" strokeWidth="1.5" fill="none"/><line x1="-5" y1="2" x2="5" y2="2" strokeWidth="1.5"/><line x1="-3" y1="5" x2="3" y2="5" strokeWidth="1.2"/><line x1="-7" y1="8" x2="7" y2="8" strokeWidth="1.5"/></>,
  red_agent:   <><line x1="-9" y1="-9" x2="9" y2="9" strokeWidth="2"/><line x1="9" y1="-9" x2="-9" y2="9" strokeWidth="2"/></>,
  blue_agent:  <><path d="M0,-12 L10,0 L6,8 L-6,8 L-10,0 Z" strokeWidth="1.5" fill="none"/><circle cx="0" cy="1" r="3" strokeWidth="1.2" fill="none"/></>,
};

// ─── Status ring colours ──────────────────────────────────────────────────────
const STATUS_STYLE = {
  normal:      { ring: "#3B82F6", fill: "#1e3a5f", dot: "#22c55e",  label: "Normal" },
  scanning:    { ring: "#F59E0B", fill: "#3d2c0a", dot: "#F59E0B",  label: "Scanning" },
  compromised: { ring: "#EF4444", fill: "#3d0a0a", dot: "#EF4444",  label: "Compromised" },
  defended:    { ring: "#22c55e", fill: "#0a2d0f", dot: "#22c55e",  label: "Defended" },
};

// ─── Zone layout config ───────────────────────────────────────────────────────
const ZONES = [
  { id: "internet",  label: "INTERNET",  x: 30,  w: 200, color: "#1a1a2e", border: "#3B82F6" },
  { id: "dmz",       label: "DMZ",       x: 250, w: 160, color: "#1a2e1a", border: "#22c55e" },
  { id: "internal",  label: "INTERNAL",  x: 430, w: 160, color: "#1a2a1a", border: "#22c55e" },
  { id: "database",  label: "DATABASE",  x: 610, w: 180, color: "#2e1a1a", border: "#7c3aed" },
];

// ─── Animated dashed edge component ──────────────────────────────────────────
function AnimatedEdge({ from, to, type, label, nodes, tick }) {
  const n1 = nodes.find(n => n.id === from);
  const n2 = nodes.find(n => n.id === to);
  if (!n1 || !n2) return null;

  const dx = n2.x - n1.x;
  const dy = n2.y - n1.y;
  const len = Math.sqrt(dx * dx + dy * dy);
  const nx = dx / len, ny = dy / len;
  const r = 22;
  const x1 = n1.x + nx * r, y1 = n1.y + ny * r;
  const x2 = n2.x - nx * r, y2 = n2.y - ny * r;
  const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;

  const isAttack  = type === "attack";
  const isDefense = type === "defense";
  const isNetwork = type === "network";

  const strokeColor = isAttack ? "#EF4444" : isDefense ? "#3B82F6" : "#4b5563";
  const dashArray   = isAttack ? "6 4" : isDefense ? "6 4" : "4 4";
  const dashOffset  = isAttack ? -(tick * 0.5) % 20 : isDefense ? (tick * 0.4) % 20 : 0;
  const strokeW     = isNetwork ? 1 : 1.5;
  const opacity     = isNetwork ? 0.3 : 0.85;
  const markerColor = isAttack ? "red" : isDefense ? "blue" : "gray";

  return (
    <g>
      <defs>
        <marker id={`arrow-${type}-${from}-${to}`} viewBox="0 0 10 10" refX="8" refY="5"
          markerWidth="5" markerHeight="5" orient="auto-start-reverse">
          <path d="M2 2L8 5L2 8" fill="none" stroke={strokeColor} strokeWidth="1.5"
            strokeLinecap="round" strokeLinejoin="round"/>
        </marker>
      </defs>
      <line
        x1={x1} y1={y1} x2={x2} y2={y2}
        stroke={strokeColor}
        strokeWidth={strokeW}
        strokeDasharray={dashArray}
        strokeDashoffset={dashOffset}
        opacity={opacity}
        markerEnd={`url(#arrow-${type}-${from}-${to})`}
      />
      {label && (
        <g>
          <rect x={mx - label.length * 3.5} y={my - 10} width={label.length * 7 + 4} height={15}
            rx="3" fill="#0f172a" fillOpacity="0.9" stroke={strokeColor} strokeWidth="0.5"/>
          <text x={mx} y={my + 1} textAnchor="middle" dominantBaseline="central"
            fontSize="8" fill={strokeColor} fontFamily="monospace" fontWeight="600">
            {label}
          </text>
        </g>
      )}
    </g>
  );
}

// ─── Single node component ────────────────────────────────────────────────────
function NetworkNode({ node, selected, onClick, pulse }) {
  const s = STATUS_STYLE[node.status] || STATUS_STYLE.normal;
  const isRed  = node.type === "red_agent";
  const isBlue = node.type === "blue_agent";
  const specialFill = isRed ? "#3d0a0a" : isBlue ? "#0a1f3d" : s.fill;
  const specialRing = isRed ? "#EF4444" : isBlue ? "#3B82F6" : s.ring;
  const ringW = selected ? 2.5 : 1.5;
  const r = 22;

  // pulse animation: glowing outer ring for compromised/scanning
  const shouldPulse = (node.status === "compromised" || node.status === "scanning") && pulse;
  const pulseR = r + 8 + Math.sin(pulse * 0.15) * 4;
  const pulseOpacity = 0.15 + Math.sin(pulse * 0.15) * 0.1;

  return (
    <g
      transform={`translate(${node.x}, ${node.y})`}
      onClick={() => onClick(node)}
      style={{ cursor: "pointer" }}
    >
      {shouldPulse && (
        <circle r={pulseR} fill={specialRing} opacity={pulseOpacity} />
      )}
      {/* outer ring */}
      <circle r={r} fill={specialFill} stroke={specialRing} strokeWidth={ringW} />
      {/* icon */}
      <g stroke={specialRing} fill="none" strokeLinecap="round">
        {NODE_ICONS[node.type] || <circle r="8" strokeWidth="1.5"/>}
      </g>
      {/* status dot */}
      <circle cx={r - 4} cy={-(r - 4)} r={4} fill={s.dot} stroke="#0f172a" strokeWidth="1"/>
      {/* label below */}
      <text y={r + 12} textAnchor="middle" fontSize="9" fill="#e2e8f0"
        fontFamily="monospace" fontWeight="700" letterSpacing="0.5">
        {node.label}
      </text>
      {node.port && (
        <text y={r + 22} textAnchor="middle" fontSize="8" fill="#94a3b8" fontFamily="monospace">
          {node.port}
        </text>
      )}
      {/* status badge */}
      {node.status !== "normal" && (
        <text y={-(r + 7)} textAnchor="middle" fontSize="7" fill={s.ring}
          fontFamily="monospace" fontWeight="600" letterSpacing="0.3">
          {node.status.toUpperCase()}
        </text>
      )}
    </g>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────
export default function NetworkTopology() {
  const [state, setState] = useState(INITIAL_STATE);
  const [selected, setSelected] = useState(null);
  const [tick, setTick] = useState(0);
  const animRef = useRef(null);

  useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), 50);
    return () => clearInterval(id);
  }, []);

  const SVG_W = 960;
  const SVG_H = 440;
  const ZONE_H = 380;
  const ZONE_Y = 30;

  const selectedNode = selected ? state.nodes.find(n => n.id === selected) : null;

  // ── load replay frame from outside: window.loadFrame(json) ──────────────────
  useEffect(() => {
    window.loadFrame = (json) => setState(json);
    return () => { delete window.loadFrame; };
  }, []);

  return (
    <div style={{
      background: "#0a0f1e",
      borderRadius: "12px",
      padding: "0",
      fontFamily: "monospace",
      userSelect: "none",
      border: "1px solid #1e293b",
      overflow: "hidden",
    }}>
      {/* ── Header bar ────────────────────────────────────────────────────── */}
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "10px 18px", background: "#060b18",
        borderBottom: "1px solid #1e293b",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          {/* Red team */}
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{
              width: 10, height: 10, borderRadius: "50%",
              background: "#EF4444", boxShadow: "0 0 6px #EF4444"
            }}/>
            <span style={{ color: "#EF4444", fontSize: 11, letterSpacing: 1 }}>RED TEAM</span>
            <span style={{
              background: "#3d0a0a", color: "#EF4444", borderRadius: 4,
              padding: "2px 8px", fontSize: 12, fontWeight: 700,
              border: "1px solid #EF4444"
            }}>{state.redScore} pts</span>
          </div>
          {/* Round indicator */}
          <div style={{
            background: "#1e293b", border: "1px solid #334155",
            borderRadius: 6, padding: "3px 14px",
            color: "#94a3b8", fontSize: 11, letterSpacing: 2,
          }}>
            ROUND {state.round} / {state.totalRounds}
          </div>
          {/* Blue team */}
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{
              background: "#0a1f3d", color: "#3B82F6", borderRadius: 4,
              padding: "2px 8px", fontSize: 12, fontWeight: 700,
              border: "1px solid #3B82F6"
            }}>{state.blueScore} pts</span>
            <span style={{ color: "#3B82F6", fontSize: 11, letterSpacing: 1 }}>BLUE TEAM</span>
            <div style={{
              width: 10, height: 10, borderRadius: "50%",
              background: "#3B82F6", boxShadow: "0 0 6px #3B82F6"
            }}/>
          </div>
        </div>
        {/* Round progress bar */}
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{
            width: 140, height: 4, background: "#1e293b",
            borderRadius: 2, overflow: "hidden",
          }}>
            <div style={{
              width: `${(state.round / state.totalRounds) * 100}%`,
              height: "100%",
              background: "linear-gradient(90deg, #EF4444 0%, #7c3aed 50%, #3B82F6 100%)",
              borderRadius: 2,
            }}/>
          </div>
          <span style={{ color: "#475569", fontSize: 10 }}>
            {Math.round((state.round / state.totalRounds) * 100)}%
          </span>
        </div>
      </div>

      {/* ── SVG topology ──────────────────────────────────────────────────── */}
      <div style={{ position: "relative" }}>
        <svg
          width="100%"
          viewBox={`0 0 ${SVG_W} ${SVG_H}`}
          style={{ display: "block" }}
        >
          {/* Zone background panels */}
          {ZONES.map(z => (
            <g key={z.id}>
              <rect
                x={z.x} y={ZONE_Y} width={z.w} height={ZONE_H}
                rx="8" fill={z.color} fillOpacity="0.6"
                stroke={z.border} strokeWidth="1" strokeOpacity="0.25"
                strokeDasharray="4 4"
              />
              <text x={z.x + z.w / 2} y={ZONE_Y + 18} textAnchor="middle"
                fontSize="9" fill={z.border} fontFamily="monospace"
                letterSpacing="2" fontWeight="600" opacity="0.7">
                {z.label}
              </text>
            </g>
          ))}

          {/* Red base box */}
          <rect x={32} y={ZONE_Y + 10} width={92} height={ZONE_H - 20}
            rx="6" fill="none" stroke="#EF4444" strokeWidth="1"
            strokeDasharray="4 3" strokeOpacity="0.6"/>
          <text x={78} y={ZONE_Y + 25} textAnchor="middle" fontSize="8"
            fill="#EF4444" fontFamily="monospace" letterSpacing="1">RED BASE</text>
          <text x={78} y={ZONE_Y + ZONE_H - 18} textAnchor="middle" fontSize="10"
            fill="#EF4444" fontFamily="monospace" fontWeight="700">
            {state.redScore} pts
          </text>

          {/* Blue base box */}
          <rect x={806} y={ZONE_Y + 10} width={100} height={ZONE_H - 20}
            rx="6" fill="none" stroke="#3B82F6" strokeWidth="1"
            strokeDasharray="4 3" strokeOpacity="0.6"/>
          <text x={856} y={ZONE_Y + 25} textAnchor="middle" fontSize="8"
            fill="#3B82F6" fontFamily="monospace" letterSpacing="1">BLUE BASE</text>
          <text x={856} y={ZONE_Y + ZONE_H - 18} textAnchor="middle" fontSize="10"
            fill="#3B82F6" fontFamily="monospace" fontWeight="700">
            {state.blueScore} pts
          </text>

          {/* Edges (drawn before nodes so nodes appear on top) */}
          {state.edges.map(e => (
            <AnimatedEdge
              key={e.id}
              from={e.from} to={e.to}
              type={e.type}
              label={e.label}
              nodes={state.nodes}
              tick={tick}
            />
          ))}

          {/* Nodes */}
          {state.nodes.map(n => (
            <NetworkNode
              key={n.id}
              node={n}
              selected={selected === n.id}
              onClick={(node) => setSelected(selected === node.id ? null : node.id)}
              pulse={tick}
            />
          ))}
        </svg>
      </div>

      {/* ── Legend bar ────────────────────────────────────────────────────── */}
      <div style={{
        display: "flex", alignItems: "center", flexWrap: "wrap",
        gap: "14px 20px", padding: "8px 18px",
        borderTop: "1px solid #1e293b", background: "#060b18",
      }}>
        {[
          { color: "#22c55e",  label: "正常运行" },
          { color: "#F59E0B",  label: "被扫描/侦察" },
          { color: "#EF4444",  label: "已被攻破" },
          { color: "#3B82F6",  label: "防御加固" },
        ].map(item => (
          <div key={item.label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: item.color }}/>
            <span style={{ color: "#94a3b8", fontSize: 10 }}>{item.label}</span>
          </div>
        ))}
        <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <svg width="30" height="10"><line x1="0" y1="5" x2="30" y2="5"
            stroke="#EF4444" strokeWidth="1.5" strokeDasharray="4 3"/></svg>
          <span style={{ color: "#94a3b8", fontSize: 10 }}>攻击路径</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <svg width="30" height="10"><line x1="0" y1="5" x2="30" y2="5"
            stroke="#3B82F6" strokeWidth="1.5" strokeDasharray="4 3"/></svg>
          <span style={{ color: "#94a3b8", fontSize: 10 }}>防御加固</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <svg width="30" height="10"><line x1="0" y1="5" x2="30" y2="5"
            stroke="#4b5563" strokeWidth="1" strokeDasharray="3 3"/></svg>
          <span style={{ color: "#94a3b8", fontSize: 10 }}>网络连接</span>
        </div>
      </div>

      {/* ── Selected node detail panel ─────────────────────────────────────── */}
      {selectedNode && (
        <div style={{
          margin: "0 18px 14px", padding: "10px 14px",
          background: "#0f172a", borderRadius: 8,
          border: `1px solid ${STATUS_STYLE[selectedNode.status].ring}`,
          display: "flex", alignItems: "flex-start", gap: 20,
        }}>
          <div>
            <div style={{ color: "#e2e8f0", fontSize: 13, fontWeight: 700, marginBottom: 4 }}>
              {selectedNode.label}
              <span style={{
                marginLeft: 8, fontSize: 10, fontWeight: 600,
                color: STATUS_STYLE[selectedNode.status].ring,
                background: "#1e293b", padding: "2px 7px", borderRadius: 4,
              }}>
                {STATUS_STYLE[selectedNode.status].label.toUpperCase()}
              </span>
            </div>
            <div style={{ color: "#64748b", fontSize: 10, marginBottom: 2 }}>
              TYPE: {selectedNode.type.replace("_", " ").toUpperCase()}
            </div>
            <div style={{ color: "#64748b", fontSize: 10, marginBottom: 2 }}>
              ZONE: {selectedNode.zone.toUpperCase()}
            </div>
            {selectedNode.port && (
              <div style={{ color: "#64748b", fontSize: 10 }}>
                PORT: <span style={{ color: "#94a3b8" }}>{selectedNode.port}</span>
              </div>
            )}
          </div>
          <div style={{ marginLeft: "auto" }}>
            <button
              onClick={() => setSelected(null)}
              style={{
                background: "none", border: "1px solid #334155",
                borderRadius: 4, color: "#94a3b8", cursor: "pointer",
                padding: "3px 10px", fontSize: 10,
              }}
            >✕ 关闭</button>
          </div>
        </div>
      )}

      {/* ── Usage hint for developer ──────────────────────────────────────── */}
      <div style={{
        padding: "6px 18px 10px", color: "#334155", fontSize: 9, letterSpacing: 0.5
      }}>
        DEV: 调用 <code style={{ color: "#475569" }}>window.loadFrame(json)</code> 加载后端帧数据进行回放
      </div>
    </div>
  );
}
