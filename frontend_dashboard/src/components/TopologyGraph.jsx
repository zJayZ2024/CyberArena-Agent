import React, { useEffect, useRef, useState } from "react";

const PAGE_STYLES = `
  @import url("https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600&display=swap");
  .topology-page { max-width: 920px; margin: 0 auto; min-height: 100vh; padding: 20px; }
  .page-title { font-family: 'JetBrains Mono', monospace; font-size: 11px; letter-spacing: 2px; color: #4b5563; margin-bottom: 12px; text-transform: uppercase; }
  .controls { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
  .ctrl-btn { font-family: 'JetBrains Mono', monospace; font-size: 10px; padding: 5px 12px; border-radius: 4px; cursor: pointer; background: #111827; border: 1px solid #1f2937; color: #9ca3af; transition: all 0.15s; }
  .ctrl-btn:hover:not(:disabled) { border-color: #3b82f6; color: #3b82f6; }
  .ctrl-btn.active { background: #0d1f3c; border-color: #3b82f6; color: #3b82f6; }
  .ctrl-btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .info-row { display: flex; gap: 12px; margin-top: 10px; flex-wrap: wrap; }
  .info-chip { font-family: 'JetBrains Mono', monospace; font-size: 10px; padding: 4px 10px; border-radius: 20px; background: #111827; border: 0.5px solid #1f2937; color: #6b7280; }
`;

// 鈹€鈹€鈹€ DESIGN TOKENS 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
const T = {
  bg: "#07090f", bgPanel: "#0d1117", bgNode: "#111827", border: "#1f2937",
  red: "#ef4444", redDim: "#7f1d1d", redBg: "#1a0a0a", redGlow: "rgba(239,68,68,0.55)",
  blue: "#3b82f6", blueDim: "#1e3a5f", blueBg: "#080f1c", blueGlow: "rgba(59,130,246,0.55)",
  green: "#22c55e", greenBg: "#071510", greenGlow: "rgba(34,197,94,0.45)",
  amber: "#f59e0b", amberBg: "#1a1000",
  gray: "#374151", grayMid: "#4b5563", grayText: "#9ca3af", grayDim: "#6b7280",
  fontMono: "'JetBrains Mono', monospace",
};

const ZONE_CONFIGS = {
  internet: { label:"INTERNET", x:110, y:15, w:120, h:350, color:T.gray,  bg:"rgba(55,65,81,0.06)"   },
  dmz:      { label:"DMZ",      x:250, y:15, w:120, h:350, color:T.blue,  bg:"rgba(59,130,246,0.05)" },
  internal: { label:"INTERNAL", x:390, y:15, w:120, h:350, color:T.green, bg:"rgba(34,197,94,0.05)"  },
  database: { label:"DATABASE", x:530, y:15, w:120, h:350, color:T.amber, bg:"rgba(245,158,11,0.05)" },
};

const NODE_CONFIGS = {
  web_server: { id:"web_server", label:"WEB",  sublabel:":80/443",  zone:"dmz",      x:310, y:120, ports:[80,443],       vulns:["SQLi-login","CVE-2021-44228"], description:"Nginx 1.18 · PHP 7.4 · DMZ exposed" },
  dns_server: { id:"dns_server", label:"DNS",  sublabel:":53",      zone:"dmz",      x:310, y:250, ports:[53],           vulns:["DNS-cache-poison"],            description:"BIND 9.16 · DMZ resolver"          },
  app_server: { id:"app_server", label:"APP",  sublabel:":8080",    zone:"internal", x:450, y:120, ports:[8080,8443],    vulns:["CVE-2023-1234"],               description:"Tomcat 10 · Internal app tier"     },
  admin_host: { id:"admin_host", label:"ADM",  sublabel:":22",      zone:"internal", x:450, y:250, ports:[22,3389],      vulns:["Weak-SSH-key"],                description:"Admin workstation · Jump host"     },
  database:   { id:"database",   label:"DB",   sublabel:":3306",    zone:"database", x:590, y:190, ports:[3306,5432],    vulns:["SQLi-stored","Unpatched-MySQL"],description:"MySQL 8.0 · FINAL TARGET"          },
  firewall:   { id:"firewall",   label:"FW",   sublabel:"gateway",  zone:"internet", x:170, y:190, ports:[],             vulns:[],                              description:"pfSense 2.7 · Internet gateway"    },
};

const STATIC_EDGES = [
  ["firewall","web_server"],["firewall","dns_server"],
  ["web_server","app_server"],["dns_server","app_server"],
  ["app_server","database"],["app_server","admin_host"],["admin_host","database"],
];

const STATUS_STYLES = {
  normal:      { border:T.blue,  bg:T.bgNode,  glow:"none",                            dot:T.green, label:"ONLINE"      },
  scanning:    { border:T.amber, bg:T.amberBg, glow:`0 0 10px rgba(245,158,11,.55)`,   dot:T.amber, label:"SCANNING"    },
  compromised: { border:T.red,   bg:T.redBg,   glow:`0 0 14px rgba(239,68,68,.7)`,     dot:T.red,   label:"COMPROMISED" },
  defended:    { border:T.green, bg:T.greenBg, glow:`0 0 10px rgba(34,197,94,.55)`,    dot:T.green, label:"HARDENED"    },
};

const MULTI_HOP = {
  database:   ["firewall","web_server","app_server","database"],
  app_server: ["firewall","web_server","app_server"],
  admin_host: ["firewall","web_server","app_server","admin_host"],
  web_server: ["firewall","web_server"],
  dns_server: ["firewall","dns_server"],
  firewall:   ["firewall"],
};

// 鈹€鈹€鈹€ SIMULATION ROUNDS 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
const SIM_ROUNDS = [
  {
    round:1, red_action:{technique:"Port Scan",target_node:"firewall",technique_id:"T1046",reasoning:"Initial recon -map open ports on internet-facing gateway before selecting attack vector."},
    judge_result:{success:true,damage:5,logs:["[WARN] Port scan detected: 254 probes/3s","[INFO] Open: 80, 443, 22, 53"],node_status_change:"scanning",success_prob:0.9},
    blue_action:{type:"ids_update",target:"firewall",rule_or_code:"alert tcp any -> $HOME_NET any (msg:\"PortScan\"; detection_filter:track by_src,count 100,seconds 3;)",action_cost:2,effectiveness:0.6,reasoning:"IDS signature update to track scan pattern."},
    world_state:{round:1,nodes:[
      {id:"web_server",status:"normal",attack_count:0,defense_count:0},{id:"dns_server",status:"normal",attack_count:0,defense_count:0},
      {id:"app_server",status:"normal",attack_count:0,defense_count:0},{id:"admin_host",status:"normal",attack_count:0,defense_count:0},
      {id:"database",status:"normal",attack_count:0,defense_count:0},{id:"firewall",status:"scanning",attack_count:1,defense_count:0},
    ],score:{red:5,blue:8},red_phase:"Recon",availability:1.0,blue_action_points:1,special_event:null},
  },
  {
    round:2, red_action:{technique:"SQL Injection",target_node:"web_server",technique_id:"T1190",reasoning:"Port 80 is open. Attempt SQLi on login endpoint -highest yield given patch_level 0.5."},
    judge_result:{success:true,damage:20,logs:["[CRIT] SQLi on /api/login","[WARN] Unusual DB queries from WEB_SERVER"],node_status_change:"compromised",success_prob:0.72},
    blue_action:{type:"firewall_rule",target:"web_server",rule_or_code:"iptables -A INPUT -p tcp --dport 80 -m limit --limit 30/min -j ACCEPT\n# Rate-limit HTTP",action_cost:1,effectiveness:0.55,reasoning:"Deploy HTTP rate-limit to slow injection attempts."},
    world_state:{round:2,nodes:[
      {id:"web_server",status:"compromised",attack_count:1,defense_count:1},{id:"dns_server",status:"normal",attack_count:0,defense_count:0},
      {id:"app_server",status:"normal",attack_count:0,defense_count:0},{id:"admin_host",status:"normal",attack_count:0,defense_count:0},
      {id:"database",status:"normal",attack_count:0,defense_count:0},{id:"firewall",status:"scanning",attack_count:1,defense_count:0},
    ],score:{red:25,blue:16},red_phase:"Exploit",availability:0.96,blue_action_points:2,special_event:null},
  },
  {
    round:3, red_action:{technique:"Lateral Movement",target_node:"app_server",technique_id:"T1021",reasoning:"Web server compromised. Pivot to app_server using stored credentials found in /var/www/config."},
    judge_result:{success:false,damage:0,logs:["[INFO] Lateral move attempt blocked","[OK] WAF rule matched -connection dropped"],node_status_change:null,success_prob:0.38},
    blue_action:{type:"patch",target:"app_server",rule_or_code:"# Emergency patch applied\napt-get install --only-upgrade tomcat10\n# CVE-2023-1234 remediated",action_cost:3,effectiveness:0.9,reasoning:"App_server is likely next pivot target. Apply emergency patch while attack is still on web_server."},
    world_state:{round:3,nodes:[
      {id:"web_server",status:"compromised",attack_count:1,defense_count:1},{id:"dns_server",status:"normal",attack_count:0,defense_count:0},
      {id:"app_server",status:"defended",attack_count:1,defense_count:1},{id:"admin_host",status:"normal",attack_count:0,defense_count:0},
      {id:"database",status:"normal",attack_count:0,defense_count:0},{id:"firewall",status:"scanning",attack_count:1,defense_count:0},
    ],score:{red:25,blue:42},red_phase:"LateralMove",availability:0.91,blue_action_points:0,special_event:null},
  },
  {
    round:4, red_action:{technique:"Credential Dump",target_node:"admin_host",technique_id:"T1003",reasoning:"App_server patched. Try admin_host via SSH using credentials cached in web_server memory."},
    judge_result:{success:true,damage:15,logs:["[CRIT] Unauthorized SSH login to ADMIN_HOST","[WARN] sudo commands executed","[INFO] /etc/shadow accessed"],node_status_change:"compromised",success_prob:0.61},
    blue_action:{type:"ids_update",target:"database",rule_or_code:"alert tcp $INTERNAL_NET any -> $DB_SERVERS 3306 (msg:\"Suspicious DB Access\"; threshold:type both,track by_src,count 5,seconds 60;)",action_cost:2,effectiveness:0.75,reasoning:"Admin_host compromised -DB is now reachable. Pre-emptive IDS rule on DB port 3306."},
    world_state:{round:4,nodes:[
      {id:"web_server",status:"compromised",attack_count:1,defense_count:1},{id:"dns_server",status:"normal",attack_count:0,defense_count:0},
      {id:"app_server",status:"defended",attack_count:1,defense_count:1},{id:"admin_host",status:"compromised",attack_count:1,defense_count:0},
      {id:"database",status:"normal",attack_count:0,defense_count:1},{id:"firewall",status:"scanning",attack_count:1,defense_count:0},
    ],score:{red:40,blue:52},red_phase:"LateralMove",availability:0.88,blue_action_points:1,special_event:null},
  },
  {
    round:5, red_action:{technique:"Data Exfiltration",target_node:"database",technique_id:"T1041",reasoning:"Full path: web鈫抋dmin鈫抎b. Using admin credentials to access MySQL 3306. Target: customer PII table."},
    judge_result:{success:true,damage:35,logs:["[CRIT] Bulk SELECT on users table -50k rows","[CRIT] Data exfil detected: 12MB outbound","[ERR] Rate limit exceeded"],node_status_change:"compromised",success_prob:0.68},
    blue_action:{type:"firewall_rule",target:"database",rule_or_code:"iptables -I OUTPUT -p tcp --dport 443 -m owner --uid-owner mysql -j DROP\n# Block DB outbound",action_cost:2,effectiveness:0.8,reasoning:"Database actively exfiltrating. Emergency outbound block on mysql process traffic."},
    world_state:{round:5,nodes:[
      {id:"web_server",status:"compromised",attack_count:1,defense_count:1},{id:"dns_server",status:"normal",attack_count:0,defense_count:0},
      {id:"app_server",status:"defended",attack_count:1,defense_count:1},{id:"admin_host",status:"compromised",attack_count:1,defense_count:0},
      {id:"database",status:"compromised",attack_count:1,defense_count:2},{id:"firewall",status:"scanning",attack_count:1,defense_count:0},
    ],score:{red:75,blue:62},red_phase:"Exfiltrate",availability:0.82,blue_action_points:1,special_event:"zero_day"},
  },
];

function normalizeNodes(nodes = []) {
  return Object.keys(NODE_CONFIGS).map((id) => {
    const next = nodes.find((node) => node.id === id) ?? {};
    return {
      id,
      status: next.status ?? "normal",
      attack_count: next.attack_count ?? next.attackCount ?? 0,
      defense_count: next.defense_count ?? next.defenseCount ?? 0,
      ...next,
    };
  });
}

function normalizeRound(round, fallbackIndex, totalRounds) {
  const base = SIM_ROUNDS[Math.min(fallbackIndex, SIM_ROUNDS.length - 1)] ?? SIM_ROUNDS[0];
  const worldStateInput = round?.world_state ?? round?.worldState ?? {};
  const roundNumber = round?.round ?? worldStateInput.round ?? fallbackIndex + 1;
  const redAction = { ...base.red_action, ...(round?.red_action ?? round?.redAction ?? {}) };
  const blueAction = { ...base.blue_action, ...(round?.blue_action ?? round?.blueAction ?? {}) };

  if (!redAction.target_node && redAction.target) {
    redAction.target_node = redAction.target;
  }

  return {
    ...base,
    ...round,
    round: roundNumber,
    total_rounds: round?.total_rounds ?? round?.totalRounds ?? totalRounds,
    red_action: redAction,
    blue_action: blueAction,
    judge_result: {
      ...base.judge_result,
      ...(round?.judge_result ?? round?.judgeResult ?? {}),
    },
    world_state: {
      ...base.world_state,
      ...worldStateInput,
      round: roundNumber,
      nodes: normalizeNodes(worldStateInput.nodes ?? round?.nodes ?? base.world_state.nodes),
      score: {
        red: worldStateInput.score?.red ?? round?.redScore ?? base.world_state.score.red,
        blue: worldStateInput.score?.blue ?? round?.blueScore ?? base.world_state.score.blue,
      },
      red_phase: worldStateInput.red_phase ?? worldStateInput.redPhase ?? base.world_state.red_phase,
      availability: worldStateInput.availability ?? base.world_state.availability,
      blue_action_points: worldStateInput.blue_action_points ?? worldStateInput.blueActionPoints ?? base.world_state.blue_action_points,
      special_event: worldStateInput.special_event ?? worldStateInput.specialEvent ?? null,
    },
  };
}

export function normalizeRoundsPayload(payload) {
  const maybeRounds = Array.isArray(payload)
    ? payload
    : payload?.rounds ?? payload?.frames ?? (payload ? [payload] : []);

  if (!maybeRounds.length) {
    return SIM_ROUNDS;
  }

  return maybeRounds.map((round, index) => normalizeRound(round, index, maybeRounds.length));
}

// 鈹€鈹€鈹€ SVG ICON COMPONENTS (Lucide-style, no external dep) 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
const IconShield  = ({size=16,color="#fff"}) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>;
const IconServer  = ({size=16,color="#fff"}) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>;
const IconDB      = ({size=16,color="#fff"}) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/><path d="M3 12c0 1.66 4.03 3 9 3s9-1.34 9-3"/></svg>;
const IconMonitor = ({size=16,color="#fff"}) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>;
const IconGlobe   = ({size=16,color="#fff"}) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>;
const IconWifi    = ({size=16,color="#fff"}) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>;
const IconTerminal= ({size=16,color="#fff"}) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>;
const IconAlert   = ({size=12,color="#fff"}) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>;

const ICONS = { web_server: IconGlobe, dns_server: IconWifi, app_server: IconServer, admin_host: IconMonitor, database: IconDB, firewall: IconShield };

// 鈹€鈹€鈹€ ANIMATED EDGE 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
function AnimatedEdge({ x1,y1,x2,y2,color,dasharray="6 3",speed=0.4,markerId,opacity=0.9 }) {
  return (
    <line x1={x1} y1={y1} x2={x2} y2={y2}
      stroke={color} strokeWidth="1.8" strokeDasharray={dasharray}
      markerEnd={`url(#${markerId})`} opacity={opacity}
      style={{animation:`cyberFlow ${speed}s linear infinite`}}/>
  );
}

// 鈹€鈹€鈹€ EDGE LABEL 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
function EdgeLabel({x,y,text,color,bg}) {
  const w = Math.max(text.length * 5.5 + 16, 52);
  return (
    <g transform={`translate(${x - w/2},${y - 9})`}>
      <rect width={w} height={16} rx={3} fill={bg} stroke={color} strokeWidth="0.7"/>
      <text x={w/2} y={11} textAnchor="middle" fontFamily={T.fontMono} fontSize={8} fill={color}>{text}</text>
    </g>
  );
}

// 鈹€鈹€鈹€ NODE 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
function Node({ cfg, status, atkCnt=0, defCnt=0, isTarget, isDefended, hovered, onHover, onClick }) {
  const st = STATUS_STYLES[status] || STATUS_STYLES.normal;
  const Icon = ICONS[cfg.id] || IconServer;
  const pulseAnim = status === "scanning"    ? "cyberPulseAmber"
                  : status === "compromised" ? "cyberPulseRed"
                  : status === "defended"    ? "cyberPulseGreen"
                  : "none";
  return (
    <g transform={`translate(${cfg.x},${cfg.y})`} onClick={onClick}
      onMouseEnter={()=>onHover(cfg.id)} onMouseLeave={()=>onHover(null)}
      style={{cursor:"pointer"}}>
      {status !== "normal" && (
        <circle r={32} cx={0} cy={0} fill="none" stroke={st.border} strokeWidth="0.7"
          strokeDasharray="3 3" opacity="0.45"
          style={{animation:"cyberSpin 8s linear infinite",transformOrigin:"0 0"}}/>
      )}
      <circle r={24} cx={0} cy={0} fill={st.bg} stroke={st.border}
        strokeWidth={isTarget ? 2.5 : 1.8}
        style={{
          filter: st.glow !== "none" ? `drop-shadow(${st.glow})` : "none",
          animation: pulseAnim !== "none" ? `${pulseAnim} 1.8s ease-in-out infinite` : "none",
        }}/>
      {hovered && <circle r={24} cx={0} cy={0} fill="white" opacity="0.04"/>}
      <foreignObject x={-9} y={-19} width={18} height={18} style={{pointerEvents:"none",overflow:"visible"}}>
        <div xmlns="http://www.w3.org/1999/xhtml" style={{display:"flex",alignItems:"center",justifyContent:"center",width:"100%",height:"100%"}}>
          <Icon size={13} color={st.border}/>
        </div>
      </foreignObject>
      <text y={6} textAnchor="middle" fontFamily={T.fontMono} fontSize={9} fontWeight="600" fill={st.border}>{cfg.label}</text>
      <text y={16} textAnchor="middle" fontFamily={T.fontMono} fontSize={7} fill={T.grayDim}>{cfg.sublabel}</text>
      {/* status dot */}
      <circle cx={18} cy={18} r={5} fill={T.bg}/>
      <circle cx={18} cy={18} r={4} fill={st.dot}/>
      {/* atk badge */}
      {atkCnt > 0 && <g transform="translate(-21,-21)"><circle r={7} fill={T.redBg} stroke={T.red} strokeWidth="0.8"/><text textAnchor="middle" y={3} fontFamily={T.fontMono} fontSize={7} fill={T.red} fontWeight="700">{atkCnt}</text></g>}
      {/* def badge */}
      {defCnt > 0 && <g transform="translate(21,-21)"><circle r={7} fill={T.blueBg} stroke={T.blue} strokeWidth="0.8"/><text textAnchor="middle" y={3} fontFamily={T.fontMono} fontSize={7} fill={T.blue} fontWeight="700">{defCnt}</text></g>}
      {/* labels */}
      {isTarget && <g transform="translate(0,-38)"><rect x={-20} y={-8} width={40} height={14} rx={3} fill={T.redBg} stroke={T.red} strokeWidth="0.8"/><text textAnchor="middle" y={2} fontFamily={T.fontMono} fontSize={7} fill={T.red}>TARGET</text></g>}
      {isDefended && !isTarget && <g transform="translate(0,-38)"><rect x={-24} y={-8} width={48} height={14} rx={3} fill={T.greenBg} stroke={T.green} strokeWidth="0.8"/><text textAnchor="middle" y={2} fontFamily={T.fontMono} fontSize={7} fill={T.green}>HARDENED</text></g>}
    </g>
  );
}

// 鈹€鈹€鈹€ BASE NODE 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
function Base({x,y,label,sublabel,score,color,bg,glowColor,Icon}) {
  return (
    <g transform={`translate(${x},${y})`}>
      <rect x={-44} y={-70} width={88} height={140} rx={8} fill={bg} stroke={color} strokeWidth={1}
        strokeDasharray="4 2" opacity={0.85}
        style={{filter:`drop-shadow(0 0 12px ${glowColor})`}}/>
      <text x={0} y={-52} textAnchor="middle" fontFamily={T.fontMono} fontSize={8} fill={color} letterSpacing="1" fontWeight="600">{label}</text>
      <circle r={26} cx={0} cy={0} fill={bg} stroke={color} strokeWidth={2.5} style={{filter:`drop-shadow(0 0 10px ${glowColor})`}}/>
      <foreignObject x={-10} y={-16} width={20} height={20} style={{pointerEvents:"none",overflow:"visible"}}>
        <div xmlns="http://www.w3.org/1999/xhtml" style={{display:"flex",alignItems:"center",justifyContent:"center",width:"100%",height:"100%"}}>
          <Icon size={16} color={color}/>
        </div>
      </foreignObject>
      <text y={12} textAnchor="middle" fontFamily={T.fontMono} fontSize={8} fill={color} fontWeight="600">{sublabel}</text>
      <rect x={-24} y={34} width={48} height={18} rx={4} fill={`${color}18`} stroke={color} strokeWidth="0.8"/>
      <text x={0} y={47} textAnchor="middle" fontFamily={T.fontMono} fontSize={9} fill={color} fontWeight="700">{score} pts</text>
    </g>
  );
}

// 鈹€鈹€鈹€ TOOLTIP 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
function Tooltip({cfg,status,atkCnt,defCnt}) {
  const st = STATUS_STYLES[status] || STATUS_STYLES.normal;
  const lines = [
    `Zone:     ${cfg.zone.toUpperCase()}`,
    `Ports:    ${cfg.ports.join(", ") || "none"}`,
    `Status:   ${st.label}`,
    `Attacks:  ${atkCnt}   Defenses: ${defCnt}`,
    ...cfg.vulns.map(v=>`Vuln: ${v}`),
  ];
  const w=188, lh=14, pad=10;
  const h = lines.length * lh + pad * 2 + 22;
  const tipX = cfg.x > 560 ? cfg.x - 210 : cfg.x + 34;
  const tipY = cfg.y - h/2;
  return (
    <g transform={`translate(${tipX},${tipY})`} style={{pointerEvents:"none"}}>
      <rect width={w} height={h} rx={6} fill={T.bgPanel} stroke={st.border} strokeWidth="1" opacity="0.97"/>
      <rect width={w} height={20} rx={6} fill={`${st.border}20`}/>
      <rect width={w} height={4} y={16} fill={T.bgPanel}/>
      <text x={pad} y={14} fontFamily={T.fontMono} fontSize={9} fill={st.border} fontWeight="700">{cfg.label} -{cfg.id.replace("_"," ")}</text>
      {lines.map((ln,i)=>(
        <text key={i} x={pad} y={pad+24+i*lh} fontFamily={T.fontMono} fontSize={8}
          fill={ln.startsWith("Vuln") ? T.amber : T.grayText}>{ln}</text>
      ))}
    </g>
  );
}

// 鈹€鈹€鈹€ THOUGHT PANEL 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
function ThoughtPanel({round,onClose}) {
  if (!round) return null;
  const {red_action: ra, blue_action: ba, judge_result: jr} = round;
  return (
    <div style={{
      position:"absolute",right:0,top:0,bottom:0,width:280,
      background:`${T.bgPanel}f8`,borderLeft:`1px solid ${T.border}`,
      padding:16,overflowY:"auto",zIndex:30,
      fontFamily:T.fontMono,fontSize:11,
    }}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
        <span style={{color:T.grayText,fontSize:10,letterSpacing:1}}>AGENT REASONING</span>
        <button type="button" onClick={onClose} style={{background:"none",border:"none",color:T.grayDim,cursor:"pointer",fontSize:14}}>x</button>
      </div>
      {[
        {label:"RED ACTION",color:T.red,icon:"RED",text:ra?.reasoning, extra:`${ra?.technique_id} · ${ra?.technique}`},
        {label:"JUDGE",color:T.amber,icon:"JDG",text:jr?.narrative, extra:`Success: ${jr?.success ? "YES" : "NO"} · dmg ${jr?.damage ?? 0}`},
        {label:"BLUE ACTION",color:T.blue,icon:"DEF",text:ba?.reasoning, extra:`Type: ${ba?.type} · cost ${ba?.action_cost}pt`},
      ].map(({label,color,icon,text,extra})=>(
        <div key={label} style={{marginBottom:14,padding:10,background:`${color}0d`,borderRadius:6,border:`0.5px solid ${color}44`}}>
          <div style={{color,fontSize:9,letterSpacing:1,marginBottom:4}}>{icon} {label}</div>
          <div style={{color:T.grayDim,fontSize:9,marginBottom:6,borderBottom:`0.5px solid ${color}33`,paddingBottom:4}}>{extra}</div>
          <div style={{color:T.grayText,fontSize:10,lineHeight:1.6}}>{text ?? "-"}</div>
        </div>
      ))}
      {jr?.logs?.length > 0 && (
        <div style={{marginTop:8}}>
          <div style={{color:T.grayDim,fontSize:9,letterSpacing:1,marginBottom:6}}>SYSTEM LOGS</div>
          {jr.logs.map((lg,i)=>(
            <div key={i} style={{
              fontFamily:T.fontMono,fontSize:9,marginBottom:3,
              color: lg.startsWith("[CRIT]") ? T.red : lg.startsWith("[OK]") ? T.green : lg.startsWith("[WARN]") ? T.amber : T.grayDim
            }}>{lg}</div>
          ))}
        </div>
      )}
    </div>
  );
}

// 鈹€鈹€鈹€ KILL CHAIN BAR 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
function KillChainBar({phase}) {
  const phases = ["Recon","Weaponize","Exploit","LateralMove","Exfiltrate"];
  const cur = phases.indexOf(phase ?? "Recon");
  return (
    <div style={{display:"flex",alignItems:"center",gap:5,padding:"6px 14px",borderTop:`1px solid ${T.border}`,background:T.bgPanel}}>
      {phases.map((p,i)=>(
        <React.Fragment key={p}>
          <div style={{flex:1,display:"flex",flexDirection:"column",alignItems:"center",gap:2}}>
            <div style={{height:3,width:"100%",borderRadius:2,background:i<cur?T.red:i===cur?T.amber:T.border,boxShadow:i===cur?`0 0 6px ${T.amber}`:"none",transition:"background .5s"}}/>
            <span style={{fontFamily:T.fontMono,fontSize:8,color:i<cur?T.red:i===cur?T.amber:T.grayDim,fontWeight:i===cur?700:400}}>{p}</span>
          </div>
          {i<4 && <span style={{color:T.border,fontSize:10,marginBottom:10}}>-</span>}
        </React.Fragment>
      ))}
    </div>
  );
}

// 鈹€鈹€鈹€ MAIN APP 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
export default function TopologyGraph({ initialRounds = SIM_ROUNDS }) {
  const [rounds, setRounds]    = useState(() => normalizeRoundsPayload(initialRounds));
  const [idx,setIdx]           = useState(0);
  const [playing,setPlaying]   = useState(false);
  const [speed,setSpeed]       = useState(1);
  const [hoveredNode,setHoveredNode] = useState(null);
  const [showThought,setShowThought] = useState(false);
  const [toast,setToast]       = useState({visible:false,text:"",color:T.red});
  const intervalRef = useRef(null);

  const round = rounds[idx] ?? rounds[0];
  const ws    = round?.world_state ?? rounds[0]?.world_state ?? SIM_ROUNDS[0].world_state;

  useEffect(() => {
    setRounds(normalizeRoundsPayload(initialRounds));
    setIdx(0);
    setPlaying(false);
  }, [initialRounds]);

  useEffect(() => {
    const loadReplay = (payload) => {
      const nextRounds = normalizeRoundsPayload(payload);
      setRounds(nextRounds);
      setIdx(0);
      setPlaying(false);
      setShowThought(false);
      setHoveredNode(null);
    };

    window.loadFrame = loadReplay;
    window.loadReplay = loadReplay;
    window.setTopologyRounds = loadReplay;

    return () => {
      delete window.loadFrame;
      delete window.loadReplay;
      delete window.setTopologyRounds;
    };
  }, []);

  // Auto-play
  useEffect(()=>{
    if (playing) {
      intervalRef.current = setInterval(()=>{
        setIdx(i => {
          if (i >= rounds.length - 1) { setPlaying(false); return i; }
          return i + 1;
        });
      }, 2200 / speed);
    }
    return () => clearInterval(intervalRef.current);
  },[playing, rounds.length, speed]);

  // Toast on round change
  useEffect(()=>{
    const ra = round?.red_action; const jr = round?.judge_result;
    if (!ra) return;
    const ok = jr?.success;
    setToast({
      visible: true,
      text: `R${round.round}: ${ra.technique_id} ${ra.technique} -> ${ra.target_node} ${ok ? "OK" : "BLOCKED"}`,
      color: ok ? T.red : T.grayDim,
    });
    const t = setTimeout(()=>setToast(s=>({...s,visible:false})), 3000);
    return ()=>clearTimeout(t);
  },[round]);

  const nodeStatus = id => ws.nodes?.find(n=>n.id===id)?.status ?? "normal";
  const nodeData   = id => ws.nodes?.find(n=>n.id===id) ?? {};
  const targetNode = round?.red_action?.target_node;
  const defendNode = round?.blue_action?.target;

  // Compute active attack edges
  const activePath  = MULTI_HOP[targetNode] ?? [];
  const attackEdges = activePath.slice(0,-1).map((_,i)=>({
    a: NODE_CONFIGS[activePath[i]], b: NODE_CONFIGS[activePath[i+1]]
  })).filter(e=>e.a&&e.b);

  // Defense edge
  const defTarget = NODE_CONFIGS[defendNode];
  const defEdge   = defTarget ? {x1:710,y1:190,x2:defTarget.x,y2:defTarget.y} : null;

  // Ghost paths (historical successful attacks)
  const ghostPaths = [];
  rounds.slice(0,idx).forEach(r=>{
    if (!r?.judge_result?.success) return;
    const hp = MULTI_HOP[r.red_action?.target_node] ?? [];
    hp.slice(0,-1).forEach((_,i)=>{
      const a=NODE_CONFIGS[hp[i]], b=NODE_CONFIGS[hp[i+1]];
      if(a&&b) ghostPaths.push({x1:a.x,y1:a.y,x2:b.x,y2:b.y,key:`g${r.round}-${i}`});
    });
  });

  const score = ws.score ?? {red:0,blue:0};
  const specialEvent = ws.special_event;

  return (
    <div className="topology-page">
      <style>{PAGE_STYLES}</style>
      <div className="page-title">// CyberArena · TopologyGraph · Preview</div>

      <div style={{position:"relative",background:T.bg,borderRadius:10,border:`1px solid ${T.border}`,overflow:"hidden"}}>
        <style>{`
          @keyframes cyberFlow      { to{stroke-dashoffset:-18} }
          @keyframes cyberPulseRed  { 0%,100%{filter:drop-shadow(0 0 5px rgba(239,68,68,.4))} 50%{filter:drop-shadow(0 0 16px rgba(239,68,68,.9))} }
          @keyframes cyberPulseAmber{ 0%,100%{filter:drop-shadow(0 0 4px rgba(245,158,11,.3))} 50%{filter:drop-shadow(0 0 12px rgba(245,158,11,.8))} }
          @keyframes cyberPulseGreen{ 0%,100%{filter:drop-shadow(0 0 4px rgba(34,197,94,.3))}  50%{filter:drop-shadow(0 0 12px rgba(34,197,94,.7))}  }
          @keyframes cyberSpin      { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
          @keyframes cyberBlink     { 0%,100%{opacity:1} 50%{opacity:0.3} }
        `}</style>

        {/* Special event banner */}
        {specialEvent && (
          <div style={{position:"absolute",top:0,left:0,right:0,background:`${T.amber}20`,borderBottom:`1px solid ${T.amber}55`,
            padding:"5px 12px",display:"flex",alignItems:"center",gap:8,zIndex:15,fontFamily:T.fontMono,fontSize:11}}>
            <IconAlert size={12} color={T.amber}/>
            <span style={{color:T.amber,fontWeight:600,animation:"cyberBlink 1s ease infinite"}}>
              {specialEvent==="zero_day" ? "ALERT ZERO-DAY EXPLOIT DETECTED -UNPATCHED VECTOR ACTIVE"
              : specialEvent==="ddos"   ? "ALERT DDoS SATURATION -BLUE AGENT ACTION POINTS HALVED"
              :                           "ALERT INTEL LEAK -RED AGENT HAS CURRENT DEFENSE BLUEPRINT"}
            </span>
          </div>
        )}

        {/* Toast */}
        <div style={{position:"absolute",top:specialEvent?36:10,left:"50%",transform:`translateX(-50%) translateY(${toast.visible?0:-8}px)`,
          background:`${T.bgPanel}f0`,border:`1px solid ${toast.color}`,borderRadius:6,padding:"5px 14px",
          fontFamily:T.fontMono,fontSize:11,color:toast.color,pointerEvents:"none",whiteSpace:"nowrap",
          boxShadow:`0 0 12px ${toast.color}44`,transition:"opacity .4s,transform .4s",opacity:toast.visible?1:0,zIndex:20}}>
          {toast.text}
        </div>

        {/* Thought panel */}
        {showThought && <ThoughtPanel round={round} onClose={()=>setShowThought(false)}/>}

        {/* SVG */}
        <svg viewBox="0 0 800 380" width="100%" height="auto" style={{display:"block"}} preserveAspectRatio="xMidYMid meet">
          <defs>
            <pattern id="sl" width="1" height="3" patternUnits="userSpaceOnUse">
              <line x1="0" y1="0" x2="1" y2="0" stroke="#fff" strokeWidth="0.4" opacity="0.012"/>
            </pattern>
            <marker id="ar" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto">
              <path d="M1 1L9 5L1 9" fill="none" stroke={T.red} strokeWidth="1.5"/>
            </marker>
            <marker id="ab" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto">
              <path d="M1 1L9 5L1 9" fill="none" stroke={T.blue} strokeWidth="1.5"/>
            </marker>
            <marker id="ag" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto">
              <path d="M1 1L9 5L1 9" fill="none" stroke={T.gray} strokeWidth="1"/>
            </marker>
          </defs>
          <rect width="800" height="380" fill="url(#sl)"/>

          {/* Zones */}
          {Object.values(ZONE_CONFIGS).map(z=>(
            <g key={z.label}>
              <rect x={z.x} y={z.y} width={z.w} height={z.h} rx={6} fill={z.bg} stroke={z.color} strokeWidth="0.5" strokeDasharray="5 3" opacity={0.85}/>
              <text x={z.x+z.w/2} y={z.y+14} textAnchor="middle" fontFamily={T.fontMono} fontSize={8} fill={z.color} letterSpacing="1.5" fontWeight="600" opacity="0.75">{z.label}</text>
            </g>
          ))}

          {/* Static edges */}
          {STATIC_EDGES.map(([f,t])=>{
            const a=NODE_CONFIGS[f],b=NODE_CONFIGS[t]; if(!a||!b) return null;
            return <line key={`${f}-${t}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={T.gray} strokeWidth="0.8" opacity="0.35"/>;
          })}

          {/* Ghost paths */}
          {ghostPaths.map(g=>(
            <line key={g.key} x1={g.x1} y1={g.y1} x2={g.x2} y2={g.y2} stroke={T.red} strokeWidth="1" strokeDasharray="3 5" opacity="0.2"/>
          ))}

          {/* Base connectors */}
          <line x1={90} y1={190} x2={144} y2={190} stroke={T.redDim} strokeWidth="1" strokeDasharray="4 3" opacity="0.5" markerEnd="url(#ag)"/>
          <line x1={658} y1={190} x2={616} y2={190} stroke={T.blueDim} strokeWidth="1" strokeDasharray="4 3" opacity="0.5" markerEnd="url(#ag)"/>

          {/* Attack edges */}
          {attackEdges.map(({a,b},i)=>(
            <AnimatedEdge key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} color={T.red} dasharray="6 3" speed={0.38} markerId="ar" opacity={0.9}/>
          ))}
          {attackEdges.length>0 && round?.red_action?.technique_id && (()=>{
            const last=attackEdges[attackEdges.length-1];
            return <EdgeLabel x={(last.a.x+last.b.x)/2} y={(last.a.y+last.b.y)/2-18}
              text={`${round.red_action.technique_id} · ${round.red_action.technique?.split(" ")[0]}`}
              color={T.red} bg={T.redBg}/>;
          })()}

          {/* Defense edge */}
          {defEdge && <>
            <AnimatedEdge x1={defEdge.x1} y1={defEdge.y1} x2={defEdge.x2} y2={defEdge.y2} color={T.blue} dasharray="7 3" speed={0.55} markerId="ab" opacity={0.85}/>
            <EdgeLabel x={(defEdge.x1+defEdge.x2)/2} y={(defEdge.y1+defEdge.y2)/2+20}
              text={round?.blue_action?.type?.replace("_"," ").toUpperCase()??"DEFENSE"}
              color={T.blue} bg={T.blueBg}/>
          </>}

          {/* Nodes */}
          {Object.values(NODE_CONFIGS).map(cfg=>{
            const nd=nodeData(cfg.id);
            return <Node key={cfg.id} cfg={cfg} status={nodeStatus(cfg.id)}
              atkCnt={nd.attack_count??0} defCnt={nd.defense_count??0}
              isTarget={cfg.id===targetNode} isDefended={cfg.id===defendNode&&nodeStatus(cfg.id)==="defended"}
              hovered={hoveredNode===cfg.id} onHover={setHoveredNode}
              onClick={()=>setShowThought(true)}/>;
          })}

          {/* Tooltip */}
          {hoveredNode && NODE_CONFIGS[hoveredNode] && (()=>{
            const cfg=NODE_CONFIGS[hoveredNode], nd=nodeData(hoveredNode);
            return <Tooltip cfg={cfg} status={nodeStatus(hoveredNode)} atkCnt={nd.attack_count??0} defCnt={nd.defense_count??0}/>;
          })()}

          {/* Bases */}
          <Base x={50} y={190} label="RED BASE" sublabel="ATTACKER" score={score.red} color={T.red} bg={T.redBg} glowColor={T.redGlow} Icon={IconTerminal}/>
          <Base x={750} y={190} label="BLUE BASE" sublabel="DEFENDER" score={score.blue} color={T.blue} bg={T.blueBg} glowColor={T.blueGlow} Icon={IconShield}/>

          {/* Round badge */}
          <g transform="translate(400,8)">
            <rect x={-60} y={0} width={120} height={18} rx={4} fill={T.bgPanel} stroke={T.border} strokeWidth="0.5"/>
            <text x={0} y={13} textAnchor="middle" fontFamily={T.fontMono} fontSize={8} fill={T.grayText} letterSpacing="1">
              ROUND {ws.round ?? 1} / {rounds.length} · {ws.red_phase?.toUpperCase()}
            </text>
          </g>

          {/* Availability bar */}
          <g transform="translate(274,368)">
            <text fontFamily={T.fontMono} fontSize={7} fill={T.grayDim} x={0} y={0}>AVAIL</text>
            <rect x={34} y={-8} width={100} height={7} rx={2} fill={T.bgPanel} stroke={T.border} strokeWidth="0.5"/>
            <rect x={34} y={-8} width={100*(ws.availability??1)} height={7} rx={2} fill={T.green} opacity="0.7"/>
            <text fontFamily={T.fontMono} fontSize={7} fill={T.green} x={138} y={0}>{Math.round((ws.availability??1)*100)}%</text>
          </g>

          {/* Legend */}
          <g transform="translate(470,356)">
            {[[T.red,true,"Attack"],[T.blue,false,"Defense"],[T.gray,false,"Network"]].map(([c,d,l],i)=>(
              <g key={i} transform={`translate(${i*90},0)`}>
                <line x1={0} y1={8} x2={20} y2={8} stroke={c} strokeWidth={1.2} strokeDasharray={d?"4 2":"none"} opacity="0.8"/>
                <text x={24} y={12} fontFamily={T.fontMono} fontSize={7} fill={T.grayDim}>{l}</text>
              </g>
            ))}
          </g>
        </svg>

        {/* Kill chain bar */}
        <KillChainBar phase={ws.red_phase}/>
      </div>

      {/* Controls */}
      <div className="controls">
        <button type="button" className={`ctrl-btn${playing?" active":""}`} onClick={()=>setPlaying(p=>!p)}>
          {playing ? "PAUSE" : "PLAY"}
        </button>
        <button type="button" className="ctrl-btn" onClick={()=>{setPlaying(false);setIdx(0);}}>RESET</button>
        <button type="button" className="ctrl-btn" onClick={()=>setIdx(i=>Math.max(0,i-1))} disabled={idx===0}>PREV</button>
        <button type="button" className="ctrl-btn" onClick={()=>setIdx(i=>Math.min(rounds.length-1,i+1))} disabled={idx===rounds.length-1}>NEXT</button>
        {[0.5,1,2].map(s=>(
          <button type="button" key={s} className={`ctrl-btn${speed===s?" active":""}`} onClick={()=>setSpeed(s)}>{s}x</button>
        ))}
        <button type="button" className="ctrl-btn" onClick={()=>setShowThought(t=>!t)}>
          {showThought ? "CLOSE THOUGHTS" : "AGENT THOUGHTS"}
        </button>
      </div>

      <div className="info-row">
        {rounds.map((r,i)=>(
          <div key={i} className="info-chip" style={{
            cursor:"pointer", borderColor: i===idx ? T.blue : undefined,
            color: i===idx ? T.blue : undefined,
          }} onClick={()=>{setPlaying(false);setIdx(i);}}>
            R{r.round} {r.judge_result.success ? "OK" : "NO"} {r.red_action.technique_id}
          </div>
        ))}
      </div>

      <div style={{ paddingTop: 10, color: "#4b5563", fontFamily: T.fontMono, fontSize: 10 }}>
        DEV: call <code style={{ color: "#6b7280" }}>window.loadFrame(json)</code> to replace preview rounds with backend replay data.
      </div>
    </div>
  );
}


