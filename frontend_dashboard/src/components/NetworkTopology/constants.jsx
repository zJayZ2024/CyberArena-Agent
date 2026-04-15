const INITIAL_STATE = {
  round: 7,
  totalRounds: 20,
  redScore: 42,
  blueScore: 68,
  nodes: [
    { id: "attacker", label: "ATTACKER", type: "red_agent", zone: "internet", x: 112, y: 230, status: "compromised", port: null },
    { id: "fw", label: "FW", type: "firewall", zone: "internet", x: 230, y: 230, status: "normal", port: ":firewall" },
    { id: "web", label: "WEB", type: "web_server", zone: "dmz", x: 370, y: 180, status: "compromised", port: null },
    { id: "dns", label: "DNS", type: "dns_server", zone: "dmz", x: 370, y: 310, status: "normal", port: ":53" },
    { id: "app", label: "APP", type: "app_server", zone: "internal", x: 510, y: 230, status: "defended", port: null },
    { id: "db", label: "DB", type: "database", zone: "database", x: 650, y: 195, status: "compromised", port: null },
    { id: "adm", label: "ADM", type: "admin_host", zone: "database", x: 650, y: 310, status: "normal", port: ":ss" },
    { id: "defender", label: "DEFENDER", type: "blue_agent", zone: "blue_base", x: 820, y: 230, status: "defended", port: null },
  ],
  edges: [
    { id: "e1", from: "attacker", to: "fw", type: "attack", label: "T1190 - SQLi" },
    { id: "e2", from: "fw", to: "web", type: "attack", label: null },
    { id: "e3", from: "fw", to: "dns", type: "attack", label: null },
    { id: "e4", from: "web", to: "app", type: "attack", label: null },
    { id: "e5", from: "app", to: "db", type: "attack", label: null },
    { id: "e6", from: "defender", to: "db", type: "defense", label: "DROP :3306" },
    { id: "e7", from: "fw", to: "web", type: "network", label: null },
    { id: "e8", from: "fw", to: "dns", type: "network", label: null },
  ],
};

export const NODE_ICONS = {
  web_server: (
    <>
      <rect x="-10" y="-12" width="20" height="14" rx="2" strokeWidth="1.5" fill="none" />
      <line x1="-10" y1="-2" x2="10" y2="-2" strokeWidth="1" />
      <circle cx="0" cy="7" r="3" strokeWidth="1.5" fill="none" />
      <line x1="-4" y1="10" x2="4" y2="10" strokeWidth="1.5" />
    </>
  ),
  database: (
    <>
      <ellipse cx="0" cy="-8" rx="9" ry="4" strokeWidth="1.5" fill="none" />
      <line x1="-9" y1="-8" x2="-9" y2="8" strokeWidth="1.5" />
      <line x1="9" y1="-8" x2="9" y2="8" strokeWidth="1.5" />
      <ellipse cx="0" cy="8" rx="9" ry="4" strokeWidth="1.5" fill="none" />
      <path d="M-9,0 Q0,4 9,0" strokeWidth="1" fill="none" />
    </>
  ),
  app_server: (
    <>
      <rect x="-10" y="-10" width="20" height="20" rx="2" strokeWidth="1.5" fill="none" />
      <line x1="-6" y1="-4" x2="0" y2="-4" strokeWidth="1.5" />
      <line x1="-6" y1="0" x2="4" y2="0" strokeWidth="1.5" />
      <line x1="-6" y1="4" x2="2" y2="4" strokeWidth="1.5" />
    </>
  ),
  dns_server: (
    <>
      <rect x="-9" y="-9" width="18" height="18" rx="3" strokeWidth="1.5" fill="none" />
      <line x1="-5" y1="-3" x2="5" y2="-3" strokeWidth="1.5" />
      <line x1="-5" y1="2" x2="5" y2="2" strokeWidth="1.5" />
      <line x1="-5" y1="7" x2="2" y2="7" strokeWidth="1.2" />
    </>
  ),
  firewall: (
    <>
      <path d="M0,-13 L12,0 L0,13 L-12,0 Z" strokeWidth="1.5" fill="none" />
      <path d="M-4,-4 L0,0 L-4,4 M0,-4 L4,0 L0,4" strokeWidth="1.2" fill="none" />
    </>
  ),
  admin_host: (
    <>
      <rect x="-9" y="-12" width="18" height="14" rx="2" strokeWidth="1.5" fill="none" />
      <line x1="-5" y1="2" x2="5" y2="2" strokeWidth="1.5" />
      <line x1="-3" y1="5" x2="3" y2="5" strokeWidth="1.2" />
      <line x1="-7" y1="8" x2="7" y2="8" strokeWidth="1.5" />
    </>
  ),
  red_agent: (
    <>
      <line x1="-9" y1="-9" x2="9" y2="9" strokeWidth="2" />
      <line x1="9" y1="-9" x2="-9" y2="9" strokeWidth="2" />
    </>
  ),
  blue_agent: (
    <>
      <path d="M0,-12 L10,0 L6,8 L-6,8 L-10,0 Z" strokeWidth="1.5" fill="none" />
      <circle cx="0" cy="1" r="3" strokeWidth="1.2" fill="none" />
    </>
  ),
};

export const STATUS_STYLE = {
  normal: { ring: "#3B82F6", fill: "#1e3a5f", dot: "#22c55e", label: "Normal" },
  scanning: { ring: "#F59E0B", fill: "#3d2c0a", dot: "#F59E0B", label: "Scanning" },
  compromised: { ring: "#EF4444", fill: "#3d0a0a", dot: "#EF4444", label: "Compromised" },
  defended: { ring: "#22c55e", fill: "#0a2d0f", dot: "#22c55e", label: "Defended" },
};

export const ZONES = [
  { id: "internet", label: "INTERNET", x: 30, w: 200, color: "#1a1a2e", border: "#3B82F6" },
  { id: "dmz", label: "DMZ", x: 250, w: 160, color: "#1a2e1a", border: "#22c55e" },
  { id: "internal", label: "INTERNAL", x: 430, w: 160, color: "#1a2a1a", border: "#22c55e" },
  { id: "database", label: "DATABASE", x: 610, w: 180, color: "#2e1a1a", border: "#7c3aed" },
];

export const LEGEND_ITEMS = [
  { color: "#22c55e", label: "正常运行" },
  { color: "#F59E0B", label: "扫描侦察" },
  { color: "#EF4444", label: "已被攻破" },
  { color: "#3B82F6", label: "防御加固" },
];

export const EDGE_LEGEND_ITEMS = [
  { color: "#EF4444", strokeWidth: "1.5", strokeDasharray: "4 3", label: "攻击路径" },
  { color: "#3B82F6", strokeWidth: "1.5", strokeDasharray: "4 3", label: "防御动作" },
  { color: "#4b5563", strokeWidth: "1", strokeDasharray: "3 3", label: "网络连接" },
];

export const GRAPH_DIMENSIONS = {
  svgWidth: 960,
  svgHeight: 440,
  zoneHeight: 380,
  zoneY: 30,
};

export default INITIAL_STATE;
