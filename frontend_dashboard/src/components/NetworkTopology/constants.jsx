export const T = {
  bg: "#07090f",
  bgPanel: "#0d1117",
  bgNode: "#111827",
  border: "#1f2937",
  red: "#ef4444",
  redDim: "#7f1d1d",
  redBg: "#1a0a0a",
  redGlow: "rgba(239,68,68,0.55)",
  blue: "#3b82f6",
  blueDim: "#1e3a5f",
  blueBg: "#080f1c",
  blueGlow: "rgba(59,130,246,0.55)",
  green: "#22c55e",
  greenBg: "#071510",
  greenGlow: "rgba(34,197,94,0.45)",
  amber: "#f59e0b",
  amberBg: "#1a1000",
  gray: "#374151",
  grayText: "#9ca3af",
  grayDim: "#6b7280",
  fontMono: "'JetBrains Mono', monospace",
};

export const PAGE_STYLES = `
  @import url("https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600&display=swap");
  .topology-page { margin: 0 auto; min-height: 100vh; padding: 24px 40px; }
  .page-title { font-family: 'JetBrains Mono', monospace; font-size: 11px; letter-spacing: 2px; color: #4b5563; margin-bottom: 16px; text-transform: uppercase; }
  .controls { display: flex; gap: 10px; margin-top: 20px; flex-wrap: wrap; }
  .ctrl-btn { font-family: 'JetBrains Mono', monospace; font-size: 10px; padding: 6px 14px; border-radius: 4px; cursor: pointer; background: #111827; border: 1px solid #1f2937; color: #9ca3af; transition: all 0.15s; }
  .ctrl-btn:hover:not(:disabled) { border-color: #3b82f6; color: #3b82f6; }
  .ctrl-btn.active { background: #0d1f3c; border-color: #3b82f6; color: #3b82f6; }
  .ctrl-btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .info-row { display: flex; gap: 14px; margin-top: 18px; flex-wrap: wrap; }
  .info-chip { font-family: 'JetBrains Mono', monospace; font-size: 10px; padding: 5px 12px; border-radius: 20px; background: #111827; border: 0.5px solid #1f2937; color: #6b7280; }
`;

export const ZONE_CONFIGS = {
  internet: { label: "INTERNET", x: 110, y: 30, w: 120, h: 340, color: T.gray, bg: "rgba(55,65,81,0.06)" },
  dmz: { label: "DMZ", x: 250, y: 30, w: 120, h: 340, color: T.blue, bg: "rgba(59,130,246,0.05)" },
  internal: { label: "INTERNAL", x: 390, y: 30, w: 120, h: 340, color: T.green, bg: "rgba(34,197,94,0.05)" },
  database: { label: "DATABASE", x: 530, y: 30, w: 120, h: 340, color: T.amber, bg: "rgba(245,158,11,0.05)" },
};

export const NODE_CONFIGS = {
  web_server: { id: "web_server", label: "WEB", sublabel: ":80/443", zone: "dmz", x: 310, y: 120, ports: [80, 443], vulns: ["SQLi-login", "CVE-2021-44228"], description: "Nginx 1.18 · PHP 7.4 · DMZ exposed" },
  dns_server: { id: "dns_server", label: "DNS", sublabel: ":53", zone: "dmz", x: 310, y: 250, ports: [53], vulns: ["DNS-cache-poison"], description: "BIND 9.16 · DMZ resolver" },
  app_server: { id: "app_server", label: "APP", sublabel: ":8080", zone: "internal", x: 450, y: 120, ports: [8080, 8443], vulns: ["CVE-2023-1234"], description: "Tomcat 10 · Internal app tier" },
  admin_host: { id: "admin_host", label: "ADM", sublabel: ":22", zone: "internal", x: 450, y: 250, ports: [22, 3389], vulns: ["Weak-SSH-key"], description: "Admin workstation · Jump host" },
  database: { id: "database", label: "DB", sublabel: ":3306", zone: "database", x: 590, y: 190, ports: [3306, 5432], vulns: ["SQLi-stored", "Unpatched-MySQL"], description: "MySQL 8.0 · FINAL TARGET" },
  firewall: { id: "firewall", label: "FW", sublabel: "gateway", zone: "internet", x: 170, y: 190, ports: [], vulns: [], description: "pfSense 2.7 · Internet gateway" },
};

export const STATIC_EDGES = [
  ["firewall", "web_server"],
  ["firewall", "dns_server"],
  ["web_server", "app_server"],
  ["dns_server", "app_server"],
  ["app_server", "database"],
  ["app_server", "admin_host"],
  ["admin_host", "database"],
];

export const STATUS_STYLES = {
  normal: { border: T.blue, bg: T.bgNode, glow: "none", dot: T.green, label: "ONLINE" },
  scanning: { border: T.amber, bg: T.amberBg, glow: "0 0 10px rgba(245,158,11,.55)", dot: T.amber, label: "SCANNING" },
  compromised: { border: T.red, bg: T.redBg, glow: "0 0 14px rgba(239,68,68,.7)", dot: T.red, label: "COMPROMISED" },
  defended: { border: T.green, bg: T.greenBg, glow: "0 0 10px rgba(34,197,94,.55)", dot: T.green, label: "HARDENED" },
};

export const MULTI_HOP = {
  database: ["firewall", "web_server", "app_server", "database"],
  app_server: ["firewall", "web_server", "app_server"],
  admin_host: ["firewall", "web_server", "app_server", "admin_host"],
  web_server: ["firewall", "web_server"],
  dns_server: ["firewall", "dns_server"],
  firewall: ["firewall"],
};

const IconShield = ({ size = 16, color = "#fff" }) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>;
const IconServer = ({ size = 16, color = "#fff" }) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" /><rect x="2" y="14" width="20" height="8" rx="2" /><line x1="6" y1="6" x2="6.01" y2="6" /><line x1="6" y1="18" x2="6.01" y2="18" /></svg>;
const IconDB = ({ size = 16, color = "#fff" }) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3" /><path d="M3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5" /><path d="M3 12c0 1.66 4.03 3 9 3s9-1.34 9-3" /></svg>;
const IconMonitor = ({ size = 16, color = "#fff" }) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" /></svg>;
const IconGlobe = ({ size = 16, color = "#fff" }) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" /></svg>;
const IconWifi = ({ size = 16, color = "#fff" }) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0" /><path d="M1.42 9a16 16 0 0 1 21.16 0" /><path d="M8.53 16.11a6 6 0 0 1 6.95 0" /><line x1="12" y1="20" x2="12.01" y2="20" /></svg>;

export const IconTerminal = ({ size = 16, color = "#fff" }) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" /></svg>;
export const IconAlert = ({ size = 12, color = "#fff" }) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>;

export const ICONS = { web_server: IconGlobe, dns_server: IconWifi, app_server: IconServer, admin_host: IconMonitor, database: IconDB, firewall: IconShield };
