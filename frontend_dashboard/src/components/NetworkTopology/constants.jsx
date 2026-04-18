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

export const GRAPH_VIEW = {
  width: 980,
  height: 460,
  zoneX: 120,
  zoneY: 30,
  zoneW: 740,
  zoneH: 390,
  zoneGap: 14,
  redBaseX: 60,
  blueBaseX: 920,
  baseY: 230,
};

const FIREWALL_KEYWORDS = ["fw", "firewall", "gateway", "edge", "waf"];
const DMZ_KEYWORDS = ["web", "vpn", "proxy", "mail", "bastion", "dmz"];
const OFFICE_KEYWORDS = ["office", "pc", "workstation", "client", "endpoint"];
const DATABASE_KEYWORDS = ["db", "database", "mysql", "postgres", "sql"];
const CORE_KEYWORDS = ["app", "db", "database", "mysql", "postgres", "sql", "storage", "redis", "cache"];

const ZONE_ORDER = ["external", "dmz", "office", "core"];
const ZONE_LABELS = {
  external: "EXTERNAL THREAT",
  dmz: "DMZ ISOLATION - FW / WEB / VPN",
  office: "OFFICE INTRANET - OFFICE_PC",
  core: "CORE BUSINESS - APP / DEV / DB / STORAGE",
};
const ZONE_NOTES = {
  external: "RED STARTS FROM INTERNET; NOT A CONTESTABLE RESOURCE NODE",
};
const ZONE_STYLES = {
  external: { color: T.gray, bg: "rgba(55,65,81,0.05)" },
  dmz: { color: T.blue, bg: "rgba(59,130,246,0.05)" },
  office: { color: "#22c55e", bg: "rgba(34,197,94,0.05)" },
  core: { color: T.amber, bg: "rgba(245,158,11,0.05)" },
};

const HIDDEN_RESOURCE_NODE_IDS = new Set(["internet"]);
const NODE_ZONE_MAP = {
  fw: "dmz",
  firewall: "dmz",
  web: "dmz",
  vpn: "dmz",
  office_pc: "office",
  app: "core",
  dev: "core",
  db: "core",
  storage: "core",
};

export const STATUS_STYLES = {
  Normal: { border: T.blue, bg: T.bgNode, glow: "none", dot: T.green, label: "ONLINE" },
  Scanning: { border: T.amber, bg: T.amberBg, glow: "0 0 10px rgba(245,158,11,.55)", dot: T.amber, label: "SCANNING" },
  Compromised: { border: T.red, bg: T.redBg, glow: "0 0 14px rgba(239,68,68,.7)", dot: T.red, label: "COMPROMISED" },
  Defended: { border: T.green, bg: T.greenBg, glow: "0 0 10px rgba(34,197,94,.55)", dot: T.green, label: "HARDENED" },
  Isolated: { border: "#64748b", bg: "#0b1220", glow: "none", dot: T.grayDim, label: "ISOLATED" },
  Patched: { border: T.green, bg: T.greenBg, glow: "0 0 10px rgba(34,197,94,.55)", dot: T.green, label: "PATCHED" },
  normal: { border: T.blue, bg: T.bgNode, glow: "none", dot: T.green, label: "ONLINE" },
  scanning: { border: T.amber, bg: T.amberBg, glow: "0 0 10px rgba(245,158,11,.55)", dot: T.amber, label: "SCANNING" },
  compromised: { border: T.red, bg: T.redBg, glow: "0 0 14px rgba(239,68,68,.7)", dot: T.red, label: "COMPROMISED" },
  defended: { border: T.green, bg: T.greenBg, glow: "0 0 10px rgba(34,197,94,.55)", dot: T.green, label: "HARDENED" },
  isolated: { border: "#64748b", bg: "#0b1220", glow: "none", dot: T.grayDim, label: "ISOLATED" },
  patched: { border: T.green, bg: T.greenBg, glow: "0 0 10px rgba(34,197,94,.55)", dot: T.green, label: "PATCHED" },
  down: { border: "#64748b", bg: "#0b1220", glow: "none", dot: T.grayDim, label: "DOWN" },
};

const IconShield = ({ size = 16, color = "#fff" }) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>;
const IconServer = ({ size = 16, color = "#fff" }) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" /><rect x="2" y="14" width="20" height="8" rx="2" /><line x1="6" y1="6" x2="6.01" y2="6" /><line x1="6" y1="18" x2="6.01" y2="18" /></svg>;
const IconDB = ({ size = 16, color = "#fff" }) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3" /><path d="M3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5" /><path d="M3 12c0 1.66 4.03 3 9 3s9-1.34 9-3" /></svg>;
const IconMonitor = ({ size = 16, color = "#fff" }) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" /></svg>;
const IconGlobe = ({ size = 16, color = "#fff" }) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" /></svg>;
const IconWifi = ({ size = 16, color = "#fff" }) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0" /><path d="M1.42 9a16 16 0 0 1 21.16 0" /><path d="M8.53 16.11a6 6 0 0 1 6.95 0" /><line x1="12" y1="20" x2="12.01" y2="20" /></svg>;

export const IconTerminal = ({ size = 16, color = "#fff" }) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" /></svg>;
export const IconAlert = ({ size = 12, color = "#fff" }) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>;

export const ICONS = {
  internet: IconGlobe,
  fw: IconShield,
  firewall: IconShield,
  web: IconGlobe,
  app: IconServer,
  storage: IconServer,
  db: IconDB,
  vpn: IconWifi,
  office_pc: IconMonitor,
  dev: IconServer,
};

function normalizeZoneId(zoneId = "", nodeId = "") {
  const normalized = String(zoneId || "").toLowerCase();
  if (["external", "internet", "outside", "wan"].includes(normalized)) {
    return "external";
  }
  if (["dmz", "perimeter", "edge", "firewall", "fw", "gateway", "perimeter_fw"].includes(normalized)) {
    return "dmz";
  }
  if (["office", "intranet", "office_lan", "corp"].includes(normalized)) {
    return "office";
  }
  if (["core", "internal", "database", "datacenter", "lan"].includes(normalized)) {
    return "core";
  }
  return classifyZone(nodeId);
}

export function isHiddenResourceNode(nodeId = "") {
  return HIDDEN_RESOURCE_NODE_IDS.has(String(nodeId || "").toLowerCase());
}

export function classifyZone(nodeId = "") {
  const lowered = String(nodeId || "").toLowerCase();
  if (isHiddenResourceNode(lowered)) {
    return "external";
  }
  if (NODE_ZONE_MAP[lowered]) {
    return NODE_ZONE_MAP[lowered];
  }
  if (FIREWALL_KEYWORDS.some((keyword) => lowered.includes(keyword)) || DMZ_KEYWORDS.some((keyword) => lowered.includes(keyword))) {
    return "dmz";
  }
  if (OFFICE_KEYWORDS.some((keyword) => lowered.includes(keyword))) {
    return "office";
  }
  if (CORE_KEYWORDS.some((keyword) => lowered.includes(keyword))) {
    return "core";
  }
  return "core";
}

function abbreviateNodeId(nodeId = "") {
  const cleaned = String(nodeId || "").trim();
  if (!cleaned) {
    return "NODE";
  }
  const parts = cleaned.split(/[^a-zA-Z0-9]+/).filter(Boolean);
  if (parts.length > 1) {
    return parts.map((part) => part[0]).join("").slice(0, 4).toUpperCase();
  }
  if (cleaned.length <= 4) {
    return cleaned.toUpperCase();
  }
  return cleaned.slice(0, 4).toUpperCase();
}

export function buildZoneConfigs(nodes = []) {
  const slotCount = ZONE_ORDER.length;
  const availableWidth = GRAPH_VIEW.zoneW - GRAPH_VIEW.zoneGap * Math.max(0, slotCount - 1);
  const slotWidth = Math.max(120, Math.floor(availableWidth / slotCount));

  return ZONE_ORDER.map((zone, index) => {
    const style = ZONE_STYLES[zone] || ZONE_STYLES.core;
    return {
      id: zone,
      label: ZONE_LABELS[zone] || zone.toUpperCase(),
      note: ZONE_NOTES[zone] || "",
      x: GRAPH_VIEW.zoneX + index * (slotWidth + GRAPH_VIEW.zoneGap),
      y: GRAPH_VIEW.zoneY,
      w: slotWidth,
      h: GRAPH_VIEW.zoneH,
      color: style.color,
      bg: style.bg,
    };
  });
}

export function buildNodeConfigs(nodes = [], networkNodes = {}, zoneConfigs = []) {
  const byZone = new Map();

  nodes
    .slice()
    .sort((a, b) => String(a.id || "").localeCompare(String(b.id || "")))
    .forEach((node) => {
      const nodeId = String(node?.id || "");
      if (!nodeId || isHiddenResourceNode(nodeId)) {
        return;
      }
      const zone = normalizeZoneId(node.zone, nodeId);
      if (!byZone.has(zone)) {
        byZone.set(zone, []);
      }
      byZone.get(zone).push(node);
    });

  const configs = {};
  zoneConfigs.forEach((zone) => {
    const group = byZone.get(zone.id) || [];
    const verticalGap = zone.h / (group.length + 1);
    group.forEach((node, index) => {
      const nodeId = String(node.id);
      const rawPorts = networkNodes?.[nodeId]?.exposed_ports ?? node.exposed_ports ?? [];
      const ports = Array.isArray(rawPorts) ? rawPorts.map((port) => Number(port)).filter((port) => Number.isFinite(port)) : [];
      const vulns = Object.keys(networkNodes?.[nodeId]?.vulnerabilities ?? node.vulnerabilities ?? {});
      const xOffset = group.length > 1 && index % 2 === 1 ? -12 : group.length > 1 ? 12 : 0;
      configs[nodeId] = {
        id: nodeId,
        label: abbreviateNodeId(nodeId),
        sublabel: ports.length ? `:${ports[0]}` : "node",
        zone: zone.id,
        x: Math.round(zone.x + zone.w / 2 + xOffset),
        y: Math.round(zone.y + verticalGap * (index + 1)),
        ports,
        vulns,
      };
    });
  });

  return configs;
}

export function resolveNodeIcon(nodeId = "", zone = "core") {
  const lowered = String(nodeId || "").toLowerCase();
  if (ICONS[lowered]) {
    return ICONS[lowered];
  }
  if (DATABASE_KEYWORDS.some((keyword) => lowered.includes(keyword))) {
    return IconDB;
  }
  if (lowered === "internet" || zone === "external") {
    return IconGlobe;
  }
  if (DMZ_KEYWORDS.some((keyword) => lowered.includes(keyword)) || zone === "dmz") {
    return lowered.includes("vpn") ? IconWifi : IconShield;
  }
  if (OFFICE_KEYWORDS.some((keyword) => lowered.includes(keyword)) || zone === "office") {
    return IconMonitor;
  }
  if (FIREWALL_KEYWORDS.some((keyword) => lowered.includes(keyword))) {
    return IconShield;
  }
  return IconServer;
}
