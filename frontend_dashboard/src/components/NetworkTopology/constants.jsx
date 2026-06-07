export const T = {
  bg: "#0c1220",
  bgPanel: "#111a2e",
  bgNode: "#1c2d4a",
  border: "#304060",
  red: "#ff6b7a",
  redDim: "#b91c1c",
  redBg: "rgba(255,107,122,0.12)",
  redGlow: "rgba(255,107,122,0.65)",
  blue: "#5b9fff",
  blueDim: "#2563eb",
  blueBg: "rgba(91,159,255,0.10)",
  blueGlow: "rgba(91,159,255,0.55)",
  green: "#34e08d",
  greenBg: "rgba(52,224,141,0.10)",
  greenGlow: "rgba(52,224,141,0.50)",
  amber: "#ffcc55",
  amberBg: "rgba(255,204,85,0.08)",
  purple: "#a78bfa",
  purpleBg: "rgba(167,139,250,0.12)",
  cyan: "#22d3ee",
  gray: "#7088b0",
  grayText: "#b8c5db",
  grayDim: "#8a9bc0",
  fontMono: "'JetBrains Mono', monospace",
};

export const PAGE_STYLES = `
  @import url("https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap");
  .topology-page { margin: 0 auto; min-height: 100vh; padding: 24px 40px; }
  .page-title { font-family: 'JetBrains Mono', monospace; font-size: 11px; letter-spacing: 2px; color: #8a9bc0; margin-bottom: 16px; text-transform: uppercase; }
  .controls { display: flex; gap: 10px; margin-top: 20px; flex-wrap: wrap; }
  .ctrl-btn { font-family: 'JetBrains Mono', monospace; font-size: 10px; padding: 6px 14px; border-radius: 4px; cursor: pointer; background: #1c2d4a; border: 1px solid #304060; color: #b8c5db; transition: all 0.15s; }
  .ctrl-btn:hover:not(:disabled) { border-color: #5b9fff; color: #5b9fff; }
  .ctrl-btn.active { background: rgba(91,159,255,0.10); border-color: #5b9fff; color: #5b9fff; }
  .ctrl-btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .info-row { display: flex; gap: 14px; margin-top: 18px; flex-wrap: wrap; }
  .info-chip { font-family: 'JetBrains Mono', monospace; font-size: 10px; padding: 5px 12px; border-radius: 20px; background: #1c2d4a; border: 0.5px solid #304060; color: #8a9bc0; }
`;

export const GRAPH_VIEW = {
  width: 1180,
  height: 500,
  zoneX: 100,
  zoneY: 30,
  zoneW: 980,
  zoneH: 430,
  zoneGap: 12,
  redBaseX: 48,
  blueBaseX: 1132,
  baseY: 250,
};

const FIREWALL_KEYWORDS = ["fw", "firewall", "gateway", "edge", "waf"];
const DMZ_KEYWORDS = ["web", "vpn", "proxy", "mail", "bastion", "dmz"];
const OFFICE_KEYWORDS = ["office", "pc", "workstation", "client", "endpoint"];
const DEVOPS_KEYWORDS = ["dev", "ci", "jenkins", "build", "git", "pipeline"];
const DATABASE_KEYWORDS = ["db", "database", "mysql", "postgres", "sql"];
const CORE_KEYWORDS = ["app", "db", "database", "mysql", "postgres", "sql", "storage", "redis", "cache"];

const ZONE_ORDER = ["external", "dmz", "office", "devops", "core"];
const ZONE_WEIGHTS = {
  external: 0.7,
  dmz: 1,
  office: 1.15,
  devops: 1,
  core: 1.65,
};
const ZONE_LABELS = {
  external: "外部威胁",
  dmz: "DMZ 边界 - 防火墙 / 网站 / 远程接入",
  office: "办公内网 - 终端与跳板",
  devops: "研发供应链 - 开发 / CI/CD",
  core: "核心业务 - 应用 / 数据库 / 存储 / 安全",
};
const ZONE_NOTES = {
  external: "红方从互联网发起行动；该区域不是可争夺资产。",
};
const ZONE_STYLES = {
  external: { color: T.gray, bg: "rgba(112,136,176,0.07)" },
  dmz: { color: T.blue, bg: "rgba(91,159,255,0.07)" },
  office: { color: T.green, bg: "rgba(52,224,141,0.06)" },
  devops: { color: T.purple, bg: "rgba(167,139,250,0.06)" },
  core: { color: T.amber, bg: "rgba(255,204,85,0.07)" },
};

const HIDDEN_RESOURCE_NODE_IDS = new Set(["internet"]);
const NODE_ZONE_MAP = {
  fw: "dmz",
  firewall: "dmz",
  web: "dmz",
  vpn: "dmz",
  office_pc: "office",
  finance_pc: "office",
  identity: "office",
  dev: "devops",
  ci: "devops",
  api: "core",
  app: "core",
  db: "core",
  storage: "core",
  backup: "core",
  soc: "core",
};

const NODE_POSITION_HINTS = {
  dmz: {
    fw: { xRatio: 0.34, yRatio: 0.25 },
    web: { xRatio: 0.66, yRatio: 0.5 },
    vpn: { xRatio: 0.34, yRatio: 0.75 },
  },
  office: {
    office_pc: { xRatio: 0.5, yRatio: 0.22 },
    finance_pc: { xRatio: 0.32, yRatio: 0.58 },
    identity: { xRatio: 0.68, yRatio: 0.78 },
  },
  devops: {
    ci: { xRatio: 0.35, yRatio: 0.34 },
    dev: { xRatio: 0.65, yRatio: 0.7 },
  },
  core: {
    api: { xRatio: 0.27, yRatio: 0.18 },
    app: { xRatio: 0.72, yRatio: 0.18 },
    storage: { xRatio: 0.27, yRatio: 0.5 },
    backup: { xRatio: 0.72, yRatio: 0.5 },
    soc: { xRatio: 0.27, yRatio: 0.82 },
    db: { xRatio: 0.72, yRatio: 0.82 },
  },
};

export const STATUS_STYLES = {
  Normal: { border: T.grayDim, bg: T.bgNode, glow: "none", dot: T.gray, label: "正常" },
  Scanning: { border: T.grayDim, bg: T.bgNode, glow: "none", dot: T.gray, label: "正常" },
  Compromised: { border: T.red, bg: T.redBg, glow: "0 0 16px rgba(255,107,122,.75)", dot: T.red, label: "已失陷" },
  Defended: { border: T.green, bg: T.greenBg, glow: "0 0 12px rgba(52,224,141,.6)", dot: T.green, label: "已加固" },
  Isolated: { border: T.grayDim, bg: "#162340", glow: "none", dot: T.grayDim, label: "已隔离" },
  Patched: { border: T.green, bg: T.greenBg, glow: "0 0 12px rgba(52,224,141,.6)", dot: T.green, label: "已修补" },
  Down: { border: T.grayDim, bg: "#162340", glow: "none", dot: T.grayDim, label: "离线" },
  normal: { border: T.grayDim, bg: T.bgNode, glow: "none", dot: T.gray, label: "正常" },
  scanning: { border: T.grayDim, bg: T.bgNode, glow: "none", dot: T.gray, label: "正常" },
  compromised: { border: T.red, bg: T.redBg, glow: "0 0 16px rgba(255,107,122,.75)", dot: T.red, label: "已失陷" },
  defended: { border: T.green, bg: T.greenBg, glow: "0 0 12px rgba(52,224,141,.6)", dot: T.green, label: "已加固" },
  isolated: { border: T.grayDim, bg: "#162340", glow: "none", dot: T.grayDim, label: "已隔离" },
  patched: { border: T.green, bg: T.greenBg, glow: "0 0 12px rgba(52,224,141,.6)", dot: T.green, label: "已修补" },
  down: { border: T.grayDim, bg: "#162340", glow: "none", dot: T.grayDim, label: "离线" },
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
  if (["devops", "development", "pipeline", "supply_chain"].includes(normalized)) {
    return "devops";
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
  if (DEVOPS_KEYWORDS.some((keyword) => lowered.includes(keyword))) {
    return "devops";
  }
  if (CORE_KEYWORDS.some((keyword) => lowered.includes(keyword))) {
    return "core";
  }
  return "core";
}

function abbreviateNodeId(nodeId = "") {
  const cleaned = String(nodeId || "").trim();
  if (!cleaned) {
    return "节点";
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
  const availableWidth = GRAPH_VIEW.zoneW - GRAPH_VIEW.zoneGap * Math.max(0, ZONE_ORDER.length - 1);
  const totalWeight = ZONE_ORDER.reduce((sum, zone) => sum + (ZONE_WEIGHTS[zone] || 1), 0);
  let cursorX = GRAPH_VIEW.zoneX;

  return ZONE_ORDER.map((zone) => {
    const style = ZONE_STYLES[zone] || ZONE_STYLES.core;
    const width = Math.floor(availableWidth * ((ZONE_WEIGHTS[zone] || 1) / totalWeight));
    const config = {
      id: zone,
      label: ZONE_LABELS[zone] || zone.toUpperCase(),
      note: ZONE_NOTES[zone] || "",
      x: cursorX,
      y: GRAPH_VIEW.zoneY,
      w: width,
      h: GRAPH_VIEW.zoneH,
      color: style.color,
      bg: style.bg,
    };
    cursorX += width + GRAPH_VIEW.zoneGap;
    return config;
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
    const columns = group.length >= 4 ? 2 : 1;
    const rows = Math.ceil(group.length / columns);
    const usableTop = zone.y + 62;
    const usableHeight = zone.h - 96;
    const rowGap = usableHeight / Math.max(rows - 1, 1);
    group.forEach((node, index) => {
      const nodeId = String(node.id);
      const rawPorts = networkNodes?.[nodeId]?.exposed_ports ?? node.exposed_ports ?? [];
      const ports = Array.isArray(rawPorts) ? rawPorts.map((port) => Number(port)).filter((port) => Number.isFinite(port)) : [];
      const vulns = Object.keys(networkNodes?.[nodeId]?.vulnerabilities ?? node.vulnerabilities ?? {});
      const hint = NODE_POSITION_HINTS?.[zone.id]?.[nodeId.toLowerCase()];
      const column = index % columns;
      const row = Math.floor(index / columns);
      const x = hint
        ? zone.x + zone.w * hint.xRatio
        : columns === 1
          ? zone.x + zone.w / 2
          : zone.x + zone.w * (column === 0 ? 0.3 : 0.7);
      const y = hint
        ? zone.y + zone.h * hint.yRatio
        : rows === 1
          ? zone.y + zone.h / 2
          : usableTop + row * rowGap;
      configs[nodeId] = {
        id: nodeId,
        label: abbreviateNodeId(nodeId),
        sublabel: ports.length ? `:${ports[0]}` : "节点",
        zone: zone.id,
        x: Math.round(x),
        y: Math.round(y),
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
