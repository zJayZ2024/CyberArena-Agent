const STATUS_LABELS = {
  normal: "正常",
  online: "在线",
  scanning: "侦察中",
  compromised: "已失陷",
  defended: "已加固",
  hardened: "已加固",
  isolated: "已隔离",
  patched: "已修补",
  down: "离线",
};

const ROLE_LABELS = {
  red: "红方",
  RED: "红方",
  Red: "红方",
  blue: "蓝方",
  BLUE: "蓝方",
  Blue: "蓝方",
  sys: "系统",
  SYS: "系统",
  alert: "告警",
  ALERT: "告警",
  referee: "裁判",
  Referee: "裁判",
};

const ACTION_LABELS = {
  Recon: "侦察",
  ReconScan: "侦察扫描",
  ExploitService: "服务利用",
  LateralMove: "横向移动",
  LateralMovement: "横向移动",
  CredentialAbuse: "凭据滥用",
  CredentialDump: "凭据提取",
  DataExfiltration: "数据外传",
  ExfiltrateDatabase: "数据库外传",
  AnchorFoothold: "建立据点",
  PreventivePatch: "预防修补",
  PatchNode: "漏洞修补",
  RestoreNode: "恢复节点",
  DeepRestore: "深度恢复",
  Isolate: "隔离节点",
  Monitor: "监控",
  ResolveRound: "回合裁定",
  Action: "动作",
  PortScan: "端口扫描",
  Port: "端口",
  "Port Scan": "端口扫描",
  "SQL Injection": "SQL 注入",
  "Lateral Movement": "横向移动",
  "Credential Dump": "凭据提取",
  "Data Exfiltration": "数据外传",
  ids_update: "IDS 更新",
  firewall_rule: "防火墙规则",
  patch: "修补",
};

const PHASE_LABELS = {
  Setup: "准备",
  Recon: "侦察",
  Weaponize: "武器化",
  Exploit: "利用",
  LateralMove: "横向移动",
  Exfiltrate: "数据外传",
  recon: "侦察",
};

const SEVERITY_LABELS = {
  Critical: "严重",
  High: "高危",
  Medium: "中危",
  Low: "低危",
  CRIT: "严重",
  WARN: "警告",
  INFO: "信息",
  ERR: "错误",
};

const SCENARIO_NAME_LABELS = {
  "Level 1 Basic Web": "等级 1 基础网站",
  "Level 2 Ransomware": "等级 2 勒索传播",
  "Level 3 Multi-Step Intrusion": "等级 3 多阶段入侵",
  "Level 3 Enterprise Branch": "等级 3 企业分支",
  "Level 4 Cloud SaaS": "等级 4 云端软件服务",
  level_1_basic_web: "等级 1 基础网站",
  level_2_ransomware: "等级 2 勒索传播",
  level_3_enterprise_branch: "等级 3 企业分支",
  level_4_cloud_saas: "等级 4 云端软件服务",
};

const RELATIVE_TIME_LABELS = {
  "Live session": "实时会话",
  "14 mins ago": "14 分钟前",
  "39 mins ago": "39 分钟前",
  "1 hour ago": "1 小时前",
  "2 hours ago": "2 小时前",
};

export function translateStatus(value, fallback = "未知") {
  const key = String(value || "").trim();
  return STATUS_LABELS[key] || STATUS_LABELS[key.toLowerCase()] || fallback;
}

export function translateRole(value, fallback = "系统") {
  const key = String(value || "").trim();
  return ROLE_LABELS[key] || ROLE_LABELS[key.toLowerCase()] || fallback;
}

export function translateAction(value, fallback = "动作") {
  const key = String(value || "").trim();
  return ACTION_LABELS[key] || fallback;
}

export function translatePhase(value, fallback = "侦察") {
  const key = String(value || "").trim();
  return PHASE_LABELS[key] || fallback;
}

export function translateSeverity(value, fallback = "未知") {
  const key = String(value || "").trim();
  return SEVERITY_LABELS[key] || fallback;
}

export function translateScenarioName(value) {
  const key = String(value || "").trim();
  return SCENARIO_NAME_LABELS[key] || key || "未命名场景";
}

export function translateRelativeTime(value) {
  const key = String(value || "").trim();
  return RELATIVE_TIME_LABELS[key] || key;
}

export function translateWinner(value) {
  if (value === "Red") {
    return "红方";
  }
  if (value === "Blue") {
    return "蓝方";
  }
  return "平局";
}

export function translateDifficulty(value) {
  const key = String(value || "").trim();
  if (["Intro", "入门"].includes(key)) {
    return "入门";
  }
  if (["Intermediate", "中级"].includes(key)) {
    return "中级";
  }
  if (["Advanced", "高级"].includes(key)) {
    return "高级";
  }
  if (["Expert", "专家"].includes(key)) {
    return "专家";
  }
  return key || "未分级";
}

export function isSevere(value) {
  return ["Critical", "CRIT", "严重"].includes(String(value || "").trim());
}

export function isHighSeverity(value) {
  return ["High", "高危"].includes(String(value || "").trim());
}
