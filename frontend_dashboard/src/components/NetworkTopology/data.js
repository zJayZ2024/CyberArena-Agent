export const DEFAULT_ROUNDS = [
  {
    round: 1,
    red_action: { technique: "Port Scan", target_node: "fw", technique_id: "T1046", reasoning: "初始侦察：在选择攻击向量前，先枚举面向互联网网关的开放端口。" },
    judge_result: { success: true, damage: 5, logs: ["[WARN] 检测到端口扫描：3 秒内 254 次探测", "[INFO] 开放端口：80、443、22、53"], node_status_change: "scanning", success_prob: 0.9 },
    blue_action: { type: "ids_update", target: "fw", rule_or_code: "alert tcp any -> $HOME_NET any (msg:\"PortScan\"; detection_filter:track by_src,count 100,seconds 3;)", action_cost: 2, effectiveness: 0.6, reasoning: "更新 IDS 签名以跟踪扫描模式。" },
    world_state: {
      round: 1,
      nodes: [
        { id: "internet", status: "Normal", attack_count: 0, defense_count: 0 },
        { id: "fw", status: "Scanning", attack_count: 1, defense_count: 0 },
        { id: "web", status: "Normal", attack_count: 0, defense_count: 0 },
        { id: "app", status: "Normal", attack_count: 0, defense_count: 0 },
        { id: "storage", status: "Normal", attack_count: 0, defense_count: 0 },
        { id: "db", status: "Normal", attack_count: 0, defense_count: 0 },
      ],
      score: { red: 5, blue: 8 },
      red_phase: "Recon",
      availability: 1,
      blue_action_points: 1,
      special_event: null,
    },
    action_logs: [],
    security_alerts: [],
    red_visible_nodes: ["internet", "fw", "web"],
    red_recon_nodes: [],
    red_known_services: { internet: [80, 443], fw: [443], web: [80, 443] },
    red_known_vulnerabilities: {},
  },
  {
    round: 2,
    red_action: { technique: "SQL Injection", target_node: "web", technique_id: "T1190", reasoning: "80 端口开放。尝试攻击登录接口的 SQL 注入，在当前 patch_level 0.5 下收益最高。" },
    judge_result: { success: true, damage: 20, logs: ["[CRIT] /api/login 出现 SQL 注入", "[WARN] WEB 发起异常数据库查询"], node_status_change: "compromised", success_prob: 0.72 },
    blue_action: { type: "firewall_rule", target: "web", rule_or_code: "iptables -A INPUT -p tcp --dport 80 -m limit --limit 30/min -j ACCEPT\n# Rate-limit HTTP", action_cost: 1, effectiveness: 0.55, reasoning: "部署 HTTP 限速规则以放缓注入尝试。" },
    world_state: {
      round: 2,
      nodes: [
        { id: "internet", status: "Normal", attack_count: 0, defense_count: 0 },
        { id: "fw", status: "Scanning", attack_count: 1, defense_count: 0 },
        { id: "web", status: "Compromised", attack_count: 1, defense_count: 1 },
        { id: "app", status: "Normal", attack_count: 0, defense_count: 0 },
        { id: "storage", status: "Normal", attack_count: 0, defense_count: 0 },
        { id: "db", status: "Normal", attack_count: 0, defense_count: 0 },
      ],
      score: { red: 25, blue: 16 },
      red_phase: "Exploit",
      availability: 0.96,
      blue_action_points: 2,
      special_event: null,
    },
    action_logs: [],
    security_alerts: [],
    red_visible_nodes: ["internet", "fw", "web"],
    red_recon_nodes: ["web"],
    red_known_services: { internet: [80, 443], fw: [443], web: [80, 443] },
    red_known_vulnerabilities: {},
  },
  {
    round: 3,
    red_action: { technique: "Lateral Movement", target_node: "app", technique_id: "T1021", reasoning: "Web 服务器已失陷。利用 /var/www/config 中发现的凭据向 app 横向移动。" },
    judge_result: { success: false, damage: 0, logs: ["[INFO] 横向移动尝试被阻断", "[OK] 命中 WAF 规则，连接已丢弃"], node_status_change: null, success_prob: 0.38 },
    blue_action: { type: "patch", target: "app", rule_or_code: "# Emergency patch applied\napt-get install --only-upgrade tomcat10\n# CVE-2023-1234 remediated", action_cost: 3, effectiveness: 0.9, reasoning: "app 很可能是下一个跳板目标，在攻击仍停留于 web 时执行紧急修补。" },
    world_state: {
      round: 3,
      nodes: [
        { id: "internet", status: "Normal", attack_count: 0, defense_count: 0 },
        { id: "fw", status: "Scanning", attack_count: 1, defense_count: 0 },
        { id: "web", status: "Compromised", attack_count: 1, defense_count: 1 },
        { id: "app", status: "Defended", attack_count: 1, defense_count: 1 },
        { id: "storage", status: "Normal", attack_count: 0, defense_count: 0 },
        { id: "db", status: "Normal", attack_count: 0, defense_count: 0 },
      ],
      score: { red: 25, blue: 42 },
      red_phase: "LateralMove",
      availability: 0.91,
      blue_action_points: 0,
      special_event: null,
    },
    action_logs: [],
    security_alerts: [],
    red_visible_nodes: ["internet", "fw", "web", "app"],
    red_recon_nodes: ["web"],
    red_known_services: { internet: [80, 443], fw: [443], web: [80, 443], app: [8080, 8443] },
    red_known_vulnerabilities: { web: { "CVE-2023-1234": { vuln_id: "CVE-2023-1234", severity: "High", score: 24, exploit_prob: 0.46, patch_prob: 0.58 } } },
  },
  {
    round: 4,
    red_action: { technique: "Credential Dump", target_node: "storage", technique_id: "T1003", reasoning: "app 已被修补。改用 web 内存中缓存的凭据，通过 SMB 尝试进入 storage。" },
    judge_result: { success: true, damage: 15, logs: ["[CRIT] STORAGE 出现未授权 SMB 登录", "[WARN] 执行了 sudo 命令", "[INFO] /etc/shadow 被访问"], node_status_change: "compromised", success_prob: 0.61 },
    blue_action: { type: "ids_update", target: "db", rule_or_code: "alert tcp $INTERNAL_NET any -> $DB_SERVERS 3306 (msg:\"Suspicious DB Access\"; threshold:type both,track by_src,count 5,seconds 60;)", action_cost: 2, effectiveness: 0.75, reasoning: "storage 已失陷，DB 已变得可达。提前在 DB 3306 端口部署 IDS 规则。" },
    world_state: {
      round: 4,
      nodes: [
        { id: "internet", status: "Normal", attack_count: 0, defense_count: 0 },
        { id: "fw", status: "Scanning", attack_count: 1, defense_count: 0 },
        { id: "web", status: "Compromised", attack_count: 1, defense_count: 1 },
        { id: "app", status: "Defended", attack_count: 1, defense_count: 1 },
        { id: "storage", status: "Compromised", attack_count: 1, defense_count: 0 },
        { id: "db", status: "Normal", attack_count: 0, defense_count: 1 },
      ],
      score: { red: 40, blue: 52 },
      red_phase: "LateralMove",
      availability: 0.88,
      blue_action_points: 1,
      special_event: null,
    },
    action_logs: [],
    security_alerts: [],
    red_visible_nodes: ["internet", "fw", "web", "app", "storage"],
    red_recon_nodes: ["web", "storage"],
    red_known_services: { internet: [80, 443], fw: [443], web: [80, 443], app: [8080, 8443], storage: [139, 445] },
    red_known_vulnerabilities: { web: { "CVE-2023-1234": { vuln_id: "CVE-2023-1234", severity: "High", score: 24, exploit_prob: 0.46, patch_prob: 0.58 } } },
  },
  {
    round: 5,
    red_action: { technique: "Data Exfiltration", target_node: "db", technique_id: "T1041", reasoning: "完整路径为 web->storage->db。使用 storage 凭据访问 MySQL 3306，目标是客户 PII 表。" },
    judge_result: { success: true, damage: 35, logs: ["[CRIT] users 表出现批量 SELECT，约 5 万行", "[CRIT] 检测到数据外传：12MB 出站", "[ERR] 超出速率限制"], node_status_change: "compromised", success_prob: 0.68 },
    blue_action: { type: "firewall_rule", target: "db", rule_or_code: "iptables -I OUTPUT -p tcp --dport 443 -m owner --uid-owner mysql -j DROP\n# Block DB outbound", action_cost: 2, effectiveness: 0.8, reasoning: "数据库正在主动外传。紧急阻断 mysql 进程的出站流量。" },
    world_state: {
      round: 5,
      nodes: [
        { id: "internet", status: "Normal", attack_count: 0, defense_count: 0 },
        { id: "fw", status: "Scanning", attack_count: 1, defense_count: 0 },
        { id: "web", status: "Compromised", attack_count: 1, defense_count: 1 },
        { id: "app", status: "Defended", attack_count: 1, defense_count: 1 },
        { id: "storage", status: "Compromised", attack_count: 1, defense_count: 0 },
        { id: "db", status: "Compromised", attack_count: 1, defense_count: 2 },
      ],
      score: { red: 75, blue: 62 },
      red_phase: "Exfiltrate",
      availability: 0.82,
      blue_action_points: 1,
      special_event: "zero_day",
    },
    action_logs: [],
    security_alerts: [],
    red_visible_nodes: ["internet", "fw", "web", "app", "storage", "db"],
    red_recon_nodes: ["web", "storage", "db"],
    red_known_services: { internet: [80, 443], fw: [443], web: [80, 443], app: [8080, 8443], storage: [139, 445], db: [3306, 5432] },
    red_known_vulnerabilities: { web: { "CVE-2023-1234": { vuln_id: "CVE-2023-1234", severity: "High", score: 24, exploit_prob: 0.46, patch_prob: 0.58 } }, storage: { "CVE-2020-1472": { vuln_id: "CVE-2020-1472", severity: "Critical", score: 29, exploit_prob: 0.47, patch_prob: 0.52 } } },
  },
];

const LEGACY_FALLBACK_EDGES = [
  ["internet", "fw"],
  ["fw", "web"],
  ["web", "app"],
  ["app", "storage"],
  ["storage", "db"],
  ["app", "db"],
];

const SCENARIO_EDGE_FALLBACKS = {
  level_5_hybrid_identity_crisis: [
    ["internet", "fw"],
    ["fw", "web"],
    ["fw", "vpn"],
    ["fw", "soc"],
    ["web", "app"],
    ["web", "api"],
    ["web", "ci"],
    ["vpn", "office_pc"],
    ["office_pc", "dev"],
    ["office_pc", "identity"],
    ["office_pc", "finance_pc"],
    ["identity", "finance_pc"],
    ["identity", "dev"],
    ["identity", "soc"],
    ["finance_pc", "storage"],
    ["dev", "ci"],
    ["dev", "app"],
    ["dev", "storage"],
    ["ci", "app"],
    ["api", "app"],
    ["api", "storage"],
    ["app", "storage"],
    ["app", "db"],
    ["storage", "backup"],
    ["storage", "db"],
    ["backup", "db"],
    ["soc", "db"],
  ],
};

function cloneData(value) {
  if (value === undefined || value === null) {
    return value;
  }
  return JSON.parse(JSON.stringify(value));
}

function normalizeVulnerabilities(vulnerabilities = {}) {
  if (Array.isArray(vulnerabilities)) {
    return vulnerabilities.reduce((mapped, vuln) => {
      const vulnId = String(vuln || "").trim();
      if (vulnId) {
        mapped[vulnId] = { vuln_id: vulnId };
      }
      return mapped;
    }, {});
  }
  if (vulnerabilities && typeof vulnerabilities === "object") {
    return vulnerabilities;
  }
  return {};
}

function normalizeNetworkNodeMap(networkNodes = {}) {
  if (!networkNodes || typeof networkNodes !== "object" || Array.isArray(networkNodes)) {
    return {};
  }
  return Object.fromEntries(
    Object.entries(networkNodes).map(([id, node]) => [
      id,
      {
        ...(node || {}),
        status: node?.status ?? "Normal",
        exposed_ports: Array.isArray(node?.exposed_ports) ? node.exposed_ports : [],
        vulnerabilities: normalizeVulnerabilities(node?.vulnerabilities),
      },
    ]),
  );
}

function normalizeNodes(nodes = [], networkNodes = {}) {
  const normalized = new Map();

  if (Array.isArray(nodes)) {
    nodes.forEach((row) => {
      if (!row || typeof row !== "object") {
        return;
      }
      const id = String(row.id ?? row.node_id ?? row.name ?? "").trim();
      if (!id) {
        return;
      }
      normalized.set(id, { id, ...row });
    });
  }

  if (networkNodes && typeof networkNodes === "object" && !Array.isArray(networkNodes)) {
    Object.entries(networkNodes).forEach(([id, payload]) => {
      const current = normalized.get(id) ?? { id };
      normalized.set(id, { ...current, ...(payload || {}), id });
    });
  }

  return Array.from(normalized.values())
    .sort((a, b) => String(a.id).localeCompare(String(b.id)))
    .map((next) => ({
      id: String(next.id),
      status: next.status ?? "Normal",
      attack_count: next.attack_count ?? next.attackCount ?? 0,
      defense_count: next.defense_count ?? next.defenseCount ?? 0,
      ...next,
    }));
}

function buildNetworkNodeMap(nodes = [], networkNodes = {}) {
  if (networkNodes && Object.keys(networkNodes).length) {
    return normalizeNetworkNodeMap(networkNodes);
  }
  const mapped = {};
  nodes.forEach((node) => {
    if (!node?.id) {
      return;
    }
    mapped[node.id] = {
      status: node.status ?? "Normal",
      exposed_ports: node.exposed_ports ?? [],
      vulnerabilities: normalizeVulnerabilities(node.vulnerabilities),
    };
  });
  return mapped;
}

function nodeRowsFromMap(nodes = {}) {
  return Object.entries(nodes || {}).map(([id, node]) => ({ id, ...(node || {}) }));
}

function normalizeEdges(edges = [], nodeIds = []) {
  const nodeSet = new Set(nodeIds);
  const normalized = [];
  const seen = new Set();

  const addEdge = (source, target) => {
    const src = String(source || "").trim();
    const dst = String(target || "").trim();
    if (!src || !dst || src === dst) {
      return;
    }
    if (nodeSet.size && (!nodeSet.has(src) || !nodeSet.has(dst))) {
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
        addEdge(edge[0], edge[1]);
        return;
      }
      if (typeof edge === "object") {
        addEdge(edge.source, edge.target);
      }
    });
  }

  if (!normalized.length) {
    LEGACY_FALLBACK_EDGES.forEach(([source, target]) => addEdge(source, target));
  }

  if (!normalized.length && nodeIds.length > 1) {
    nodeIds
      .slice()
      .sort((a, b) => String(a).localeCompare(String(b)))
      .forEach((id, index, list) => {
        if (index < list.length - 1) {
          addEdge(id, list[index + 1]);
        }
      });
  }

  return normalized;
}

function resolveInitialEdges(payload, nodeIds = []) {
  const scenario = payload?.meta?.scenario ?? payload?.scenario ?? "";
  const directEdges = payload?.edges
    ?? payload?.initial_edges
    ?? payload?.initial_topology_edges
    ?? payload?.topology?.edges
    ?? [];
  const fallbackEdges = SCENARIO_EDGE_FALLBACKS[scenario] ?? [];
  return normalizeEdges(Array.isArray(directEdges) && directEdges.length ? directEdges : fallbackEdges, nodeIds);
}

function applyLiteDelta(networkNodes, delta = {}) {
  const next = cloneData(networkNodes) ?? {};
  const ensureNode = (nodeId) => {
    if (!nodeId) {
      return null;
    }
    if (!next[nodeId]) {
      next[nodeId] = { status: "Normal", exposed_ports: [], vulnerabilities: {} };
    }
    if (!next[nodeId].vulnerabilities || Array.isArray(next[nodeId].vulnerabilities)) {
      next[nodeId].vulnerabilities = normalizeVulnerabilities(next[nodeId].vulnerabilities);
    }
    return next[nodeId];
  };

  (delta.node_status_changes ?? []).forEach((change) => {
    const nodeId = String(change?.node ?? change?.target ?? "").trim();
    const node = ensureNode(nodeId);
    if (node) {
      node.status = change?.to ?? node.status ?? "Normal";
    }
  });

  (delta.vulnerability_changes ?? []).forEach((change) => {
    const nodeId = String(change?.node ?? change?.target ?? "").trim();
    const node = ensureNode(nodeId);
    if (!node) {
      return;
    }
    (change?.removed ?? []).forEach((vulnId) => {
      delete node.vulnerabilities[vulnId];
    });
    (change?.added ?? []).forEach((vulnId) => {
      if (vulnId) {
        node.vulnerabilities[vulnId] = node.vulnerabilities[vulnId] ?? { vuln_id: vulnId };
      }
    });
  });

  return normalizeNetworkNodeMap(next);
}

function expandLitePayload(payload) {
  const liteRounds = Array.isArray(payload?.rounds) ? payload.rounds : [];
  const initialTopology = normalizeNetworkNodeMap(payload?.initial_topology);
  if (!liteRounds.length || !Object.keys(initialTopology).length) {
    return null;
  }

  const nodeIds = Object.keys(initialTopology);
  const edges = resolveInitialEdges(payload, nodeIds);
  let currentNodes = initialTopology;

  return liteRounds.map((round, index) => {
    currentNodes = applyLiteDelta(currentNodes, round?.delta ?? {});
    const state = round?.state ?? {};
    const redScore = state.red_score ?? round?.red_score ?? 0;
    const blueScore = state.blue_score ?? round?.blue_score ?? 0;
    const networkNodes = cloneData(currentNodes);
    const nodes = nodeRowsFromMap(networkNodes);

    return {
      ...round,
      round: round?.round ?? round?.turn ?? index + 1,
      total_rounds: payload?.meta?.total_rounds ?? liteRounds.length,
      red_action: {
        ...(round?.red_action ?? {}),
        target_node: round?.red_action?.target_node ?? round?.red_action?.target,
        technique: round?.red_action?.technique ?? round?.red_action?.action_type,
      },
      blue_action: {
        ...(round?.blue_action ?? {}),
        type: round?.blue_action?.type ?? round?.blue_action?.action_type,
      },
      judge_result: {
        ...(round?.judge_result ?? {}),
        success: round?.red_action?.effect ? !["blocked", "failed", "rejected"].includes(String(round.red_action.effect).toLowerCase()) : null,
        narrative: round?.adjudication?.summary ?? round?.judge_result?.narrative ?? "",
        score_summary: round?.score_delta ?? round?.judge_result?.score_summary ?? {},
      },
      network_nodes: networkNodes,
      nodes,
      edges,
      world_state: {
        ...(round?.world_state ?? {}),
        ...(state ?? {}),
        network_nodes: networkNodes,
        nodes,
        edges,
        score: { red: redScore, blue: blueScore },
        red_score: redScore,
        blue_score: blueScore,
        system_health: state.system_health,
        exposure_level: state.exposure_level,
        availability: typeof state.system_health === "number" ? Math.max(0, Math.min(1, state.system_health / 100)) : 1,
      },
    };
  });
}

function inferRedPhase(redAction, actionLogs) {
  const redLog = actionLogs?.find((l) => l.agent_type === "Red" || l.metadata?.agent_type === "Red");
  const actionType = redAction?.action_type || redLog?.action_type || redLog?.metadata?.action_type || "";
  const techniqueId = redAction?.technique_id || "";

  if (actionType === "Recon" || techniqueId === "T1046") return "Recon";
  if (actionType === "ExploitService" || techniqueId.startsWith("T1")) return "Exploit";
  if (actionType === "LateralMovement" || actionType === "LateralMove" || techniqueId === "T1021" || techniqueId === "T1003") return "LateralMove";
  if (actionType === "DataExfiltration" || actionType === "ExfiltrateDatabase" || techniqueId === "T1041") return "Exfiltrate";
  return "Recon";
}

function extractActionsFromLogs(actionLogs) {
  const redLog = actionLogs.find((l) => l.agent_type === "Red" || l.metadata?.agent_type === "Red");
  const blueLog = actionLogs.find((l) => l.agent_type === "Blue" || l.metadata?.agent_type === "Blue");
  const refLog = actionLogs.find((l) => l.agent_type === "Referee" || l.metadata?.agent_type === "Referee");
  const redMeta = redLog?.metadata || {};
  const blueMeta = blueLog?.metadata || {};
  const refMeta = refLog?.metadata || {};

  const redAction = redLog
    ? {
        technique: redLog.action_type,
        target_node: redMeta.target,
        technique_id: redMeta.vuln_id || redLog.action_type,
        reasoning: redLog.thought,
        action_type: redLog.action_type,
        payload: redLog.payload,
        pivot_source: redMeta.pivot_source,
      }
    : {};

  const blueAction = blueLog
    ? {
        type: blueLog.action_type,
        target: blueMeta.target,
        reasoning: blueLog.thought,
        action_cost: blueMeta.score_value ?? blueMeta.score_awarded ?? 0,
        effectiveness: blueMeta.interception_bonus ? blueMeta.interception_bonus / 10 : 0.5,
        rule_or_code: blueLog.payload,
      }
    : {};

  const judgeResult = {
    success: redMeta.intercepted !== true,
    damage: redMeta.score_value ?? redMeta.score_awarded ?? 0,
    logs: (refMeta.recent_alerts || []).map((a) => a.message),
    narrative: redLog?.referee_result || "",
    success_prob: redMeta.probability ?? redMeta.exploit_prob ?? null,
    score_summary: refMeta.score_summary || {},
  };

  return { redAction, blueAction, judgeResult };
}

function normalizeRound(round, fallbackIndex, totalRounds) {
  const base = DEFAULT_ROUNDS[Math.min(fallbackIndex, DEFAULT_ROUNDS.length - 1)] ?? DEFAULT_ROUNDS[0];
  const worldStateInput = round?.world_state ?? round?.worldState ?? {};
  const roundNumber = round?.round ?? round?.turn ?? worldStateInput.round ?? fallbackIndex + 1;
  const actionLogs = round?.action_logs ?? round?.actionLogs ?? [];
  const refereeMetadata = Array.isArray(actionLogs)
    ? actionLogs.find((log) => log?.agent_type === "Referee" || log?.metadata?.agent_type === "Referee")?.metadata ?? {}
    : {};
  const rawNetworkNodes = round?.network_nodes ?? worldStateInput.network_nodes ?? worldStateInput.networkNodes ?? {};

  const legacyRedAction = round?.red_action ?? round?.redAction ?? {};
  const legacyBlueAction = round?.blue_action ?? round?.blueAction ?? {};
  const legacyJudgeResult = round?.judge_result ?? round?.judgeResult ?? {};
  const hasLegacyActions = !!(round?.red_action || round?.redAction || round?.blue_action || round?.blueAction || round?.judge_result || round?.judgeResult);
  const hasActionLogs = Array.isArray(actionLogs) && actionLogs.length > 0;
  const extracted = hasLegacyActions
    ? { redAction: legacyRedAction, blueAction: legacyBlueAction, judgeResult: legacyJudgeResult }
    : hasActionLogs
      ? extractActionsFromLogs(actionLogs)
      : { redAction: {}, blueAction: {}, judgeResult: {} };

  const redAction = { ...(extracted.redAction ?? {}) };
  const blueAction = { ...(extracted.blueAction ?? {}) };

  if (!redAction.target_node && redAction.target) {
    redAction.target_node = redAction.target;
  }
  if (!blueAction.target && blueAction.target_node) {
    blueAction.target = blueAction.target_node;
  }

  const scoreRed = worldStateInput.score?.red ?? worldStateInput.red_score ?? round?.red_score ?? round?.redScore ?? base.world_state.score.red;
  const scoreBlue = worldStateInput.score?.blue ?? worldStateInput.blue_score ?? round?.blue_score ?? round?.blueScore ?? base.world_state.score.blue;
  const redPhase = worldStateInput.red_phase ?? worldStateInput.redPhase ?? inferRedPhase(redAction, actionLogs);

  const judgePayload = extracted.judgeResult ?? {};
  const judgeResult = {
    success: typeof judgePayload.success === "boolean" ? judgePayload.success : null,
    damage: Number.isFinite(judgePayload.damage) ? judgePayload.damage : 0,
    logs: Array.isArray(judgePayload.logs) ? judgePayload.logs : [],
    narrative: judgePayload.narrative ?? "",
    score_summary: judgePayload.score_summary ?? {},
    ...judgePayload,
  };

  const normalizedNodes = normalizeNodes(
    worldStateInput.nodes ?? worldStateInput.networkNodes ?? round?.nodes,
    rawNetworkNodes,
  );
  const normalizedNetworkNodes = buildNetworkNodeMap(normalizedNodes, rawNetworkNodes);
  const normalizedEdges = normalizeEdges(
    round?.edges ?? worldStateInput.edges ?? [],
    normalizedNodes.map((node) => node.id),
  );

  return {
    ...base,
    ...round,
    round: roundNumber,
    total_rounds: round?.total_rounds ?? round?.totalRounds ?? totalRounds,
    red_action: redAction,
    blue_action: blueAction,
    judge_result: judgeResult,
    referee_flow: round?.referee_flow ?? refereeMetadata.referee_flow ?? {},
    world_state: {
      ...base.world_state,
      ...worldStateInput,
      round: roundNumber,
      nodes: normalizedNodes,
      network_nodes: normalizedNetworkNodes,
      edges: normalizedEdges,
      score: { red: scoreRed, blue: scoreBlue },
      red_phase: redPhase,
      availability: worldStateInput.availability ?? base.world_state.availability,
      blue_action_points: worldStateInput.blue_action_points ?? worldStateInput.blueActionPoints ?? base.world_state.blue_action_points,
      special_event: worldStateInput.special_event ?? worldStateInput.specialEvent ?? null,
      system_health: worldStateInput.system_health ?? round?.system_health ?? base.world_state.system_health,
      exposure_level: worldStateInput.exposure_level ?? round?.exposure_level ?? base.world_state.exposure_level,
    },
    network_nodes: normalizedNetworkNodes,
    edges: normalizedEdges,
    action_logs: actionLogs,
    security_alerts: round?.security_alerts ?? round?.securityAlerts ?? base.security_alerts ?? [],
    red_visible_nodes: round?.red_visible_nodes ?? round?.redVisibleNodes ?? base.red_visible_nodes ?? [],
    red_recon_nodes: round?.red_recon_nodes ?? round?.redReconNodes ?? base.red_recon_nodes ?? [],
    red_known_services: round?.red_known_services ?? round?.redKnownServices ?? base.red_known_services ?? {},
    red_known_vulnerabilities: round?.red_known_vulnerabilities ?? round?.redKnownVulnerabilities ?? base.red_known_vulnerabilities ?? {},
  };
}

export function normalizeRoundsPayload(payload) {
  const expandedLiteRounds = expandLitePayload(payload);
  const maybeRounds = Array.isArray(payload)
    ? payload
    : expandedLiteRounds ?? payload?.frames ?? payload?.rounds ?? (payload ? [payload] : []);
  if (!maybeRounds.length) {
    return DEFAULT_ROUNDS;
  }

  const payloadDeclaredTotal = Number(payload?.total_rounds ?? payload?.totalRounds);
  const inferredMaxTurn = maybeRounds
    .map((round) => Number(round?.round ?? round?.turn))
    .filter((value) => Number.isFinite(value))
    .reduce((max, value) => Math.max(max, value), Number.NEGATIVE_INFINITY);

  const normalizedTotalRounds = Number.isFinite(payloadDeclaredTotal) && payloadDeclaredTotal > 0
    ? payloadDeclaredTotal
    : Number.isFinite(inferredMaxTurn) && inferredMaxTurn > 0
      ? inferredMaxTurn
      : maybeRounds.length;

  return maybeRounds.map((round, index) => normalizeRound(round, index, normalizedTotalRounds));
}
