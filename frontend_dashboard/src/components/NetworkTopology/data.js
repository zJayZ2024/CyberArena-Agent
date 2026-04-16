import { NODE_CONFIGS } from "./constants";

export const DEFAULT_ROUNDS = [
  {
    round: 1,
    red_action: { technique: "Port Scan", target_node: "firewall", technique_id: "T1046", reasoning: "Initial recon - map open ports on internet-facing gateway before selecting attack vector." },
    judge_result: { success: true, damage: 5, logs: ["[WARN] Port scan detected: 254 probes/3s", "[INFO] Open: 80, 443, 22, 53"], node_status_change: "scanning", success_prob: 0.9 },
    blue_action: { type: "ids_update", target: "firewall", rule_or_code: "alert tcp any -> $HOME_NET any (msg:\"PortScan\"; detection_filter:track by_src,count 100,seconds 3;)", action_cost: 2, effectiveness: 0.6, reasoning: "IDS signature update to track scan pattern." },
    world_state: {
      round: 1,
      nodes: [
        { id: "web_server", status: "normal", attack_count: 0, defense_count: 0 },
        { id: "dns_server", status: "normal", attack_count: 0, defense_count: 0 },
        { id: "app_server", status: "normal", attack_count: 0, defense_count: 0 },
        { id: "admin_host", status: "normal", attack_count: 0, defense_count: 0 },
        { id: "database", status: "normal", attack_count: 0, defense_count: 0 },
        { id: "firewall", status: "scanning", attack_count: 1, defense_count: 0 },
      ],
      score: { red: 5, blue: 8 },
      red_phase: "Recon",
      availability: 1,
      blue_action_points: 1,
      special_event: null,
    },
  },
  {
    round: 2,
    red_action: { technique: "SQL Injection", target_node: "web_server", technique_id: "T1190", reasoning: "Port 80 is open. Attempt SQLi on login endpoint - highest yield given patch_level 0.5." },
    judge_result: { success: true, damage: 20, logs: ["[CRIT] SQLi on /api/login", "[WARN] Unusual DB queries from WEB_SERVER"], node_status_change: "compromised", success_prob: 0.72 },
    blue_action: { type: "firewall_rule", target: "web_server", rule_or_code: "iptables -A INPUT -p tcp --dport 80 -m limit --limit 30/min -j ACCEPT\n# Rate-limit HTTP", action_cost: 1, effectiveness: 0.55, reasoning: "Deploy HTTP rate-limit to slow injection attempts." },
    world_state: {
      round: 2,
      nodes: [
        { id: "web_server", status: "compromised", attack_count: 1, defense_count: 1 },
        { id: "dns_server", status: "normal", attack_count: 0, defense_count: 0 },
        { id: "app_server", status: "normal", attack_count: 0, defense_count: 0 },
        { id: "admin_host", status: "normal", attack_count: 0, defense_count: 0 },
        { id: "database", status: "normal", attack_count: 0, defense_count: 0 },
        { id: "firewall", status: "scanning", attack_count: 1, defense_count: 0 },
      ],
      score: { red: 25, blue: 16 },
      red_phase: "Exploit",
      availability: 0.96,
      blue_action_points: 2,
      special_event: null,
    },
  },
  {
    round: 3,
    red_action: { technique: "Lateral Movement", target_node: "app_server", technique_id: "T1021", reasoning: "Web server compromised. Pivot to app_server using stored credentials found in /var/www/config." },
    judge_result: { success: false, damage: 0, logs: ["[INFO] Lateral move attempt blocked", "[OK] WAF rule matched - connection dropped"], node_status_change: null, success_prob: 0.38 },
    blue_action: { type: "patch", target: "app_server", rule_or_code: "# Emergency patch applied\napt-get install --only-upgrade tomcat10\n# CVE-2023-1234 remediated", action_cost: 3, effectiveness: 0.9, reasoning: "App_server is likely next pivot target. Apply emergency patch while attack is still on web_server." },
    world_state: {
      round: 3,
      nodes: [
        { id: "web_server", status: "compromised", attack_count: 1, defense_count: 1 },
        { id: "dns_server", status: "normal", attack_count: 0, defense_count: 0 },
        { id: "app_server", status: "defended", attack_count: 1, defense_count: 1 },
        { id: "admin_host", status: "normal", attack_count: 0, defense_count: 0 },
        { id: "database", status: "normal", attack_count: 0, defense_count: 0 },
        { id: "firewall", status: "scanning", attack_count: 1, defense_count: 0 },
      ],
      score: { red: 25, blue: 42 },
      red_phase: "LateralMove",
      availability: 0.91,
      blue_action_points: 0,
      special_event: null,
    },
  },
  {
    round: 4,
    red_action: { technique: "Credential Dump", target_node: "admin_host", technique_id: "T1003", reasoning: "App_server patched. Try admin_host via SSH using credentials cached in web_server memory." },
    judge_result: { success: true, damage: 15, logs: ["[CRIT] Unauthorized SSH login to ADMIN_HOST", "[WARN] sudo commands executed", "[INFO] /etc/shadow accessed"], node_status_change: "compromised", success_prob: 0.61 },
    blue_action: { type: "ids_update", target: "database", rule_or_code: "alert tcp $INTERNAL_NET any -> $DB_SERVERS 3306 (msg:\"Suspicious DB Access\"; threshold:type both,track by_src,count 5,seconds 60;)", action_cost: 2, effectiveness: 0.75, reasoning: "Admin_host compromised - DB is now reachable. Pre-emptive IDS rule on DB port 3306." },
    world_state: {
      round: 4,
      nodes: [
        { id: "web_server", status: "compromised", attack_count: 1, defense_count: 1 },
        { id: "dns_server", status: "normal", attack_count: 0, defense_count: 0 },
        { id: "app_server", status: "defended", attack_count: 1, defense_count: 1 },
        { id: "admin_host", status: "compromised", attack_count: 1, defense_count: 0 },
        { id: "database", status: "normal", attack_count: 0, defense_count: 1 },
        { id: "firewall", status: "scanning", attack_count: 1, defense_count: 0 },
      ],
      score: { red: 40, blue: 52 },
      red_phase: "LateralMove",
      availability: 0.88,
      blue_action_points: 1,
      special_event: null,
    },
  },
  {
    round: 5,
    red_action: { technique: "Data Exfiltration", target_node: "database", technique_id: "T1041", reasoning: "Full path: web->admin->db. Using admin credentials to access MySQL 3306. Target: customer PII table." },
    judge_result: { success: true, damage: 35, logs: ["[CRIT] Bulk SELECT on users table - 50k rows", "[CRIT] Data exfil detected: 12MB outbound", "[ERR] Rate limit exceeded"], node_status_change: "compromised", success_prob: 0.68 },
    blue_action: { type: "firewall_rule", target: "database", rule_or_code: "iptables -I OUTPUT -p tcp --dport 443 -m owner --uid-owner mysql -j DROP\n# Block DB outbound", action_cost: 2, effectiveness: 0.8, reasoning: "Database actively exfiltrating. Emergency outbound block on mysql process traffic." },
    world_state: {
      round: 5,
      nodes: [
        { id: "web_server", status: "compromised", attack_count: 1, defense_count: 1 },
        { id: "dns_server", status: "normal", attack_count: 0, defense_count: 0 },
        { id: "app_server", status: "defended", attack_count: 1, defense_count: 1 },
        { id: "admin_host", status: "compromised", attack_count: 1, defense_count: 0 },
        { id: "database", status: "compromised", attack_count: 1, defense_count: 2 },
        { id: "firewall", status: "scanning", attack_count: 1, defense_count: 0 },
      ],
      score: { red: 75, blue: 62 },
      red_phase: "Exfiltrate",
      availability: 0.82,
      blue_action_points: 1,
      special_event: "zero_day",
    },
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
  const base = DEFAULT_ROUNDS[Math.min(fallbackIndex, DEFAULT_ROUNDS.length - 1)] ?? DEFAULT_ROUNDS[0];
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
    judge_result: { ...base.judge_result, ...(round?.judge_result ?? round?.judgeResult ?? {}) },
    world_state: {
      ...base.world_state,
      ...worldStateInput,
      round: roundNumber,
      nodes: normalizeNodes(worldStateInput.nodes ?? round?.nodes ?? base.world_state.nodes),
      score: {
        red: worldStateInput.score?.red ?? worldStateInput.red_score ?? round?.redScore ?? round?.red_score ?? base.world_state.score.red,
        blue: worldStateInput.score?.blue ?? worldStateInput.blue_score ?? round?.blueScore ?? round?.blue_score ?? base.world_state.score.blue,
      },
      red_phase: worldStateInput.red_phase ?? worldStateInput.redPhase ?? base.world_state.red_phase,
      availability: worldStateInput.availability ?? base.world_state.availability,
      blue_action_points: worldStateInput.blue_action_points ?? worldStateInput.blueActionPoints ?? base.world_state.blue_action_points,
      special_event: worldStateInput.special_event ?? worldStateInput.specialEvent ?? null,
    },
  };
}

export function normalizeRoundsPayload(payload) {
  const maybeRounds = Array.isArray(payload) ? payload : payload?.rounds ?? payload?.frames ?? (payload ? [payload] : []);
  if (!maybeRounds.length) {
    return DEFAULT_ROUNDS;
  }
  return maybeRounds.map((round, index) => normalizeRound(round, index, maybeRounds.length));
}
