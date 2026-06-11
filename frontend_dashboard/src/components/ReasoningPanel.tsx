import { useEffect, useMemo, useState } from "react";

import { translateAction } from "../utils/localization";

type ReasoningPanelProps = {
  round?: any;
  nextRound?: any;
};

type FlowStep = {
  id: string;
  number: number;
  label: string;
  short: string;
  tone: string;
};

const FLOW_STEPS: FlowStep[] = [
  { id: "start", number: 1, label: "开始快照", short: "开始", tone: "text-sky-300" },
  { id: "red", number: 2, label: "红方前置条件", short: "红方", tone: "text-red-300" },
  { id: "blue", number: 3, label: "蓝方前置条件", short: "蓝方", tone: "text-blue-300" },
  { id: "attack", number: 4, label: "Attack Graph 推进", short: "推进", tone: "text-violet-300" },
  { id: "conflict", number: 5, label: "同回合冲突", short: "冲突", tone: "text-amber-300" },
  { id: "changes", number: 6, label: "状态与分数变化", short: "变化", tone: "text-emerald-300" },
  { id: "end", number: 7, label: "结束快照", short: "结束", tone: "text-cyan-300" },
];

const EMPTY = "暂无数据";

function normalizeRole(value: string) {
  return String(value || "").trim().toLowerCase();
}

function findLog(round: any, role: string) {
  const logs = Array.isArray(round?.action_logs) ? round.action_logs : [];
  return logs.find((log: any) => normalizeRole(log?.agent_type || log?.metadata?.agent_type) === role);
}

function cleanText(value: unknown, maxLength = 260) {
  const text = String(value ?? "").replace(/\s+/g, " ").trim();
  if (!text) return EMPTY;
  return text.length > maxLength ? `${text.slice(0, maxLength)}...` : text;
}

function listOf(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value
      .map((item) => typeof item === "object" ? item?.target || item?.action || item?.name || JSON.stringify(item) : item)
      .filter(Boolean)
      .map(String);
  }
  return value === undefined || value === null || value === "" ? [] : [String(value)];
}

function formatValue(value: unknown) {
  if (typeof value === "boolean") return value ? "是" : "否";
  if (Array.isArray(value)) return value.length ? value.join("、") : EMPTY;
  if (value && typeof value === "object") return JSON.stringify(value);
  return String(value ?? EMPTY);
}

function passLabel(value: unknown) {
  if (value === true) return "通过";
  if (value === false) return "未通过";
  return "未判定";
}

function targetOf(log: any, action: any) {
  return log?.metadata?.target || action?.target || action?.target_node || "";
}

function actionOf(log: any, action: any) {
  return action?.action_type || action?.type || action?.technique || log?.action_type || "";
}

function latestReflection(reflections: any) {
  return Array.isArray(reflections) && reflections.length ? reflections[reflections.length - 1] : null;
}

function policyRelation(policy: any, nextActionName: string, nextTarget: string, nextVulnId: string, hasNextRound: boolean) {
  if (!hasNextRound) return "暂无下一回合动作";
  if (!policy || Object.keys(policy).length === 0) return "本回合没有执行约束";
  const avoided = Array.isArray(policy?.avoid_exact) ? policy.avoid_exact : [];
  const repeatsAvoided = avoided.some((item: any) =>
    item?.action_type === nextActionName
    && item?.target === nextTarget
    && (!item?.vuln_id || item?.vuln_id === nextVulnId)
  );
  const repeatsLast = policy?.require_change
    && policy?.last_action_type === nextActionName
    && policy?.last_target === nextTarget;
  if (repeatsAvoided || repeatsLast) return `未遵循：重复 ${nextActionName || "动作"} → ${nextTarget || "无目标"}`;

  const preferredActions = listOf(policy?.prefer_action_types);
  const preferredTargets = listOf(policy?.prefer_targets);
  const matchedAction = preferredActions.includes(nextActionName);
  const matchedTarget = preferredTargets.includes(nextTarget);
  if (matchedAction || matchedTarget || policy?.require_change) {
    return `已遵循：${nextActionName || "动作"} → ${nextTarget || "无目标"}`;
  }
  return `无冲突：${nextActionName || "动作"} → ${nextTarget || "无目标"}`;
}

function Tags({ values, tone = "slate" }: { values: unknown; tone?: "slate" | "red" | "blue" | "violet" | "amber" | "emerald" }) {
  const items = listOf(values);
  const styles = {
    slate: "border-white/[0.12] bg-[#1c2d4a] text-slate-300",
    red: "border-red-400/30 bg-red-500/10 text-red-200",
    blue: "border-blue-400/30 bg-blue-500/10 text-blue-200",
    violet: "border-violet-400/30 bg-violet-500/10 text-violet-200",
    amber: "border-amber-400/30 bg-amber-500/10 text-amber-200",
    emerald: "border-emerald-400/30 bg-emerald-500/10 text-emerald-200",
  };
  if (!items.length) return <span className="text-xs text-slate-500">无</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((item, index) => (
        <span key={`${item}-${index}`} className={`rounded-md border px-2 py-1 font-mono text-[10px] leading-4 ${styles[tone]}`}>
          {item}
        </span>
      ))}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[76px_1fr] gap-3 border-t border-white/[0.08] py-2.5 first:border-0 first:pt-0">
      <span className="font-mono text-[10px] leading-5 text-slate-500">{label}</span>
      <div className="min-w-0 text-xs leading-5 text-slate-300">{children}</div>
    </div>
  );
}

function SnapshotView({ snapshot, compare }: { snapshot: any; compare?: any }) {
  const health = snapshot?.system_health ?? snapshot?.health;
  const exposure = snapshot?.exposure ?? snapshot?.exposure_level;
  const metric = (value: unknown, previous: unknown, suffix = "%") => {
    const currentNumber = Number(value);
    const previousNumber = Number(previous);
    const delta = Number.isFinite(currentNumber) && Number.isFinite(previousNumber) ? currentNumber - previousNumber : null;
    return (
      <div className="rounded-xl border border-white/[0.12] bg-[#162340] p-3">
        <div className="font-mono text-2xl font-semibold text-[#f0f4ff]">{value ?? "--"}{value !== undefined ? suffix : ""}</div>
        {delta !== null && delta !== 0 ? (
          <div className={`mt-1 font-mono text-[10px] ${delta > 0 ? "text-emerald-300" : "text-red-300"}`}>{delta > 0 ? "+" : ""}{delta}{suffix}</div>
        ) : <div className="mt-1 font-mono text-[10px] text-slate-500">基准态势</div>}
      </div>
    );
  };
  return (
    <div>
      <div className="grid grid-cols-2 gap-2">
        <div>
          <p className="mb-1.5 font-mono text-[9px] uppercase tracking-[0.14em] text-slate-500">系统健康</p>
          {metric(health, compare?.system_health ?? compare?.health)}
        </div>
        <div>
          <p className="mb-1.5 font-mono text-[9px] uppercase tracking-[0.14em] text-slate-500">暴露度</p>
          {metric(exposure, compare?.exposure ?? compare?.exposure_level)}
        </div>
      </div>
      <div className="mt-3">
        <Field label="活跃会话"><Tags values={snapshot?.active_sessions ?? snapshot?.sessions} tone="red" /></Field>
        <Field label="立足点"><Tags values={snapshot?.footholds} tone="red" /></Field>
        <Field label="持久化节点"><Tags values={snapshot?.persistence_nodes ?? snapshot?.persistence} tone="violet" /></Field>
        <Field label="隔离节点"><Tags values={snapshot?.isolated_nodes ?? snapshot?.isolated} tone="slate" /></Field>
        <Field label="监控节点"><Tags values={snapshot?.monitored_nodes ?? snapshot?.monitored} tone="blue" /></Field>
        <Field label="失陷节点"><Tags values={snapshot?.compromised_nodes ?? snapshot?.compromised} tone="red" /></Field>
      </div>
    </div>
  );
}

function PreconditionView({ data, tone }: { data: any; tone: "red" | "blue" }) {
  const passed = data?.passed ?? data?.allowed ?? data?.success;
  const action = data?.action ?? data?.action_type;
  const target = data?.target ?? data?.target_node;
  const badge = passed === true
    ? "border-emerald-400/40 bg-emerald-500/10 text-emerald-200"
    : passed === false
      ? "border-red-400/40 bg-red-500/10 text-red-200"
      : "border-white/[0.12] bg-[#1c2d4a] text-slate-300";
  return (
    <div>
      <div className="flex items-start justify-between gap-3 rounded-xl border border-white/[0.12] bg-[#162340] p-3">
        <div>
          <p className={`font-mono text-[10px] uppercase tracking-[0.14em] ${tone === "red" ? "text-red-300" : "text-blue-300"}`}>动作 / 目标</p>
          <p className="mt-1.5 text-sm font-medium text-[#f0f4ff]">{translateAction(action, action || EMPTY)}</p>
          <p className="mt-1 font-mono text-[10px] text-slate-400">{target || "无目标"}</p>
        </div>
        <span className={`rounded-md border px-2 py-1 font-mono text-[10px] ${badge}`}>{passLabel(passed)}</span>
      </div>
      <div className="mt-3">
        <Field label="Pivot 来源"><Tags values={data?.pivot_source ?? data?.pivot_candidates ?? data?.pivot_sources ?? data?.source} tone={tone} /></Field>
        <Field label="验证结果">{cleanText(data?.validation_result ?? data?.validation ?? data?.check_result)}</Field>
        <Field label="执行结果">{cleanText(data?.execution_result ?? data?.execution ?? data?.effect ?? data?.result)}</Field>
        <Field label="判定原因">{cleanText(data?.reason ?? data?.failure_reason ?? data?.success_reason)}</Field>
      </div>
    </div>
  );
}

function AttackGraphView({ data }: { data: any }) {
  const progressed = data?.progressed;
  return (
    <div>
      <div className="rounded-xl border border-violet-400/30 bg-violet-500/[0.07] p-3">
        <div className="flex items-center justify-between gap-3">
          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-violet-300">{data?.phase || "Attack Graph"}</span>
          <span className={`rounded-md border px-2 py-1 font-mono text-[10px] ${progressed ? "border-emerald-400/40 text-emerald-200" : "border-red-400/40 text-red-200"}`}>
            {progressed ? "已推进" : "未推进"}
          </span>
        </div>
        <p className="mt-2 text-sm font-medium text-[#f0f4ff]">{data?.technique || EMPTY}</p>
        <p className="mt-2 font-mono text-xs text-violet-200">{data?.source || "?"} <span className="text-slate-500">→</span> {data?.target || "?"}</p>
      </div>
      <div className="mt-3">
        <Field label="推进结果">{cleanText(data?.result)}</Field>
        <Field label="允许执行">{formatValue(data?.allowed)}</Field>
        <Field label="成功层级">{formatValue(data?.success_level)}</Field>
        <Field label="阻断条件"><Tags values={data?.active_blockers} tone="amber" /></Field>
      </div>
    </div>
  );
}

function ConflictView({ data }: { data: any }) {
  if (!data || Object.keys(data).length === 0) {
    return <EmptyState text="本回合没有同目标冲突" />;
  }
  const red = data?.red_action ?? {};
  const blue = data?.blue_action ?? {};
  const redAction = typeof red === "string" ? red : actionOf(null, red) || formatValue(red);
  const blueAction = typeof blue === "string" ? blue : actionOf(null, blue) || formatValue(blue);
  const redTarget = data?.red_target ?? targetOf(null, red);
  const blueTarget = data?.blue_target ?? targetOf(null, blue);
  return (
    <div>
      <div className="rounded-xl border border-amber-400/35 bg-amber-500/[0.07] p-3">
        <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-amber-300">冲突类型</p>
        <p className="mt-2 text-sm font-medium text-[#f0f4ff]">{data?.type || data?.conflict_type || EMPTY}</p>
      </div>
      <div className="mt-3">
        <Field label="红方动作">{redAction}{redTarget ? `(${redTarget})` : ""}</Field>
        <Field label="蓝方动作">{blueAction}{blueTarget ? `(${blueTarget})` : ""}</Field>
        <Field label="裁判规则">{cleanText(data?.matrix_rule ?? data?.rule)}</Field>
        <Field label="冲突结果">{cleanText(data?.explanation ?? data?.result)}</Field>
      </div>
    </div>
  );
}

function ChangesView({ stateChanges, scoreChanges }: { stateChanges: any; scoreChanges: any }) {
  const changes = Array.isArray(stateChanges) ? stateChanges : [];
  const scoreRows = [
    { role: "红方", value: scoreChanges?.red ?? scoreChanges?.red_delta, reason: scoreChanges?.red_reason ?? scoreChanges?.red_breakdown?.reason, tone: "text-red-300" },
    { role: "蓝方", value: scoreChanges?.blue ?? scoreChanges?.blue_delta, reason: scoreChanges?.blue_reason ?? scoreChanges?.blue_breakdown?.reason, tone: "text-blue-300" },
  ];
  return (
    <div className="space-y-3">
      <div>
        <p className="mb-2 font-mono text-[9px] uppercase tracking-[0.16em] text-slate-500">状态变化</p>
        <div className="space-y-1.5">
          {changes.length ? changes.map((change: any, index: number) => (
            <div key={`${change?.node}-${change?.field}-${index}`} className="rounded-lg border border-white/[0.1] bg-[#162340] px-3 py-2">
              <p className="font-mono text-[10px] text-[#f0f4ff]">{change?.node || change?.target || "节点"}.{change?.scope ? `${change.scope}.` : ""}{change?.field || change?.path || "state"}</p>
              <p className="mt-1 font-mono text-[10px] text-slate-400">{formatValue(change?.from ?? change?.old_value)} <span className="text-amber-300">→</span> {formatValue(change?.to ?? change?.new_value)}</p>
            </div>
          )) : <EmptyState text="本回合没有状态变化" compact />}
        </div>
      </div>
      <div>
        <p className="mb-2 font-mono text-[9px] uppercase tracking-[0.16em] text-slate-500">分数变化</p>
        <div className="grid grid-cols-2 gap-2">
          {scoreRows.map((score) => (
            <div key={score.role} className="rounded-xl border border-white/[0.12] bg-[#162340] p-3">
              <p className={`font-mono text-[10px] ${score.tone}`}>{score.role}</p>
              <p className="mt-1 font-mono text-xl font-semibold text-[#f0f4ff]">+{score.value ?? 0}</p>
              <p className="mt-1 break-words font-mono text-[9px] leading-4 text-slate-500">{score.reason || EMPTY}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function EmptyState({ text, compact = false }: { text: string; compact?: boolean }) {
  return <div className={`rounded-xl border border-dashed border-white/[0.12] bg-[#162340]/60 text-center text-xs text-slate-500 ${compact ? "p-3" : "px-4 py-8"}`}>{text}</div>;
}

function ReflectionCard({ role, reflection, outcomeReflection, policy, nextRound }: { role: "red" | "blue"; reflection: any; outcomeReflection?: any; policy?: any; nextRound?: any }) {
  const isRed = role === "red";
  const nextLog = findLog(nextRound, role);
  const nextAction = isRed ? nextRound?.red_action ?? {} : nextRound?.blue_action ?? {};
  const nextTarget = targetOf(nextLog, nextAction);
  const nextActionName = actionOf(nextLog, nextAction);
  const nextVulnId = nextLog?.metadata?.vuln_id || nextAction?.vuln_id || "";
  const targets = [...listOf(reflection?.prioritized_targets), ...listOf(reflection?.maintain), ...listOf(reflection?.next_goal)];
  const relation = !nextRound
    ? "暂无下一回合动作"
    : targets.some((item) => nextTarget && item.includes(nextTarget))
      ? `吻合：${nextActionName || "红方动作"} → ${nextTarget}`
      : `未直接命中：${nextActionName || "红方动作"} → ${nextTarget || "无目标"}`;
  const executionRelation = policyRelation(policy, nextActionName, nextTarget, nextVulnId, Boolean(nextRound));
  const policyTags = [
    ...listOf(policy?.prefer_action_types).map((item) => `优先 ${item}`),
    ...listOf(policy?.prefer_targets).map((item) => `目标 ${item}`),
    ...listOf(policy?.avoid_action_types).map((item) => `避开 ${item}`),
    ...(policy?.require_change ? ["必须切换动作或目标"] : []),
  ];
  const border = isRed ? "border-red-400/30" : "border-blue-400/30";
  const accent = isRed ? "text-red-300" : "text-blue-300";

  if (!reflection) {
    return (
      <article className={`rounded-xl border ${border} bg-[#162340] p-3`}>
        <p className={`font-mono text-[10px] uppercase tracking-[0.15em] ${accent}`}>{isRed ? "红方反思" : "蓝方反思"}</p>
        <div className="mt-3"><EmptyState text="尚未形成反思" compact /></div>
      </article>
    );
  }

  return (
    <article className={`rounded-xl border ${border} bg-[#162340] p-3`}>
      <div className="flex items-center justify-between gap-2">
        <p className={`font-mono text-[10px] uppercase tracking-[0.15em] ${accent}`}>{isRed ? "红方反思" : "蓝方反思"}</p>
        <span className="font-mono text-[9px] text-slate-500">来源回合 {reflection?.turn ?? "?"}</span>
      </div>
      <div className="mt-3">
        <Field label="观察">{cleanText(reflection?.summary, 320)}</Field>
        <Field label="行动复盘">{cleanText(outcomeReflection?.adjustment)}</Field>
        <Field label="执行约束"><Tags values={policyTags} tone="violet" /></Field>
        <Field label="下轮执行"><span className={executionRelation.startsWith("已遵循") ? "text-emerald-300" : executionRelation.startsWith("未遵循") ? "text-red-300" : "text-slate-300"}>{executionRelation}</span></Field>
        {isRed ? (
          <>
            <Field label="保留能力"><Tags values={reflection?.maintain} tone="red" /></Field>
            <Field label="策略调整">{cleanText(reflection?.strategy_shift)}</Field>
            <Field label="优先目标"><Tags values={reflection?.prioritized_targets} tone="red" /></Field>
            <Field label="避开对象"><Tags values={reflection?.avoid} tone="amber" /></Field>
            <Field label="下一目标">{cleanText(reflection?.next_goal)}</Field>
            <Field label="动作关系"><span className={relation.startsWith("吻合") ? "text-emerald-300" : "text-slate-300"}>{relation}</span></Field>
          </>
        ) : (
          <>
            <Field label="攻击路径"><Tags values={reflection?.likely_attack_path} tone="blue" /></Field>
            <Field label="可能目标"><Tags values={reflection?.likely_goals} tone="red" /></Field>
            <Field label="下一步建议">
              <div className="space-y-1.5">
                {Array.isArray(reflection?.priority_defense) && reflection.priority_defense.length ? reflection.priority_defense.map((item: any, index: number) => (
                  <div key={`${item?.action}-${item?.target}-${index}`} className="rounded-md border border-blue-400/20 bg-blue-500/[0.07] px-2 py-1.5">
                    <span className="font-mono text-[10px] text-blue-200">{item?.action || formatValue(item)}{item?.target ? ` → ${item.target}` : ""}</span>
                    {item?.reason ? <p className="mt-1 text-[10px] leading-4 text-slate-400">{item.reason}</p> : null}
                  </div>
                )) : <span className="text-slate-500">无</span>}
              </div>
            </Field>
            <Field label="应避免动作"><Tags values={reflection?.avoid} tone="amber" /></Field>
          </>
        )}
      </div>
    </article>
  );
}

function ReasoningPanel({ round, nextRound }: ReasoningPanelProps) {
  const [activeStep, setActiveStep] = useState("start");
  const roundLabel = round?.round ?? round?.turn ?? 0;
  const refereeLog = useMemo(() => findLog(round, "referee"), [round]);
  const flow = round?.referee_flow ?? refereeLog?.metadata?.referee_flow ?? {};
  const agentMemory = refereeLog?.metadata?.agent_memory ?? {};
  const redReflection = latestReflection(agentMemory?.red?.recent_reflections);
  const blueReflection = latestReflection(agentMemory?.blue?.recent_reflections);
  const redOutcomeReflection = latestReflection(agentMemory?.red?.outcome_reflections);
  const blueOutcomeReflection = latestReflection(agentMemory?.blue?.outcome_reflections);

  useEffect(() => {
    setActiveStep(round?.__frame_phase === "start" ? "start" : "changes");
  }, [round?.round, round?.turn, round?.__frame_phase]);

  const stepContent: Record<string, React.ReactNode> = {
    start: <SnapshotView snapshot={flow?.start_snapshot ?? {}} />,
    red: <PreconditionView data={flow?.red_precondition_check ?? {}} tone="red" />,
    blue: <PreconditionView data={flow?.blue_precondition_check ?? {}} tone="blue" />,
    attack: <AttackGraphView data={flow?.attack_graph_progress ?? {}} />,
    conflict: <ConflictView data={flow?.same_turn_conflict ?? {}} />,
    changes: <ChangesView stateChanges={flow?.state_changes} scoreChanges={flow?.score_changes ?? {}} />,
    end: <SnapshotView snapshot={flow?.end_snapshot ?? {}} compare={flow?.start_snapshot ?? {}} />,
  };
  const selected = FLOW_STEPS.find((step) => step.id === activeStep) ?? FLOW_STEPS[0];

  return (
    <section className="flex h-full min-h-0 flex-col overflow-hidden rounded-2xl border border-white/[0.14] bg-[#111a2e]/96">
      <header className="shrink-0 border-b border-white/[0.14] px-4 py-3">
        <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-400">Referee Flow</p>
        <div className="mt-1 flex items-center justify-between gap-3">
          <h2 className="text-lg font-medium tracking-wide text-[#f0f4ff]">当前回合分析</h2>
          <span className="rounded-full border border-white/[0.14] bg-[#162340] px-2 py-0.5 font-mono text-[10px] text-slate-400">
            回合 {roundLabel} · {round?.__frame_phase_label ?? "结算帧"}
          </span>
        </div>
      </header>

      <div className="cyber-scrollbar min-h-0 flex-1 overflow-y-auto">
        <div className="sticky top-0 z-10 border-b border-white/[0.1] bg-[#111a2e]/95 px-3 py-3 backdrop-blur">
          <div className="grid grid-cols-7 gap-1">
            {FLOW_STEPS.map((step) => {
              const active = activeStep === step.id;
              return (
                <button
                  key={step.id}
                  type="button"
                  title={step.label}
                  onClick={() => setActiveStep(step.id)}
                  className={`group rounded-lg border px-1 py-2 transition ${active ? "border-blue-400/50 bg-blue-500/15 shadow-[inset_0_-2px_0_#5b9fff]" : "border-white/[0.1] bg-[#162340] hover:border-white/[0.2]"}`}
                >
                  <span className={`block font-mono text-[10px] font-semibold ${active ? step.tone : "text-slate-500 group-hover:text-slate-300"}`}>{step.number}</span>
                  <span className={`mt-0.5 block text-[9px] ${active ? "text-slate-200" : "text-slate-500"}`}>{step.short}</span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="space-y-4 p-3">
          <article className="rounded-xl border border-white/[0.12] bg-[#111a2e] p-3 shadow-[0_14px_32px_rgba(0,0,0,0.2)]">
            <div className="mb-3 flex items-center gap-2 border-b border-white/[0.1] pb-3">
              <span className={`flex h-6 w-6 items-center justify-center rounded-md border border-white/[0.14] bg-[#1c2d4a] font-mono text-[10px] ${selected.tone}`}>{selected.number}</span>
              <h3 className="text-sm font-medium text-[#f0f4ff]">{selected.label}</h3>
            </div>
            {stepContent[activeStep]}
          </article>

          <div className="pt-1">
            <div className="mb-3 flex items-end justify-between gap-3">
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-violet-300">Agent Reflection</p>
                <h3 className="mt-1 text-base font-medium text-[#f0f4ff]">策略演化</h3>
              </div>
              <span className="font-mono text-[9px] text-slate-500">仅展示结构化反思</span>
            </div>
            <div className="space-y-3">
              <ReflectionCard role="red" reflection={redReflection} outcomeReflection={redOutcomeReflection} policy={agentMemory?.red?.active_reflection_policy} nextRound={nextRound} />
              <ReflectionCard role="blue" reflection={blueReflection} outcomeReflection={blueOutcomeReflection} policy={agentMemory?.blue?.active_reflection_policy} nextRound={nextRound} />
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export default ReasoningPanel;
