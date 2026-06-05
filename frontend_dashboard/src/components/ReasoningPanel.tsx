import { useMemo } from "react";

import { translateAction } from "../utils/localization";

type ReasoningPanelProps = {
  round?: any;
};

type AnalysisBlock = {
  id: string;
  title: string;
  action: string;
  target: string;
  result: string;
  reason: string;
  tone: "red" | "blue" | "amber";
};

const TONE_CLASS: Record<AnalysisBlock["tone"], string> = {
  red: "border-red-400/40 bg-red-500/[0.075]",
  blue: "border-blue-400/40 bg-blue-500/[0.075]",
  amber: "border-amber-400/40 bg-amber-500/[0.075]",
};

const LABEL_CLASS: Record<AnalysisBlock["tone"], string> = {
  red: "text-red-300",
  blue: "text-blue-300",
  amber: "text-amber-300",
};

function normalizeRole(value: string) {
  return String(value || "").trim().toLowerCase();
}

function cleanText(text: string, maxLength = 220) {
  const cleaned = String(text || "").replace(/\s+/g, " ").trim();
  if (!cleaned) {
    return "暂无可用解释。";
  }
  return cleaned.length > maxLength ? `${cleaned.slice(0, maxLength)}...` : cleaned;
}

function targetOf(log: any, fallback: any) {
  return log?.metadata?.target || fallback?.target || fallback?.target_node || "无目标";
}

function effectText(effect?: string) {
  const value = String(effect || "").toLowerCase();
  if (["compromise", "bypass", "exfiltration"].includes(value)) return "行动生效";
  if (["blocked", "failed", "rejected"].includes(value)) return "被阻断";
  if (["hardening", "restoration", "isolation", "monitoring"].includes(value)) return "处置生效";
  if (value === "intel") return "获得情报";
  return effect || "已结算";
}

function statusLabel(value: string) {
  const labels: Record<string, string> = {
    Normal: "正常",
    normal: "正常",
    Compromised: "失陷",
    compromised: "失陷",
    Defended: "已加固",
    defended: "已加固",
    Isolated: "已隔离",
    isolated: "已隔离",
    Down: "离线",
    down: "离线",
  };
  return labels[value] || value || "未知";
}

function createBlocks(round: any): AnalysisBlock[] {
  const logs = Array.isArray(round?.action_logs) ? round.action_logs : [];
  const pickLog = (agentRole: string) => logs.find((log: any) => normalizeRole(log.agent_type || log?.metadata?.agent_type) === agentRole);
  const redLog = pickLog("red");
  const blueLog = pickLog("blue");
  const refereeLog = pickLog("referee");
  const redAction = round?.red_action ?? {};
  const blueAction = round?.blue_action ?? {};
  const interaction = refereeLog?.metadata?.interaction?.type || "independent";
  const scoreSummary = refereeLog?.metadata?.score_summary;
  const isStartFrame = round?.__frame_phase === "start";

  return [
    {
      id: "red",
      title: "红方为什么这么做",
      action: redAction?.action_type || redAction?.technique || redLog?.action_type || "Action",
      target: targetOf(redLog, redAction),
      result: isStartFrame ? "待执行" : effectText(redLog?.metadata?.referee_effect),
      reason: cleanText(redLog?.thought || redAction?.reasoning || redLog?.referee_result || ""),
      tone: "red",
    },
    {
      id: "blue",
      title: "蓝方为什么这么做",
      action: blueAction?.type || blueAction?.action_type || blueLog?.action_type || "Action",
      target: targetOf(blueLog, blueAction),
      result: isStartFrame ? "待执行" : effectText(blueLog?.metadata?.referee_effect),
      reason: cleanText(blueLog?.thought || blueAction?.reasoning || blueLog?.referee_result || ""),
      tone: "blue",
    },
    {
      id: "referee",
      title: "裁判如何判定",
      action: refereeLog?.action_type || "ResolveRound",
      target: isStartFrame ? "尚未结算" : interaction === "independent" ? "独立结算" : interaction,
      result: isStartFrame ? "等待裁定" : scoreSummary
        ? `红方 +${scoreSummary.red_delta ?? 0} / 蓝方 +${scoreSummary.blue_delta ?? 0}`
        : "等待裁定",
      reason: cleanText(isStartFrame ? round?.__frame_explanation : refereeLog?.referee_result || refereeLog?.thought || round?.judge_result?.narrative || "", 260),
      tone: "amber",
    },
  ];
}

function ReasoningPanel({ round }: ReasoningPanelProps) {
  const roundLabel = round?.round ?? round?.turn ?? 0;
  const blocks = useMemo(() => createBlocks(round ?? {}), [round]);
  const frameChanges = Array.isArray(round?.__frame_changes) ? round.__frame_changes : [];
  const frameTone = round?.__frame_phase === "start" ? "border-amber-400/30 bg-amber-500/[0.06]" : "border-emerald-400/30 bg-emerald-500/[0.055]";

  return (
    <section className="flex h-full min-h-0 flex-col overflow-hidden rounded-2xl border border-white/[0.08] bg-[#070d16]/78">
      <header className="shrink-0 border-b border-white/[0.07] px-4 py-3">
        <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-500">Round analysis</p>
        <div className="mt-1 flex items-center justify-between gap-3">
          <h2 className="text-lg font-medium tracking-wide text-slate-100">当前回合分析</h2>
          <span className="rounded-full border border-slate-700/80 px-2 py-0.5 font-mono text-[10px] text-slate-400">
            回合 {roundLabel} · {round?.__frame_phase_label ?? "单帧"}
          </span>
        </div>
      </header>

      <div className="cyber-scrollbar min-h-0 flex-1 space-y-3 overflow-y-auto p-3">
        {round?.__frame_explanation ? (
          <article className={`rounded-xl border p-3 ${frameTone}`}>
            <p className="font-mono text-[10px] uppercase tracking-[0.15em] text-slate-400">状态口径</p>
            <h3 className="mt-2 text-base font-medium text-slate-100">{round.__frame_phase_label}</h3>
            <p className="mt-2 text-sm leading-6 text-slate-300">{round.__frame_explanation}</p>
            {frameChanges.length ? (
              <div className="mt-3 flex flex-wrap gap-2">
                {frameChanges.slice(0, 5).map((change: any) => (
                  <span key={`${change.node}-${change.from}-${change.to}`} className="rounded-md border border-white/[0.08] bg-white/[0.04] px-2 py-1 font-mono text-[10px] text-slate-300">
                    {change.node}: {statusLabel(change.from)} {"->"} {statusLabel(change.to)}
                  </span>
                ))}
              </div>
            ) : null}
          </article>
        ) : null}

        {blocks.map((block) => (
          <article key={block.id} className={`rounded-xl border p-3 ${TONE_CLASS[block.tone]}`}>
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <p className={`font-mono text-[10px] uppercase tracking-[0.15em] ${LABEL_CLASS[block.tone]}`}>{block.title}</p>
                <h3 className="mt-2 truncate text-base font-medium text-slate-100">
                  {translateAction(block.action, block.action)}
                </h3>
                <p className="mt-1 font-mono text-[11px] text-slate-400">目标：{block.target}</p>
              </div>
              <span className={`shrink-0 rounded-md bg-white/[0.06] px-2 py-1 font-mono text-[10px] ${LABEL_CLASS[block.tone]}`}>
                {block.result}
              </span>
            </div>
            <p className="mt-3 text-sm leading-6 text-slate-300">{block.reason}</p>
          </article>
        ))}
      </div>
    </section>
  );
}

export default ReasoningPanel;
