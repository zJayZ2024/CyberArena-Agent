import { useMemo } from "react";

import { translateAction } from "../utils/localization";

type ReasoningPanelProps = {
  round?: any;
};

type ReasoningCard = {
  id: string;
  title: string;
  action: string;
  reasoning: string;
  className: string;
  actionClassName: string;
};

const MOCK_CARDS: ReasoningCard[] = [
  {
    id: "red",
    title: "红方智能体",
    action: "服务利用",
    reasoning: "从 web 跳转到 app，再尝试利用 storage 暴露面收集凭据。",
    className: "border-l-2 border-red-500/50 bg-red-950/20 shadow-[0_10px_24px_rgba(2,8,24,0.24)]",
    actionClassName: "text-red-300",
  },
  {
    id: "blue",
    title: "蓝方智能体",
    action: "漏洞修补",
    reasoning: "修补 storage 上的高分漏洞，降低可达攻击链深度。",
    className: "border-l-2 border-blue-500/50 bg-blue-950/20 shadow-[0_10px_24px_rgba(2,8,24,0.24)]",
    actionClassName: "text-blue-300",
  },
  {
    id: "referee",
    title: "裁判",
    action: "回合裁定",
    reasoning: "根据动作元数据确定性评估前置条件与得分变化。",
    className: "border-l-2 border-amber-400/55 bg-amber-950/20 shadow-[0_10px_24px_rgba(2,8,24,0.24)]",
    actionClassName: "text-amber-300",
  },
];

function normalizeRole(value: string) {
  return String(value || "").trim().toLowerCase();
}

function createCards(round: any): ReasoningCard[] {
  const logs = Array.isArray(round?.action_logs) ? round.action_logs : [];
  const pickLog = (agentRole: string) => logs.find((log: any) => normalizeRole(log.agent_type || log?.metadata?.agent_type) === agentRole);

  const redLog = pickLog("red");
  const blueLog = pickLog("blue");
  const refereeLog = pickLog("referee");

  return [
    {
      id: "red",
      title: "红方智能体",
      action: round?.red_action?.action_type || round?.red_action?.technique || redLog?.action_type || "Recon",
      reasoning: round?.red_action?.reasoning || redLog?.thought || "本回合没有红方推理内容。",
      className: "border-l-2 border-red-500/50 bg-red-950/20 shadow-[0_10px_24px_rgba(2,8,24,0.24)]",
      actionClassName: "text-red-300",
    },
    {
      id: "blue",
      title: "蓝方智能体",
      action: round?.blue_action?.type || round?.blue_action?.action_type || blueLog?.action_type || "Monitor",
      reasoning: round?.blue_action?.reasoning || blueLog?.thought || "本回合没有蓝方推理内容。",
      className: "border-l-2 border-blue-500/50 bg-blue-950/20 shadow-[0_10px_24px_rgba(2,8,24,0.24)]",
      actionClassName: "text-blue-300",
    },
    {
      id: "referee",
      title: "裁判",
      action: refereeLog?.action_type || "ResolveRound",
      reasoning: refereeLog?.thought || round?.judge_result?.narrative || "本回合没有裁判叙述。",
      className: "border-l-2 border-amber-400/55 bg-amber-950/20 shadow-[0_10px_24px_rgba(2,8,24,0.24)]",
      actionClassName: "text-amber-300",
    },
  ];
}

function ReasoningPanel({ round }: ReasoningPanelProps) {
  const roundLabel = round?.round ?? round?.turn ?? 1;
  const cards = useMemo(() => {
    if (!round) {
      return MOCK_CARDS;
    }
    return createCards(round);
  }, [round]);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="px-4 py-3">
        <p className="font-mono text-[13px] uppercase tracking-[0.22em] text-slate-300">智能体推理流</p>
        <p className="mt-1 text-xs text-slate-500">回合 {roundLabel}</p>
      </div>

      <div className="cyber-scrollbar min-h-0 flex-1 space-y-4 overflow-y-auto px-3 py-3">
        {cards.map((card) => (
          <article key={card.id} className={`rounded-xl p-3 ${card.className}`}>
            <div className="flex items-center justify-between">
              <h3 className="font-mono text-xs uppercase tracking-[0.14em] text-slate-200">{card.title}</h3>
              <span className={`font-mono text-[11px] ${card.actionClassName}`}>{translateAction(card.action, card.action)}</span>
            </div>
            <p className="mt-2 text-sm leading-6 text-slate-300">{card.reasoning}</p>
          </article>
        ))}
      </div>
    </div>
  );
}

export default ReasoningPanel;
