import { useMemo } from "react";

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
    title: "RED Agent",
    action: "ExploitService",
    reasoning: "Pivot from web to app, then target storage exposure for credential harvesting.",
    className: "border-l-2 border-red-500/50 bg-red-950/20 shadow-[0_10px_24px_rgba(2,8,24,0.24)]",
    actionClassName: "text-red-300",
  },
  {
    id: "blue",
    title: "BLUE Agent",
    action: "PatchNode",
    reasoning: "Patch high-score vulnerability on storage to reduce reachable kill chain depth.",
    className: "border-l-2 border-blue-500/50 bg-blue-950/20 shadow-[0_10px_24px_rgba(2,8,24,0.24)]",
    actionClassName: "text-blue-300",
  },
  {
    id: "referee",
    title: "Referee",
    action: "ResolveRound",
    reasoning: "Evaluate prerequisites and score deltas deterministically from action metadata.",
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
      title: "RED Agent",
      action: round?.red_action?.action_type || round?.red_action?.technique || redLog?.action_type || "Recon",
      reasoning: round?.red_action?.reasoning || redLog?.thought || "No RED reasoning available in this round.",
      className: "border-l-2 border-red-500/50 bg-red-950/20 shadow-[0_10px_24px_rgba(2,8,24,0.24)]",
      actionClassName: "text-red-300",
    },
    {
      id: "blue",
      title: "BLUE Agent",
      action: round?.blue_action?.type || round?.blue_action?.action_type || blueLog?.action_type || "Monitor",
      reasoning: round?.blue_action?.reasoning || blueLog?.thought || "No BLUE reasoning available in this round.",
      className: "border-l-2 border-blue-500/50 bg-blue-950/20 shadow-[0_10px_24px_rgba(2,8,24,0.24)]",
      actionClassName: "text-blue-300",
    },
    {
      id: "referee",
      title: "Referee",
      action: refereeLog?.action_type || "ResolveRound",
      reasoning: refereeLog?.thought || round?.judge_result?.narrative || "No referee narrative available in this round.",
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
        <p className="font-mono text-[13px] uppercase tracking-[0.22em] text-slate-300">Agent Reasoning Stream</p>
        <p className="mt-1 text-xs text-slate-500">Round {roundLabel}</p>
      </div>

      <div className="cyber-scrollbar min-h-0 flex-1 space-y-4 overflow-y-auto px-3 py-3">
        {cards.map((card) => (
          <article key={card.id} className={`rounded-xl p-3 ${card.className}`}>
            <div className="flex items-center justify-between">
              <h3 className="font-mono text-xs uppercase tracking-[0.14em] text-slate-200">{card.title}</h3>
              <span className={`font-mono text-[11px] ${card.actionClassName}`}>{card.action}</span>
            </div>
            <p className="mt-2 text-sm leading-6 text-slate-300">{card.reasoning}</p>
          </article>
        ))}
      </div>
    </div>
  );
}

export default ReasoningPanel;
