import { useEffect, useMemo, useState } from "react";

import SvgGraph from "./NetworkTopology/SvgGraph";
import { T } from "./NetworkTopology/constants";
import { DEFAULT_ROUNDS, normalizeRoundsPayload } from "./NetworkTopology/data";
import { translateAction } from "../utils/localization";

type TopologyVisualizerProps = {
  round?: any;
  rounds?: any[];
  roundIndex?: number;
  variant?: "default" | "embedded";
};

const MOCK_ROUNDS = normalizeRoundsPayload(DEFAULT_ROUNDS);

function TopologyVisualizer({
  round,
  rounds = MOCK_ROUNDS,
  roundIndex = 0,
  variant = "default",
}: TopologyVisualizerProps) {
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [toast, setToast] = useState({ visible: false, text: "", color: T.red });

  const safeRounds = rounds.length ? rounds : MOCK_ROUNDS;
  const safeIndex = Math.min(roundIndex, Math.max(safeRounds.length - 1, 0));
  const currentRound = round ?? safeRounds[safeIndex] ?? MOCK_ROUNDS[0];

  useEffect(() => {
    const redAction = currentRound?.red_action;
    const judgeResult = currentRound?.judge_result;
    const hasActionSignal = !!(
      redAction?.technique_id
      || redAction?.action_type
      || redAction?.technique
      || redAction?.target_node
      || redAction?.target
    );
    if (!hasActionSignal) {
      setToast((prev) => (prev.visible || prev.text ? { ...prev, visible: false, text: "" } : prev));
      return undefined;
    }

    const turn = currentRound?.round ?? currentRound?.turn ?? safeIndex + 1;
    const rawAction = redAction.technique_id || redAction.action_type || redAction.technique || "Action";
    const action = translateAction(rawAction, rawAction);
    const target = redAction.target_node || redAction.target || "未知";
    const statusLabel = currentRound?.__frame_phase === "start"
      ? "待执行"
      : judgeResult?.success === false ? "被阻断" : "生效";

    setToast({
      visible: true,
      text: `R${turn}: ${action} -> ${target} ${statusLabel}`,
      color: judgeResult?.success === false ? T.grayDim : T.red,
    });

    const timer = window.setTimeout(() => {
      setToast((prev) => ({ ...prev, visible: false }));
    }, 2600);

    return () => window.clearTimeout(timer);
  }, [currentRound, safeIndex]);

  const hoveredDetail = useMemo(() => {
    if (!hoveredNode) {
      return null;
    }

    const node = currentRound?.network_nodes?.[hoveredNode];
    if (!node) {
      return null;
    }

    return {
      id: hoveredNode,
      exposedPorts: node.exposed_ports ?? [],
      vulnerabilities: Object.keys(node.vulnerabilities ?? {}),
    };
  }, [currentRound, hoveredNode]);

  return (
    <div className={`flex h-full min-h-0 flex-col overflow-hidden ${variant === "default" ? "rounded-2xl bg-[#0c1220] shadow-inner shadow-black/35" : "bg-transparent"}`}>
      {variant === "default" ? (
        <div className="flex items-center justify-between bg-transparent px-4 pb-3 pt-4">
          <p className="font-mono text-[13px] uppercase tracking-[0.18em] text-slate-300">动态网络拓扑</p>
          <div className="flex items-center gap-2 font-mono text-[10px]">
            <span className="rounded-full border border-blue-500/35 bg-blue-900/25 px-2 py-0.5 text-blue-300">正常</span>
            <span className="rounded-full border border-red-400/50 bg-[rgba(255,107,122,0.12)] px-2 py-0.5 text-red-300">已失陷</span>
            <span className="rounded-full border border-slate-500/35 bg-slate-500/15 px-2 py-0.5 text-slate-300">隔离 / 离线</span>
          </div>
        </div>
      ) : null}

      <div className={`relative min-h-0 flex-1 overflow-hidden bg-transparent ${variant === "default" ? "p-2" : "p-0"}`}>
        <SvgGraph
          round={currentRound}
          rounds={safeRounds}
          idx={safeIndex}
          hoveredNode={hoveredNode}
          onHoverNode={setHoveredNode}
          toast={toast}
        />

        {hoveredDetail && (
          <div className={`pointer-events-none absolute bottom-4 right-4 w-72 rounded-lg p-3 font-mono text-[11px] ${variant === "default" ? "bg-[#111a2e]/90 shadow-[0_8px_24px_rgba(2,8,28,0.45)]" : "bg-[#162340]/78 shadow-[0_8px_24px_rgba(2,8,28,0.45)]"}`}>
            <p className="text-[10px] uppercase tracking-[0.16em] text-slate-400">{hoveredDetail.id}</p>
            <p className="mt-2 text-slate-300">端口：{hoveredDetail.exposedPorts.length ? hoveredDetail.exposedPorts.join(", ") : "无"}</p>
            <p className="mt-1 text-slate-400">漏洞：{hoveredDetail.vulnerabilities.length ? hoveredDetail.vulnerabilities.slice(0, 3).join(", ") : "无"}</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default TopologyVisualizer;
