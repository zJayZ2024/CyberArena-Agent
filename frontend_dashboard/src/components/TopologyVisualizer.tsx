import { useEffect, useMemo, useState } from "react";

import SvgGraph from "./NetworkTopology/SvgGraph";
import { T } from "./NetworkTopology/constants";
import { DEFAULT_ROUNDS, normalizeRoundsPayload } from "./NetworkTopology/data";

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
    const action = redAction.technique_id || redAction.action_type || redAction.technique || "Action";
    const target = redAction.target_node || redAction.target || "unknown";
    const statusLabel = judgeResult?.success === false ? "BLOCKED" : "OK";

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
    <div className={`flex h-full min-h-0 flex-col overflow-hidden ${variant === "default" ? "rounded-xl border border-[#1f2937] bg-[#07090f]" : "bg-transparent"}`}>
      {variant === "default" ? (
        <div className="flex items-center justify-between border-b border-[#1f2937] px-3 py-2">
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-slate-400">Dynamic Network Topology</p>
          <div className="flex items-center gap-2 font-mono text-[10px]">
            <span className="rounded-full border border-emerald-500/30 bg-emerald-950/30 px-2 py-0.5 text-emerald-300">Normal</span>
            <span className="rounded-full border border-red-500/30 bg-red-950/30 px-2 py-0.5 text-red-300">Compromised</span>
            <span className="rounded-full border border-slate-400/40 bg-slate-900/70 px-2 py-0.5 text-slate-300">Down / Isolated</span>
          </div>
        </div>
      ) : null}

      <div className={`relative min-h-0 flex-1 overflow-hidden ${variant === "default" ? "p-2" : "p-0"}`}>
        <SvgGraph
          round={currentRound}
          rounds={safeRounds}
          idx={safeIndex}
          hoveredNode={hoveredNode}
          onHoverNode={setHoveredNode}
          toast={toast}
        />

        {hoveredDetail && (
          <div className={`pointer-events-none absolute bottom-4 right-4 w-72 rounded-lg p-3 font-mono text-[11px] ${variant === "default" ? "border border-[#1f2937] bg-[#0d1117]/95" : "bg-[#050814]/78 shadow-[0_8px_24px_rgba(2,8,28,0.45)]"}`}>
            <p className="text-[10px] uppercase tracking-[0.16em] text-slate-400">{hoveredDetail.id}</p>
            <p className="mt-2 text-slate-300">Ports: {hoveredDetail.exposedPorts.length ? hoveredDetail.exposedPorts.join(", ") : "none"}</p>
            <p className="mt-1 text-slate-400">Vulns: {hoveredDetail.vulnerabilities.length ? hoveredDetail.vulnerabilities.slice(0, 3).join(", ") : "none"}</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default TopologyVisualizer;
