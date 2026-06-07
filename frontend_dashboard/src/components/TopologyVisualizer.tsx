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

    const node = currentRound?.network_nodes?.[hoveredNode] ?? currentRound?.world_state?.network_nodes?.[hoveredNode];
    if (!node) {
      return null;
    }

    return {
      id: hoveredNode,
      status: node.status ?? "Normal",
      exposedPorts: node.exposed_ports ?? [],
      vulnerabilities: Object.keys(node.vulnerabilities ?? {}),
      redState: node.red_state ?? {},
      blueState: node.blue_state ?? {},
      attackCount: node.attack_count ?? 0,
      defenseCount: node.defense_count ?? 0,
    };
  }, [currentRound, hoveredNode]);

  const blueCapabilities = hoveredDetail ? [
    hoveredDetail.blueState.restored && "已恢复",
    hoveredDetail.blueState.monitored && "被监控",
    hoveredDetail.blueState.isolated && "已隔离",
    hoveredDetail.blueState.hardened && "已加固",
  ].filter(Boolean) as string[] : [];

  const redCapabilities = hoveredDetail ? [
    hoveredDetail.redState.recon_known && "已侦察",
    hoveredDetail.redState.credential_known && "持有凭据",
    hoveredDetail.redState.session_active && "活动 Session",
    hoveredDetail.redState.foothold && "Foothold",
    hoveredDetail.redState.persistence && "持久化",
    hoveredDetail.redState.privilege && hoveredDetail.redState.privilege !== "none" && String(hoveredDetail.redState.privilege).toUpperCase(),
  ].filter(Boolean) as string[] : [];

  return (
    <div className={`flex h-full min-h-0 flex-col overflow-hidden ${variant === "default" ? "rounded-2xl bg-[#0c1220] shadow-inner shadow-black/35" : "bg-transparent"}`}>
      {variant === "default" ? (
        <div className="flex items-center justify-between bg-transparent px-4 pb-3 pt-4">
          <p className="font-mono text-[13px] uppercase tracking-[0.18em] text-slate-300">动态网络拓扑</p>
          <div className="flex items-center gap-2 font-mono text-[10px]">
            <span className="rounded-full border border-slate-500/50 bg-slate-500/15 px-2 py-0.5 text-slate-300">正常</span>
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
          <div className="pointer-events-none absolute bottom-4 right-4 z-30 w-[340px] overflow-hidden rounded-xl border border-[#304060] bg-[#111a2e]/[0.97] font-mono shadow-[0_18px_45px_rgba(2,8,28,0.58)] backdrop-blur-md">
            <div className="flex items-center justify-between border-b border-[#304060] bg-[#162340] px-4 py-3">
              <div>
                <p className="text-[9px] uppercase tracking-[0.2em] text-[#8a9bc0]">节点情报</p>
                <p className="mt-1 text-sm font-semibold tracking-wide text-[#f0f4ff]">{hoveredDetail.id}</p>
              </div>
              <span className={`rounded-md border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] ${
                String(hoveredDetail.status).toLowerCase() === "compromised"
                  ? "border-red-400/60 bg-red-500/15 text-red-200"
                  : String(hoveredDetail.status).toLowerCase() === "defended"
                    ? "border-emerald-400/60 bg-emerald-500/15 text-emerald-200"
                    : "border-slate-500/60 bg-slate-500/15 text-slate-200"
              }`}>
                {hoveredDetail.status}
              </span>
            </div>

            <div className="space-y-3 p-3">
              <div className="grid grid-cols-2 gap-2">
                <div className="rounded-lg border border-red-400/25 bg-[rgba(255,107,122,0.07)] px-3 py-2">
                  <p className="text-[9px] uppercase tracking-[0.15em] text-red-300/80">红方能力</p>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {redCapabilities.length ? redCapabilities.map((label) => (
                      <span key={label} className="rounded border border-red-400/35 bg-red-500/10 px-1.5 py-1 text-[9px] text-red-100">{label}</span>
                    )) : <span className="text-[10px] text-[#8a9bc0]">无残留能力</span>}
                  </div>
                </div>

                <div className="rounded-lg border border-cyan-400/25 bg-cyan-400/[0.05] px-3 py-2">
                  <p className="text-[9px] uppercase tracking-[0.15em] text-cyan-300/80">蓝方处置</p>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {blueCapabilities.length ? blueCapabilities.map((label) => (
                      <span key={label} className="rounded border border-cyan-400/35 bg-cyan-400/10 px-1.5 py-1 text-[9px] text-cyan-100">{label}</span>
                    )) : <span className="text-[10px] text-[#8a9bc0]">无处置标记</span>}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-[1fr_auto_auto] items-center gap-3 rounded-lg border border-[#304060] bg-[#162340] px-3 py-2 text-[10px]">
                <div>
                  <p className="text-[#8a9bc0]">开放端口</p>
                  <p className="mt-1 text-slate-200">{hoveredDetail.exposedPorts.length ? hoveredDetail.exposedPorts.join(", ") : "无"}</p>
                </div>
                <div className="border-l border-[#304060] pl-3 text-center">
                  <p className="text-[#8a9bc0]">攻击</p>
                  <p className="mt-1 text-red-300">{hoveredDetail.attackCount}</p>
                </div>
                <div className="border-l border-[#304060] pl-3 text-center">
                  <p className="text-[#8a9bc0]">防御</p>
                  <p className="mt-1 text-blue-300">{hoveredDetail.defenseCount}</p>
                </div>
              </div>

              <div className="rounded-lg border border-[#304060] bg-[#0c1220]/70 px-3 py-2">
                <div className="flex items-center justify-between">
                  <p className="text-[9px] uppercase tracking-[0.15em] text-[#8a9bc0]">已知漏洞</p>
                  <span className="text-[9px] text-amber-300">{hoveredDetail.vulnerabilities.length}</span>
                </div>
                <p className="mt-1.5 truncate text-[10px] text-slate-300">
                  {hoveredDetail.vulnerabilities.length ? hoveredDetail.vulnerabilities.slice(0, 2).join(" · ") : "暂无已知漏洞"}
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default TopologyVisualizer;
