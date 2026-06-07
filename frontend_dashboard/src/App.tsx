import { useEffect, useMemo, useState } from "react";

import LiveScoreChart from "./components/LiveScoreChart";
import ReasoningPanel from "./components/ReasoningPanel";
import ReplayPicker, { type ReplayCatalogItem } from "./components/ReplayPicker";
import ScenarioSelection, { type ScenarioCatalogItem } from "./components/ScenarioSelection";
import TerminalLogs from "./components/TerminalLogs";
import { CyberArenaLogo } from "./components/TopBar";
import TopologyVisualizer from "./components/TopologyVisualizer";
import { DEFAULT_ROUNDS, normalizeRoundsPayload } from "./components/NetworkTopology/data";
import { translateAction, translateScenarioName, translateStatus } from "./utils/localization";

const FALLBACK_ROUNDS = normalizeRoundsPayload(DEFAULT_ROUNDS);

type AppTabKey = "demo" | "scenarios" | "analysis" | "settings";

const NAV_ITEMS: Array<{ key: AppTabKey; label: string; subtitle: string }> = [
  { key: "demo", label: "攻防演示", subtitle: "主工作台" },
  { key: "scenarios", label: "场景库", subtitle: "拓扑选择" },
  { key: "analysis", label: "结果分析", subtitle: "复盘指标" },
  { key: "settings", label: "设置", subtitle: "系统控制" },
];

function getWorldState(round: any) {
  return round?.world_state ?? round ?? {};
}

function getNetworkNodes(round: any) {
  return round?.network_nodes ?? round?.world_state?.network_nodes ?? {};
}

function getScore(round: any) {
  const worldState = getWorldState(round);
  return worldState?.score ?? {
    red: worldState?.red_score ?? round?.red_score ?? 0,
    blue: worldState?.blue_score ?? round?.blue_score ?? 0,
  };
}

function getAgentLog(round: any, agentType: "Red" | "Blue" | "Referee") {
  const logs = Array.isArray(round?.action_logs) ? round.action_logs : [];
  return logs.find((log: any) => log?.agent_type === agentType);
}

function getActionTarget(log: any, fallbackAction: any) {
  return log?.metadata?.target || fallbackAction?.target || fallbackAction?.target_node || "无目标";
}

function getActionName(log: any, fallbackAction: any) {
  return fallbackAction?.action_type || fallbackAction?.technique || fallbackAction?.type || log?.action_type || "Action";
}

function getActionLabel(log: any, fallbackAction: any) {
  const action = getActionName(log, fallbackAction);
  return translateAction(action, action);
}

function phaseFromAction(actionType?: string) {
  const action = String(actionType || "");
  if (["Recon", "ReconScan", "PortScan", "recon"].includes(action)) return "侦察";
  if (["Exploit", "ExploitService"].includes(action)) return "初始访问";
  if (["LateralMove", "LateralMovement", "CredentialAbuse", "CredentialDump"].includes(action)) return "横向移动";
  if (["Exfiltrate", "ExfiltrateDatabase", "DataExfiltration"].includes(action)) return "数据外传";
  if (["AnchorFoothold", "ReactivateFoothold"].includes(action)) return "持久化";
  if (["PreventivePatch", "PatchNode", "RestoreNode", "DeepRestore", "Isolate", "Monitor"].includes(action)) return "防御处置";
  return "准备";
}

function effectTone(effect?: string) {
  const value = String(effect || "").toLowerCase();
  if (["compromise", "bypass", "exfiltration"].includes(value)) return "red";
  if (["blocked", "failed", "rejected"].includes(value)) return "amber";
  if (["hardening", "restoration", "isolation", "monitoring"].includes(value)) return "blue";
  if (value === "intel") return "slate";
  return "slate";
}

function effectLabel(effect?: string) {
  const value = String(effect || "").toLowerCase();
  if (["compromise", "bypass", "exfiltration"].includes(value)) return "红方生效";
  if (["blocked", "failed", "rejected"].includes(value)) return "被阻断";
  if (["hardening", "restoration", "isolation", "monitoring"].includes(value)) return "蓝方处置";
  if (value === "intel") return "情报获取";
  return effect || "已结算";
}

function trimText(text: string, maxLength = 140) {
  const cleaned = String(text || "").replace(/\s+/g, " ").trim();
  if (!cleaned) return "";
  return cleaned.length > maxLength ? `${cleaned.slice(0, maxLength)}...` : cleaned;
}

function cloneData<T>(value: T): T {
  if (value === undefined || value === null) return value;
  return JSON.parse(JSON.stringify(value));
}

function roundNumberOf(round: any, fallback = 0) {
  const value = Number(round?.round ?? round?.turn ?? getWorldState(round)?.round ?? fallback);
  return Number.isFinite(value) ? value : fallback;
}

function nodeRowsFromMap(nodes: Record<string, any>) {
  return Object.entries(nodes || {}).map(([id, node]) => ({ id, ...(node || {}) }));
}

function describeActionPair(round: any) {
  const redLog = getAgentLog(round, "Red");
  const blueLog = getAgentLog(round, "Blue");
  const redAction = round?.red_action ?? {};
  const blueAction = round?.blue_action ?? {};
  const redTarget = getActionTarget(redLog, redAction);
  const blueTarget = getActionTarget(blueLog, blueAction);
  const redLabel = getActionLabel(redLog, redAction);
  const blueLabel = getActionLabel(blueLog, blueAction);
  const parts = [];

  if (redLog || Object.keys(redAction).length) {
    parts.push(`红方准备执行 ${redLabel} -> ${redTarget}`);
  }
  if (blueLog || Object.keys(blueAction).length) {
    parts.push(`蓝方准备执行 ${blueLabel} -> ${blueTarget}`);
  }
  return parts.length ? parts.join("；") : "本回合暂无显式动作。";
}

function diffNodeStatus(previous: any, current: any) {
  const previousNodes = getNetworkNodes(previous);
  const currentNodes = getNetworkNodes(current);
  const nodeIds = Array.from(new Set([...Object.keys(previousNodes), ...Object.keys(currentNodes)])).sort();

  return nodeIds
    .map((nodeId) => ({
      node: nodeId,
      from: previousNodes?.[nodeId]?.status ?? "未知",
      to: currentNodes?.[nodeId]?.status ?? "未知",
    }))
    .filter((change) => change.from !== change.to);
}

function createPlaybackFrame(round: any, previousRound: any | null, sourceIndex: number, phase: "start" | "end") {
  const nextFrame = cloneData(round);
  const roundNumber = roundNumberOf(round, sourceIndex);
  const basePrevious = previousRound ? cloneData(previousRound) : null;

  if (phase === "start" && basePrevious) {
    const previousWorld = getWorldState(basePrevious);
    const previousNodes = cloneData(getNetworkNodes(basePrevious));
    const previousScore = cloneData(getScore(basePrevious));
    nextFrame.network_nodes = previousNodes;
    nextFrame.nodes = cloneData(previousWorld?.nodes ?? basePrevious?.nodes ?? nodeRowsFromMap(previousNodes));
    nextFrame.red_score = previousScore?.red ?? basePrevious?.red_score ?? nextFrame?.red_score;
    nextFrame.blue_score = previousScore?.blue ?? basePrevious?.blue_score ?? nextFrame?.blue_score;
    nextFrame.system_health = previousWorld?.system_health ?? basePrevious?.system_health ?? nextFrame?.system_health;
    nextFrame.exposure_level = previousWorld?.exposure_level ?? basePrevious?.exposure_level ?? nextFrame?.exposure_level;
    nextFrame.world_state = {
      ...(nextFrame.world_state ?? {}),
      network_nodes: previousNodes,
      nodes: cloneData(previousWorld?.nodes ?? basePrevious?.nodes ?? nodeRowsFromMap(previousNodes)),
      score: previousScore,
      red_score: previousScore?.red,
      blue_score: previousScore?.blue,
      system_health: previousWorld?.system_health ?? basePrevious?.system_health,
      exposure_level: previousWorld?.exposure_level ?? basePrevious?.exposure_level,
      availability: previousWorld?.availability ?? nextFrame?.world_state?.availability,
    };
  }

  const changes = previousRound ? diffNodeStatus(previousRound, round) : [];
  nextFrame.__source_index = sourceIndex;
  nextFrame.__frame_phase = phase;
  nextFrame.__frame_phase_label = phase === "start" ? "开始快照" : "结束结算";
  nextFrame.__frame_key = `${roundNumber}-${phase}`;
  nextFrame.__frame_changes = phase === "end" ? changes : [];
  nextFrame.__frame_summary = phase === "start"
    ? describeActionPair(round)
    : changes.length
      ? changes.map((change) => `${change.node}: ${translateStatus(change.from, change.from)} -> ${translateStatus(change.to, change.to)}`).join("；")
      : "本回合结算后节点状态无变化。";
  nextFrame.__frame_explanation = phase === "start"
    ? `回合 ${roundNumber} 开始快照：沿用上一回合结束后的节点状态，红蓝动作尚未改变拓扑。这个视角用于检查攻击前置条件、跳板是否存在以及蓝方处置目标。`
    : `回合 ${roundNumber} 结束结算：展示裁判完成红蓝动作判定后的节点状态。若同一回合出现“红方从已恢复节点发起路径”，通常是因为红方动作按回合开始快照执行，而蓝方恢复在结算后改变了节点颜色。`;

  return nextFrame;
}

function buildPlaybackFrames(rounds: any[]) {
  if (!rounds.length) return [];
  const frames: any[] = [];
  rounds.forEach((round, index) => {
    if (index === 0) {
      frames.push(createPlaybackFrame(round, null, index, "end"));
      return;
    }
    frames.push(createPlaybackFrame(round, rounds[index - 1], index, "start"));
    frames.push(createPlaybackFrame(round, rounds[index - 1], index, "end"));
  });

  return frames.map((frame, index) => ({
    ...frame,
    __playback_index: index,
    __playback_count: frames.length,
  }));
}

function MetricTile({ label, value, tone = "slate", subtext }: { label: string; value: string | number; tone?: "red" | "blue" | "green" | "amber" | "slate"; subtext?: string }) {
  const toneClass = {
    red: "border-red-400/50 border-l-[3px] border-l-[#ff6b7a] text-red-200",
    blue: "border-blue-400/50 border-l-[3px] border-l-[#5b9fff] text-blue-200",
    green: "border-emerald-400/35 text-emerald-200",
    amber: "border-amber-400/35 text-amber-200",
    slate: "border-slate-600/50 text-slate-200",
  }[tone];

  return (
    <div className={`rounded-xl border bg-[#162340] px-4 py-3 ${toneClass}`}>
      <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-slate-400">{label}</p>
      <p className="mt-2 text-2xl font-light tracking-wide">{value}</p>
      {subtext ? <p className="mt-1 text-xs text-slate-400">{subtext}</p> : null}
    </div>
  );
}

function StatusPill({ label, value, tone = "slate" }: { label: string; value: string | number; tone?: "red" | "blue" | "green" | "amber" | "slate" }) {
  const toneClass = {
    red: "text-red-200",
    blue: "text-blue-200",
    green: "text-emerald-200",
    amber: "text-amber-200",
    slate: "text-slate-100",
  }[tone];

  return (
    <div className="flex min-w-0 items-baseline gap-2 whitespace-nowrap">
      <span className="font-mono text-[10px] uppercase tracking-[0.13em] text-slate-400">{label}</span>
      <span className={`font-mono text-sm ${toneClass}`}>{value}</span>
    </div>
  );
}

function SituationBar({
  currentRound,
  rounds,
  selectedReplay,
  displayRound,
  totalRounds,
  roundIndex,
  frameCount,
  playing,
  onTogglePlay,
  onNext,
  onSeek,
  onOpenScenarios,
}: {
  currentRound: any;
  rounds: any[];
  selectedReplay: ReplayCatalogItem | null;
  displayRound: number;
  totalRounds: number;
  roundIndex: number;
  frameCount: number;
  playing: boolean;
  onTogglePlay: () => void;
  onNext: () => void;
  onSeek: (index: number) => void;
  onOpenScenarios: () => void;
}) {
  const worldState = getWorldState(currentRound);
  const nodes = getNetworkNodes(currentRound);
  const score = getScore(currentRound);
  const redLog = getAgentLog(currentRound, "Red");
  const redAction = currentRound?.red_action ?? {};
  const actionType = getActionName(redLog, redAction);
  const health = worldState?.system_health ?? currentRound?.system_health ?? 100;
  const nodeRows = Object.values(nodes) as Array<any>;
  const exposedNodes = nodeRows.filter((node) => Object.keys(node?.vulnerabilities ?? {}).length > 0).length;
  const scenarioName = translateScenarioName(currentRound?.scenario ?? rounds[0]?.scenario ?? selectedReplay?.name ?? "CyberArena");
  const coreAssets = worldState?.core_assets ?? currentRound?.core_assets ?? ["db"];
  const coreStatus = coreAssets
    .map((nodeName: string) => `${nodeName} ${translateStatus(nodes?.[nodeName]?.status || "未知")}`)
    .join(" / ");
  const playbackLabel = currentRound?.__frame_phase_label ?? "单帧";
  const playbackStep = `${(currentRound?.__playback_index ?? roundIndex) + 1} / ${currentRound?.__playback_count ?? frameCount}`;

  return (
    <header className="shrink-0 rounded-2xl border border-white/[0.14] bg-[#111a2e] px-4 py-3 shadow-[0_18px_42px_rgba(0,0,0,0.22)]">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-[#8a9bc0]">CyberArena live range</p>
          <h1 className="mt-1 truncate text-xl font-light tracking-wide text-slate-100">{scenarioName}</h1>
        </div>

        <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
          <StatusPill label="Round" value={`${displayRound} / ${totalRounds}`} />
          <StatusPill label="视图" value={playbackLabel} tone={currentRound?.__frame_phase === "start" ? "amber" : "green"} />
          <StatusPill label="帧" value={playbackStep} tone="slate" />
          <StatusPill label="当前阶段" value={phaseFromAction(worldState?.red_phase || actionType)} tone="amber" />
          <StatusPill label="核心资产" value={coreStatus || "未定义"} tone={String(coreStatus).includes("失陷") ? "red" : "green"} />
          <StatusPill label="红方" value={score.red ?? 0} tone="red" />
          <StatusPill label="蓝方" value={score.blue ?? 0} tone="blue" />
          <StatusPill label="系统健康" value={`${Math.round(health)}%`} tone={health < 70 ? "amber" : "green"} />
          <StatusPill label="暴露节点" value={exposedNodes} tone={exposedNodes > 3 ? "amber" : "slate"} />
        </div>

        <div className="flex min-w-[260px] flex-1 items-center justify-end gap-2">
          <button
            type="button"
            onClick={onTogglePlay}
            className="rounded-lg border border-blue-400/40 bg-blue-500/15 px-3 py-1.5 font-mono text-xs text-blue-100 transition hover:bg-blue-400/22"
          >
            {playing ? "暂停" : "播放"}
          </button>
          <button
            type="button"
            onClick={onNext}
            className="rounded-lg border border-slate-500/50 bg-[#162340] px-3 py-1.5 font-mono text-xs text-slate-200 transition hover:border-blue-300/60"
          >
            下一步
          </button>
          <button
            type="button"
            onClick={onOpenScenarios}
            className="rounded-lg border border-emerald-400/25 bg-emerald-400/10 px-3 py-1.5 font-mono text-xs text-emerald-100 transition hover:bg-emerald-400/15"
          >
            场景
          </button>
          <input
            type="range"
            min={0}
            max={Math.max(frameCount - 1, 0)}
            value={roundIndex}
            onChange={(event) => onSeek(Number(event.target.value))}
            className="h-1.5 min-w-36 flex-1 cursor-pointer appearance-none rounded-full bg-[#1c2d4a] accent-blue-500"
          />
        </div>
      </div>
    </header>
  );
}

function BattleLegend() {
  return (
    <div className="flex flex-wrap items-center gap-2 font-mono text-[10px] uppercase tracking-[0.12em]">
      <span className="rounded-full border border-red-400/50 bg-[rgba(255,107,122,0.12)] px-2.5 py-1 text-red-200">攻击 / 失陷</span>
      <span className="rounded-full border border-blue-400/50 bg-[rgba(91,159,255,0.10)] px-2.5 py-1 text-blue-200">防御 / 隔离</span>
      <span className="rounded-full border border-emerald-400/35 bg-emerald-500/15 px-2.5 py-1 text-emerald-200">修复 / 健康</span>
      <span className="rounded-full border border-amber-400/35 bg-amber-500/15 px-2.5 py-1 text-amber-200">告警 / 争夺中</span>
      <span className="rounded-full border border-slate-500/35 bg-slate-500/15 px-2.5 py-1 text-slate-300">离线</span>
    </div>
  );
}

function EventTimeline({ rounds, roundIndex }: { rounds: any[]; roundIndex: number }) {
  const items = useMemo(() => {
    const start = Math.max(0, roundIndex - 6);
    return rounds.slice(start, roundIndex + 1).map((round, offset) => {
      const redLog = getAgentLog(round, "Red");
      const redAction = round?.red_action ?? {};
      const effect = redLog?.metadata?.referee_effect;
      return {
        key: `${round?.turn ?? round?.round ?? start + offset}-${offset}`,
        turn: round?.turn ?? round?.round ?? start + offset,
        action: getActionLabel(redLog, redAction),
        target: getActionTarget(redLog, redAction),
        effect,
        tone: effectTone(effect),
      };
    });
  }, [roundIndex, rounds]);

  return (
    <section className="rounded-2xl border border-white/[0.14] bg-[#111a2e] p-3">
      <div className="flex items-center justify-between">
        <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-400">攻击链时间线</p>
        <span className="font-mono text-[10px] text-slate-400">最近 {items.length} 步</span>
      </div>
      <div className="mt-3 flex items-stretch gap-2 overflow-x-auto pb-1">
        {items.map((item) => {
          const colorClass = {
            red: "border-red-400/40 bg-red-500/[0.09] text-red-200",
            blue: "border-blue-400/40 bg-blue-500/[0.09] text-blue-200",
            amber: "border-amber-400/40 bg-amber-500/[0.09] text-amber-200",
            slate: "border-slate-500/50 bg-[#162340] text-slate-300",
            green: "border-emerald-400/40 bg-emerald-500/[0.09] text-emerald-200",
          }[item.tone as "red" | "blue" | "amber" | "slate" | "green"];
          return (
            <article key={item.key} className={`min-w-[150px] rounded-xl border px-3 py-2 ${colorClass}`}>
              <p className="font-mono text-[10px] text-slate-400">T{item.turn}</p>
              <p className="mt-1 truncate text-sm text-slate-100">{item.action}</p>
              <p className="mt-1 truncate font-mono text-[11px] opacity-80">{item.target}</p>
              <p className="mt-2 font-mono text-[10px]">{effectLabel(item.effect)}</p>
            </article>
          );
        })}
      </div>
    </section>
  );
}

function SocAlertFlow({ rounds, roundIndex }: { rounds: any[]; roundIndex: number }) {
  const alerts = useMemo(() => {
    const rows: any[] = [];
    for (let index = Math.max(0, roundIndex - 4); index <= roundIndex; index += 1) {
      const round = rounds[index];
      if (!round) continue;
      const roundAlerts = Array.isArray(round.security_alerts) ? round.security_alerts : [];
      roundAlerts.forEach((alert: any, alertIndex: number) => rows.push({
        id: `${index}-${alertIndex}-${alert?.target || "global"}`,
        turn: round.turn ?? round.round ?? index,
        severity: alert?.severity || "INFO",
        message: trimText(alert?.message || "安全告警", 88),
        target: alert?.target || "global",
      }));
    }
    return rows.slice(-5);
  }, [roundIndex, rounds]);

  return (
    <section className="rounded-2xl border border-white/[0.14] bg-[#111a2e] p-3">
      <div className="flex items-center justify-between">
        <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-400">SOC 告警流</p>
        <span className="font-mono text-[10px] text-slate-400">{alerts.length} 条</span>
      </div>
      <div className="mt-3 max-h-28 space-y-2 overflow-y-auto pr-1">
        {alerts.length ? alerts.map((alert) => (
          <div key={alert.id} className="rounded-lg border border-amber-400/20 bg-amber-400/[0.06] px-3 py-2 text-xs text-slate-300">
            <span className="mr-2 font-mono text-amber-300">[{alert.severity}]</span>
            <span className="mr-2 text-slate-400">T{alert.turn} / {alert.target}</span>
            {alert.message}
          </div>
        )) : (
          <p className="rounded-lg border border-[#304060] bg-[#162340] px-3 py-2 text-xs text-[#8a9bc0]">当前窗口暂无新增告警。</p>
        )}
      </div>
    </section>
  );
}

function ReplayControlPanel({ selectedReplay, onLoadReplay }: { selectedReplay: ReplayCatalogItem | null; onLoadReplay: (replay: ReplayCatalogItem, options?: { autoplay?: boolean }) => Promise<void> | void }) {
  return (
    <section className="rounded-2xl border border-white/[0.14] bg-[#111a2e] p-3">
      <ReplayPicker compact selectedReplayId={selectedReplay?.id} onLoadReplay={onLoadReplay} />
    </section>
  );
}

function BottomDeck({
  rounds,
  roundIndex,
  currentRound,
  selectedReplay,
  onLoadReplay,
}: {
  rounds: any[];
  roundIndex: number;
  currentRound: any;
  selectedReplay: ReplayCatalogItem | null;
  onLoadReplay: (replay: ReplayCatalogItem, options?: { autoplay?: boolean }) => Promise<void> | void;
}) {
  const [terminalOpen, setTerminalOpen] = useState(false);

  return (
    <section className="bottom-deck shrink-0 space-y-2">
      <div className="bottom-grid">
        <EventTimeline rounds={rounds} roundIndex={roundIndex} />
        <SocAlertFlow rounds={rounds} roundIndex={roundIndex} />
        <ReplayControlPanel selectedReplay={selectedReplay} onLoadReplay={onLoadReplay} />
      </div>

      <div className="rounded-2xl border border-white/[0.14] bg-[#111a2e]">
        <button
          type="button"
          onClick={() => setTerminalOpen((open) => !open)}
          className="flex w-full items-center justify-between px-4 py-3 text-left"
        >
          <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-400">实时安全终端</span>
          <span className="rounded-md border border-slate-600/60 px-2 py-1 font-mono text-[10px] text-slate-400">
            {terminalOpen ? "收起" : "展开"}
          </span>
        </button>
        {terminalOpen ? (
          <div className="h-40 border-t border-white/[0.14] p-2">
            <TerminalLogs round={currentRound} />
          </div>
        ) : null}
      </div>
    </section>
  );
}

function BattleWorkbench({
  rounds,
  currentRound,
  roundIndex,
  displayRound,
  totalRounds,
  frameCount,
  playing,
  selectedReplay,
  onTogglePlay,
  onNext,
  onSeek,
  onLoadReplay,
  onOpenScenarios,
}: {
  rounds: any[];
  currentRound: any;
  roundIndex: number;
  displayRound: number;
  totalRounds: number;
  frameCount: number;
  playing: boolean;
  selectedReplay: ReplayCatalogItem | null;
  onTogglePlay: () => void;
  onNext: () => void;
  onSeek: (index: number) => void;
  onLoadReplay: (replay: ReplayCatalogItem, options?: { autoplay?: boolean }) => Promise<void> | void;
  onOpenScenarios: () => void;
}) {
  const sourceRoundIndex = currentRound?.__source_index ?? roundIndex;

  return (
    <div className="battle-workbench">
      <SituationBar
        currentRound={currentRound}
        rounds={rounds}
        selectedReplay={selectedReplay}
        displayRound={displayRound}
        totalRounds={totalRounds}
        roundIndex={roundIndex}
        frameCount={frameCount}
        playing={playing}
        onTogglePlay={onTogglePlay}
        onNext={onNext}
        onSeek={onSeek}
        onOpenScenarios={onOpenScenarios}
      />

      <main className="battle-main">
        <section className="battle-map relative overflow-hidden rounded-[24px] border border-white/[0.14] bg-[#111a2e] shadow-[0_22px_54px_rgba(0,0,0,0.28)]">
          <div className="absolute left-4 top-4 z-10">
            <BattleLegend />
          </div>
          <div className="absolute right-4 top-4 z-10 max-w-[420px] rounded-xl border border-white/[0.14] bg-[#162340] px-3 py-2 shadow-[0_12px_28px_rgba(0,0,0,0.25)]">
            <div className="flex items-center gap-2">
              <span className={`rounded-md border px-2 py-1 font-mono text-[10px] ${currentRound?.__frame_phase === "start" ? "border-amber-400/40 text-amber-200" : "border-emerald-400/40 text-emerald-200"}`}>
                {currentRound?.__frame_phase_label ?? "回放帧"}
              </span>
              <span className="font-mono text-[10px] text-slate-400">T{displayRound}</span>
            </div>
            <p className="mt-2 line-clamp-2 text-xs leading-5 text-slate-300">{currentRound?.__frame_summary ?? "当前拓扑状态。"}</p>
          </div>
          <div className="battle-map-canvas">
            <TopologyVisualizer round={currentRound} rounds={rounds} roundIndex={sourceRoundIndex} variant="embedded" />
          </div>
        </section>

        <aside className="battle-analysis min-h-0">
          <ReasoningPanel round={currentRound} />
        </aside>
      </main>

      <BottomDeck
        rounds={rounds}
        roundIndex={sourceRoundIndex}
        currentRound={currentRound}
        selectedReplay={selectedReplay}
        onLoadReplay={onLoadReplay}
      />
    </div>
  );
}

function AnalysisPage({ rounds, currentRound, roundIndex, totalRounds }: { rounds: any[]; currentRound: any; roundIndex: number; totalRounds: number }) {
  const summary = useMemo(() => {
    let redActions = 0;
    let blocked = 0;
    let illegal = 0;
    const keyTurns: Array<string> = [];

    rounds.forEach((round) => {
      const red = getAgentLog(round, "Red");
      const blue = getAgentLog(round, "Blue");
      const referee = getAgentLog(round, "Referee");
      if (red) {
        redActions += 1;
        if (["blocked", "failed"].includes(String(red.metadata?.referee_effect || "").toLowerCase())) {
          blocked += 1;
        }
        if (red.metadata?.validation === "failed") {
          illegal += 1;
        }
      }
      if (blue?.metadata?.validation === "failed") {
        illegal += 1;
      }
      const interaction = referee?.metadata?.interaction?.type;
      if (interaction && interaction !== "independent") {
        keyTurns.push(`T${round.turn ?? round.round}: ${interaction}`);
      }
    });

    return {
      blocked,
      illegal,
      blockRate: redActions ? Math.round((blocked / redActions) * 100) : 0,
      keyTurns: keyTurns.slice(0, 6),
    };
  }, [rounds]);
  const score = getScore(currentRound);

  return (
    <div className="flex h-full min-h-0 flex-col overflow-y-auto px-6 py-5">
      <div className="shrink-0">
        <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-[#8a9bc0]">Post simulation review</p>
        <h1 className="mt-1 text-2xl font-light tracking-wide text-slate-100">结果分析</h1>
        <p className="mt-1 text-sm text-slate-400">把复杂回放压缩成胜负、转折点和异常动作，方便演示后复盘。</p>
      </div>

      <section className="mt-5 grid grid-cols-2 gap-4 xl:grid-cols-4">
        <MetricTile label="最终红方" value={score.red ?? 0} tone="red" />
        <MetricTile label="最终蓝方" value={score.blue ?? 0} tone="blue" />
        <MetricTile label="蓝方拦截率" value={`${summary.blockRate}%`} tone="amber" />
        <MetricTile label="非法动作" value={summary.illegal} tone={summary.illegal ? "amber" : "green"} />
      </section>

      <section className="mt-5 grid min-h-[260px] grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
        <LiveScoreChart rounds={rounds} currentRoundIndex={roundIndex} totalRounds={totalRounds} />
        <article className="rounded-2xl border border-white/[0.14] bg-[#111a2e] p-4">
          <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-400">关键转折</p>
          <div className="mt-4 space-y-2 text-sm text-slate-300">
            {summary.keyTurns.length ? summary.keyTurns.map((item) => (
              <div key={item} className="rounded-lg border border-amber-400/20 bg-amber-400/[0.07] px-3 py-2 text-amber-100">
                {item}
              </div>
            )) : <p className="text-[#8a9bc0]">本次回放没有显著的同回合交互事件。</p>}
          </div>
        </article>
      </section>

      <section className="mt-5 rounded-2xl border border-white/[0.14] bg-[#111a2e] p-4">
        <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-400">当前结论</p>
        <p className="mt-3 max-w-4xl text-sm leading-7 text-slate-300">
          这场回放红方得分领先，但最终节点状态和胜负字段需要结合裁判规则复核。建议演示时强调关键路径和裁判裁定，评测时关注非法动作率、胜负锁定字段和核心资产最终状态。
        </p>
      </section>
    </div>
  );
}

function PlaceholderPage({ title, description }: { title: string; description: string }) {
  return (
    <div className="flex h-full items-center justify-center p-8">
      <div className="w-full max-w-2xl rounded-2xl border border-white/[0.14] bg-[#111a2e] p-8 text-center shadow-[0_20px_45px_rgba(2,8,22,0.4)]">
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-slate-400">{title}</p>
        <h2 className="mt-3 text-2xl font-semibold text-slate-100">模块建设中</h2>
        <p className="mt-3 text-sm leading-7 text-slate-400">{description}</p>
      </div>
    </div>
  );
}

function App() {
  const [activeTab, setActiveTab] = useState<AppTabKey>("demo");
  const [rounds, setRounds] = useState(() => FALLBACK_ROUNDS);
  const [roundIndex, setRoundIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [selectedScenario, setSelectedScenario] = useState<ScenarioCatalogItem | null>(null);
  const [selectedReplay, setSelectedReplay] = useState<ReplayCatalogItem | null>(null);

  useEffect(() => {
    let cancelled = false;

    fetch("/simulation_20_rounds_eval.json")
      .then((response) => response.json())
      .then((payload) => {
        if (cancelled) {
          return;
        }
        const normalized = normalizeRoundsPayload(payload);
        if (normalized.length) {
          setRounds(normalized);
          setSelectedReplay({
            id: "simulation_20_rounds_eval",
            name: "20 回合攻防评估回放",
            summary: "已完成模拟的红蓝双方 20 回合攻防过程。",
            path: "/simulation_20_rounds_eval.json",
            rounds: normalized.length,
            tags: ["已模拟"],
          });
        }
      })
      .catch((error) => {
        console.error("回放数据加载失败，使用本地示例帧。", error);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const playbackFrames = useMemo(() => buildPlaybackFrames(rounds), [rounds]);
  const frameCount = playbackFrames.length || FALLBACK_ROUNDS.length;

  useEffect(() => {
    setRoundIndex((current) => Math.min(current, Math.max(frameCount - 1, 0)));
  }, [frameCount]);

  useEffect(() => {
    if (!playing || frameCount <= 1) {
      return undefined;
    }

    const timer = window.setInterval(() => {
      setRoundIndex((current) => {
        if (current >= frameCount - 1) {
          setPlaying(false);
          return current;
        }
        return current + 1;
      });
    }, 1850);

    return () => window.clearInterval(timer);
  }, [frameCount, playing]);

  const safeIndex = Math.min(roundIndex, Math.max(frameCount - 1, 0));
  const currentRound = useMemo(
    () => playbackFrames[safeIndex] ?? FALLBACK_ROUNDS[Math.min(safeIndex, FALLBACK_ROUNDS.length - 1)],
    [playbackFrames, safeIndex],
  );
  const totalRounds = useMemo(() => {
    const fromCurrent = Number(currentRound?.total_rounds ?? currentRound?.totalRounds);
    if (Number.isFinite(fromCurrent) && fromCurrent > 0) {
      return fromCurrent;
    }

    const fromList = rounds
      .map((item: any) => Number(item?.total_rounds ?? item?.totalRounds))
      .find((value: number) => Number.isFinite(value) && value > 0);
    if (typeof fromList === "number") {
      return fromList;
    }

    const turns = rounds
      .map((item: any) => Number(item?.round ?? item?.turn))
      .filter((value: number) => Number.isFinite(value) && value >= 0);
    if (turns.length) {
      return Math.max(...turns);
    }

    return Math.max(frameCount - 1, 1);
  }, [currentRound, frameCount, rounds]);

  const rawRoundValue = Number(currentRound?.round ?? currentRound?.turn ?? currentRound?.world_state?.round ?? currentRound?.__source_index ?? safeIndex);
  const displayRound = Number.isFinite(rawRoundValue)
    ? Math.min(Math.max(rawRoundValue, 0), totalRounds)
    : Math.min(Math.max(safeIndex, 0), totalRounds);

  const handleSeek = (nextIndex: number) => {
    setPlaying(false);
    const clamped = Math.min(Math.max(nextIndex, 0), Math.max(frameCount - 1, 0));
    setRoundIndex(clamped);
  };

  const handleNext = () => {
    setPlaying(false);
    setRoundIndex((current) => Math.min(current + 1, Math.max(frameCount - 1, 0)));
  };

  const handleLoadReplay = async (replay: ReplayCatalogItem, options?: { autoplay?: boolean }) => {
    let normalized = FALLBACK_ROUNDS;
    if (replay.path === "__builtin_default_rounds__") {
      normalized = normalizeRoundsPayload(DEFAULT_ROUNDS);
    } else {
      const response = await fetch(replay.path);
      if (!response.ok) {
        throw new Error(`回放文件请求失败：${response.status}`);
      }
      const payload = await response.json();
      normalized = normalizeRoundsPayload(payload);
    }

    if (!normalized.length) {
      throw new Error("回放文件中没有可用帧");
    }

    setSelectedReplay({ ...replay, rounds: replay.rounds ?? normalized.length });
    setSelectedScenario(null);
    setRounds(normalized);
    setRoundIndex(0);
    setPlaying(Boolean(options?.autoplay && normalized.length > 1));
    setActiveTab("demo");
  };

  const handleStartScenario = (scenario: ScenarioCatalogItem) => {
    const normalized = normalizeRoundsPayload([scenario.initial_frame]);
    setSelectedScenario(scenario);
    setSelectedReplay(null);
    setRounds(normalized.length ? normalized : FALLBACK_ROUNDS);
    setActiveTab("demo");
    setRoundIndex(0);
    setPlaying(false);
  };

  return (
    <div className="h-screen w-screen overflow-hidden bg-[#0c1220] text-slate-100">
      <div className="flex h-full overflow-hidden bg-[linear-gradient(135deg,rgba(12,18,32,0.98),rgba(17,26,46,0.96)),radial-gradient(circle_at_72%_8%,rgba(91,159,255,0.15),transparent_42%),radial-gradient(circle_at_8%_24%,rgba(52,224,141,0.08),transparent_34%)]">
        <aside className="relative w-60 shrink-0 border-r border-white/[0.14] bg-[#111a2e] shadow-[10px_0_35px_rgba(0,0,0,0.28)] backdrop-blur-sm">
          <div className="px-5 pb-4 pt-7">
            <div className="flex items-center">
              <div className="origin-left scale-[1.65]">
                <CyberArenaLogo />
              </div>
              <p className="ml-8 font-mono text-[12px] uppercase tracking-[0.2em] text-cyan-200">MACSim</p>
            </div>
            <div className="mt-4">
              <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-300">多智能体网络安全仿真器</p>
              <p className="text-[11px] text-slate-400">攻防演示控制台</p>
            </div>
          </div>

          <nav className="space-y-1.5 px-3 py-2">
            {NAV_ITEMS.map((item) => {
              const isActive = activeTab === item.key;
              return (
                <button
                  key={item.key}
                  type="button"
                  onClick={() => setActiveTab(item.key)}
                  className={`group relative w-full rounded-xl px-4 py-3 text-left transition ${
                    isActive
                      ? "border border-blue-400/30 bg-blue-400/15 shadow-[0_8px_22px_rgba(2,8,22,0.32)]"
                      : "border border-transparent bg-transparent hover:bg-white/[0.06]"
                  }`}
                >
                  <span
                    className={`absolute left-0 top-1/2 h-8 w-[2px] -translate-y-1/2 rounded-r-full transition ${
                      isActive ? "bg-blue-400 shadow-[0_0_12px_rgba(91,159,255,0.85)]" : "bg-transparent"
                    }`}
                  />
                  <p className={`font-mono text-[11px] uppercase tracking-[0.11em] ${isActive ? "text-slate-100" : "text-slate-400 group-hover:text-slate-200"}`}>
                    {item.label}
                  </p>
                  <p className={`mt-1 text-[11px] ${isActive ? "text-slate-400" : "text-slate-400 group-hover:text-slate-300"}`}>{item.subtitle}</p>
                </button>
              );
            })}
          </nav>
        </aside>

        <section className="min-w-0 flex-1 overflow-hidden">
          {activeTab === "demo" ? (
            <BattleWorkbench
              rounds={rounds}
              currentRound={currentRound}
              roundIndex={safeIndex}
              displayRound={displayRound}
              totalRounds={totalRounds}
              frameCount={frameCount}
              playing={playing}
              selectedReplay={selectedReplay}
              onTogglePlay={() => setPlaying((current) => !current)}
              onNext={handleNext}
              onSeek={handleSeek}
              onLoadReplay={handleLoadReplay}
              onOpenScenarios={() => setActiveTab("scenarios")}
            />
          ) : null}

          {activeTab === "scenarios" ? (
            <ScenarioSelection
              selectedScenario={selectedScenario}
              onSelectScenario={setSelectedScenario}
              onStartScenario={handleStartScenario}
            />
          ) : null}

          {activeTab === "analysis" ? (
            <AnalysisPage
              rounds={rounds}
              currentRound={currentRound}
              roundIndex={safeIndex}
              totalRounds={totalRounds}
            />
          ) : null}

          {activeTab === "settings" ? (
            <PlaceholderPage
              title="设置"
              description="后续可承载模型密钥、推理参数、日志级别、概率门控和导出策略。"
            />
          ) : null}
        </section>
      </div>
    </div>
  );
}

export default App;
