import { useMemo } from "react";

import TopologyVisualizer from "./TopologyVisualizer";

type HomeDashboardProps = {
  onStartNewSimulation?: () => void;
  onViewReplay?: (simulationId: string) => void;
  rounds?: any[];
  currentRound?: any;
  roundIndex?: number;
  totalRounds?: number;
};

type SimulationRecord = {
  id: string;
  scenario: string;
  rounds: number;
  winner: "Red" | "Blue" | "Draw";
  finishedAt: string;
};

function ProgressBar({ value = 0, tone = "from-blue-400 to-cyan-300" }: { value?: number; tone?: string }) {
  const safe = Math.max(0, Math.min(100, Math.round(value)));
  return (
    <div className="mt-2 h-1 w-full rounded-full bg-slate-800/70">
      <div className={`h-full rounded-full bg-gradient-to-r ${tone}`} style={{ width: `${safe}%` }} />
    </div>
  );
}

function winnerTone(winner: SimulationRecord["winner"]) {
  if (winner === "Red") {
    return "text-red-300";
  }
  if (winner === "Blue") {
    return "text-cyan-300";
  }
  return "text-slate-300";
}

function HomeDashboard({
  onStartNewSimulation,
  onViewReplay,
  rounds = [],
  currentRound,
  roundIndex = 0,
  totalRounds = 20,
}: HomeDashboardProps) {
  const worldState = currentRound?.world_state ?? {};
  const score = worldState.score ?? { red: currentRound?.red_score ?? 0, blue: currentRound?.blue_score ?? 0 };
  const totalScore = (score.red ?? 0) + (score.blue ?? 0);
  const redPressure = totalScore > 0 ? (score.red / totalScore) * 100 : 50;
  const blueControl = totalScore > 0 ? (score.blue / totalScore) * 100 : 50;
  const availability = typeof worldState.availability === "number" ? worldState.availability * 100 : 100;
  const rawExposure = typeof worldState.exposure_level === "number" ? worldState.exposure_level : 0;
  const exposure = rawExposure <= 1 ? rawExposure * 100 : rawExposure;
  const compromisedCount = Array.isArray(worldState.nodes)
    ? worldState.nodes.filter((node: any) => ["compromised", "down", "isolated"].includes(String(node?.status || "").toLowerCase())).length
    : 0;
  const safeRoundNumber = Number(currentRound?.round ?? currentRound?.turn ?? roundIndex + 1);
  const displayRound = Number.isFinite(safeRoundNumber)
    ? Math.min(Math.max(Math.round(safeRoundNumber), 1), Math.max(totalRounds, 1))
    : 1;

  const scenarioName = useMemo(() => {
    const fromRound = currentRound?.scenario ?? rounds[0]?.scenario;
    return fromRound || "Level 1 Basic Web";
  }, [currentRound, rounds]);

  const recentRecords = useMemo<SimulationRecord[]>(() => {
    const nowRecord: SimulationRecord = {
      id: "SIM-2026-0418-LIVE",
      scenario: scenarioName,
      rounds: totalRounds,
      winner: score.red > score.blue ? "Red" : score.red < score.blue ? "Blue" : "Draw",
      finishedAt: "Live session",
    };
    return [
      nowRecord,
      { id: "SIM-2026-0418-0020", scenario: "Level 2 Ransomware", rounds: 20, winner: "Red", finishedAt: "14 mins ago" },
      { id: "SIM-2026-0418-0019", scenario: "Level 1 Basic Web", rounds: 20, winner: "Blue", finishedAt: "39 mins ago" },
      { id: "SIM-2026-0418-0018", scenario: "Level 3 Multi-Step Intrusion", rounds: 20, winner: "Red", finishedAt: "1 hour ago" },
      { id: "SIM-2026-0418-0017", scenario: "Level 2 Ransomware", rounds: 20, winner: "Blue", finishedAt: "2 hours ago" },
    ];
  }, [scenarioName, totalRounds, score.red, score.blue]);

  const tactics = useMemo(() => {
    const counts = new Map<string, number>();
    rounds.slice(Math.max(0, roundIndex - 11), roundIndex + 1).forEach((item) => {
      const actionType = String(
        item?.red_action?.action_type
          ?? item?.red_action?.technique_id
          ?? item?.red_action?.technique
          ?? "",
      ).trim();
      if (!actionType) {
        return;
      }
      counts.set(actionType, (counts.get(actionType) ?? 0) + 1);
    });

    const top = [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
      .map(([label, count]) => ({ label, value: Math.round((count / Math.max(1, roundIndex + 1)) * 100) }));

    if (top.length) {
      return top;
    }

    return [
      { label: "ExploitService", value: 38 },
      { label: "LateralMove", value: 27 },
      { label: "CredentialAbuse", value: 21 },
      { label: "ReconScan", value: 14 },
    ];
  }, [rounds, roundIndex]);

  const blueBlockRate = useMemo(() => {
    const windowStart = Math.max(0, roundIndex - 9);
    const recent = rounds.slice(windowStart, roundIndex + 1);
    let attempts = 0;
    let blocked = 0;

    recent.forEach((item) => {
      const hasAction = !!(
        item?.red_action?.action_type
        || item?.red_action?.technique
        || item?.red_action?.technique_id
      );
      if (!hasAction) {
        return;
      }
      attempts += 1;
      if (item?.judge_result?.success === false) {
        blocked += 1;
      }
    });

    if (!attempts) {
      return 64;
    }
    return Math.round((blocked / attempts) * 100);
  }, [rounds, roundIndex]);

  const alerts = useMemo(() => {
    const extracted = (currentRound?.action_logs ?? [])
      .filter((line: string) => /(critical|alert|compromised|down|isolated|ransom|breach)/i.test(line))
      .slice(0, 6);

    if (extracted.length) {
      return extracted;
    }

    return [
      "ALERT: Suspicious lateral movement attempts observed on app-tier.",
      "CRITICAL: Web service vulnerability remains exposed (CVE metadata pending).",
      "ALERT: Firewall policy drift detected against baseline profile.",
      "WARN: Database node reported elevated authentication failures.",
      "ALERT: Blue patch queue backlog is increasing under attack load.",
    ];
  }, [currentRound]);

  const systemHealth = Math.max(0, Math.min(100, Math.round(availability - compromisedCount * 6)));

  return (
    <div className="h-full overflow-hidden px-6 py-4">
      <div className="flex h-full min-h-0 flex-col gap-4">
        <section className="grid min-h-0 flex-1 grid-cols-12 grid-rows-[minmax(0,1fr)_220px] gap-4">
          <div className="col-span-12 row-start-1 min-h-0 xl:col-span-8">
            <div className="relative flex h-full min-h-0 flex-col overflow-hidden rounded-[30px] bg-[#0b1222]/55 px-6 py-5 shadow-[0_22px_45px_rgba(2,8,24,0.4)]">
              <span className="pointer-events-none absolute inset-x-12 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/45 to-transparent" />

              <div className="shrink-0">
                <p className="font-mono text-[10px] uppercase tracking-[0.26em] text-slate-500">Live Operations</p>
                <h1 className="mt-2 text-[2rem] font-light tracking-wide text-slate-100">
                  Live Simulation - {scenarioName}
                </h1>
                <p className="mt-2 text-sm text-slate-400">
                  Round {displayRound} / {totalRounds} | Compromised nodes: {compromisedCount} | Status:{" "}
                  <span className={compromisedCount > 0 ? "text-amber-300" : "text-emerald-300"}>
                    {compromisedCount > 0 ? "Threat Active" : "Stable"}
                  </span>
                </p>
              </div>

              <div className="mt-5 flex min-h-0 flex-1 flex-col overflow-hidden rounded-[24px] bg-[#060b16]/35">
                <div className="flex shrink-0 items-center justify-end gap-2 px-4 pt-3 text-[10px] font-mono uppercase tracking-[0.16em]">
                  <span className="rounded-full bg-emerald-500/15 px-2 py-0.5 text-emerald-300">Normal</span>
                  <span className="rounded-full bg-red-500/15 px-2 py-0.5 text-red-300">Compromised</span>
                  <span className="rounded-full bg-slate-500/20 px-2 py-0.5 text-slate-300">Down</span>
                </div>
                <div className="min-h-0 flex-1 overflow-hidden p-2">
                  <TopologyVisualizer round={currentRound} rounds={rounds} roundIndex={roundIndex} variant="embedded" />
                </div>
              </div>
            </div>
          </div>

          <aside className="col-span-12 row-start-1 min-h-0 xl:col-span-4">
            <div className="relative h-full overflow-y-auto rounded-[28px] bg-[#0b1222]/62 px-5 py-5 shadow-[0_18px_38px_rgba(2,8,24,0.36)]">
              <span className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-blue-300/40 to-transparent" />

              <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-slate-500">Map Statistics</p>
              <p className="mt-1 text-sm font-light tracking-wide text-slate-200">Simulation Telemetry</p>

              <button
                type="button"
                onClick={() => onStartNewSimulation?.()}
                className="mt-4 w-full rounded-xl bg-gradient-to-r from-cyan-500/30 via-blue-500/35 to-cyan-400/20 px-4 py-2.5 font-mono text-xs uppercase tracking-[0.14em] text-cyan-100 shadow-[0_0_20px_rgba(34,211,238,0.32)] transition hover:brightness-110"
              >
                Start New Simulation
              </button>

              <div className="mt-6 space-y-4 text-xs text-slate-400">
                <div>
                  <div className="flex items-center justify-between">
                    <span>Red vs Blue Pressure</span>
                    <span className="text-slate-300">{Math.round(redPressure)} / {Math.round(blueControl)}</span>
                  </div>
                  <ProgressBar value={redPressure} tone="from-red-400 to-rose-300" />
                </div>
                <div>
                  <div className="flex items-center justify-between">
                    <span>Exposure Level</span>
                    <span className="text-slate-300">{Math.round(exposure)}%</span>
                  </div>
                  <ProgressBar value={exposure} tone="from-amber-400 to-orange-300" />
                </div>
                <div>
                  <div className="flex items-center justify-between">
                    <span>System Health</span>
                    <span className="text-slate-300">{systemHealth}%</span>
                  </div>
                  <ProgressBar value={systemHealth} tone="from-emerald-400 to-cyan-300" />
                </div>
              </div>

              <div className="mt-7 space-y-2 text-xs">
                <div className="flex items-center justify-between text-slate-500">
                  <span>Round Window</span>
                  <span className="text-slate-200">{displayRound} / {totalRounds}</span>
                </div>
                <div className="flex items-center justify-between text-slate-500">
                  <span>Red Score</span>
                  <span className="text-red-300">{score.red ?? 0}</span>
                </div>
                <div className="flex items-center justify-between text-slate-500">
                  <span>Blue Score</span>
                  <span className="text-cyan-300">{score.blue ?? 0}</span>
                </div>
                <div className="flex items-center justify-between text-slate-500">
                  <span>Latest Winner</span>
                  <span className={winnerTone(recentRecords[0]?.winner ?? "Draw")}>{recentRecords[0]?.winner ?? "Draw"}</span>
                </div>
              </div>

              <button
                type="button"
                onClick={() => onViewReplay?.(recentRecords[0]?.id ?? "SIM-LIVE")}
                className="mt-6 w-full rounded-xl bg-white/[0.05] px-4 py-2 text-xs tracking-wide text-slate-200 transition hover:bg-white/[0.09]"
              >
                View Replay Timeline
              </button>
            </div>
          </aside>

          <div className="col-span-12 row-start-2 grid min-h-0 grid-cols-1 gap-4 lg:grid-cols-3">
            <article className="relative overflow-hidden rounded-2xl bg-[#0a1120]/75 p-4 shadow-[0_14px_34px_rgba(2,8,24,0.3)]">
              <span className="pointer-events-none absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-red-300/45 to-transparent" />
              <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-slate-500">Red Agent Tactics</p>
              <div className="mt-4 space-y-3 text-xs">
                {tactics.map((item) => (
                  <div key={item.label}>
                    <div className="flex items-center justify-between text-slate-400">
                      <span className="truncate pr-3">{item.label}</span>
                      <span className="text-red-300">{item.value}%</span>
                    </div>
                    <ProgressBar value={item.value} tone="from-red-400 to-rose-300" />
                  </div>
                ))}
              </div>
            </article>

            <article className="relative overflow-hidden rounded-2xl bg-[#0a1120]/75 p-4 shadow-[0_14px_34px_rgba(2,8,24,0.3)]">
              <span className="pointer-events-none absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/45 to-transparent" />
              <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-slate-500">Blue Agent Block Rate</p>
              <div className="mt-4">
                <p className="text-4xl font-light tracking-wide text-cyan-200">{blueBlockRate}%</p>
                <p className="mt-2 text-xs text-slate-400">Recent 10-turn defensive interception efficiency.</p>
                <div className="mt-4">
                  <ProgressBar value={blueBlockRate} tone="from-cyan-300 to-blue-300" />
                </div>
              </div>
              <div className="mt-6 grid grid-cols-2 gap-3 text-xs">
                <div className="rounded-xl bg-white/[0.03] px-3 py-2">
                  <p className="text-slate-500">Intercepted</p>
                  <p className="mt-1 text-cyan-200">{Math.max(1, Math.round((blueBlockRate / 100) * 10))}/10</p>
                </div>
                <div className="rounded-xl bg-white/[0.03] px-3 py-2">
                  <p className="text-slate-500">Patch Queue</p>
                  <p className="mt-1 text-slate-200">{Math.max(2, compromisedCount + 1)} active</p>
                </div>
              </div>
            </article>

            <article className="relative overflow-hidden rounded-2xl bg-[#0a1120]/75 p-4 shadow-[0_14px_34px_rgba(2,8,24,0.3)]">
              <span className="pointer-events-none absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-amber-300/45 to-transparent" />
              <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-slate-500">Recent Critical Alerts</p>
              <ul className="mt-3 space-y-2 overflow-y-auto pr-1 text-xs text-slate-300">
                {alerts.map((item) => (
                  <li key={item} className="rounded-lg bg-white/[0.03] px-3 py-2 leading-5 text-slate-300">
                    <span className="mr-2 text-amber-300">[ALERT]</span>
                    {item}
                  </li>
                ))}
              </ul>
            </article>
          </div>
        </section>
      </div>
    </div>
  );
}

export default HomeDashboard;
