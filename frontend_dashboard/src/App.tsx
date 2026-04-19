import { useCallback, useEffect, useMemo, useState } from "react";

import HomeDashboard from "./components/HomeDashboard";
import ReasoningPanel from "./components/ReasoningPanel";
import SimulationHistory, { type SimulationHistoryItem } from "./components/SimulationHistory";
import type { SimulationLaunchConfig } from "./components/SimulationModal";
import TerminalLogs from "./components/TerminalLogs";
import TopBar, { CyberArenaLogo } from "./components/TopBar";
import TopologyVisualizer from "./components/TopologyVisualizer";
import { DEFAULT_ROUNDS, normalizeRoundsPayload } from "./components/NetworkTopology/data";

const FALLBACK_ROUNDS = normalizeRoundsPayload(DEFAULT_ROUNDS);
const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim() || "http://127.0.0.1:8000";

type AppTabKey = "dashboard" | "replay" | "scenarios" | "settings";

const NAV_ITEMS: Array<{ key: AppTabKey; label: string; subtitle: string }> = [
  { key: "dashboard", label: "Dashboard", subtitle: "Overview" },
  { key: "replay", label: "Simulation Replay", subtitle: "Attack/Defense Playback" },
  { key: "scenarios", label: "Simulation History", subtitle: "Stored Replays" },
  { key: "settings", label: "Settings", subtitle: "System Controls" },
];

type NoticeTone = "info" | "success" | "error";

type UiNotice = {
  id: number;
  text: string;
  tone: NoticeTone;
};

type ReportViewerState = {
  title: string;
  content: string;
};

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(url, init);
  } catch {
    throw new Error(
      `Cannot connect to backend API (${API_BASE_URL}). Start FastAPI: python -m uvicorn backend_engine.serve_replay:app --host 127.0.0.1 --port 8000 --reload`,
    );
  }

  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const payload = (await response.json()) as { detail?: string };
      if (payload?.detail) {
        detail = payload.detail;
      }
    } catch {
      // Keep default detail when server response is not JSON.
    }
    throw new Error(detail);
  }

  return (await response.json()) as T;
}

function safeNumber(value: unknown, fallback = 0): number {
  return Number.isFinite(Number(value)) ? Number(value) : fallback;
}

function inferTotalRoundsFromNormalized(rounds: any[]): number {
  const explicitTotal = rounds
    .map((item) => safeNumber(item?.total_rounds ?? item?.totalRounds, -1))
    .find((value) => value > 0);
  if (typeof explicitTotal === "number" && explicitTotal > 0) {
    return explicitTotal;
  }

  const maxTurn = rounds
    .map((item) => safeNumber(item?.round ?? item?.turn ?? item?.world_state?.round, 0))
    .reduce((max, turn) => Math.max(max, turn), 0);
  if (maxTurn > 0) {
    return maxTurn;
  }

  return Math.max(rounds.length - 1, 1);
}

function buildLocalHistoryItem(file: string, rounds: any[], simulationId: string): SimulationHistoryItem {
  const latest = rounds[rounds.length - 1] ?? {};
  const score = latest?.world_state?.score ?? {};
  const redScore = safeNumber(score.red ?? latest?.red_score, 0);
  const blueScore = safeNumber(score.blue ?? latest?.blue_score, 0);
  const scenario = String(latest?.scenario ?? rounds[0]?.scenario ?? "level_1_basic_web");
  const winner = redScore > blueScore ? "Red" : blueScore > redScore ? "Blue" : "Draw";

  return {
    file,
    simulation_id: simulationId,
    scenario,
    rounds: inferTotalRoundsFromNormalized(rounds),
    red_score: redScore,
    blue_score: blueScore,
    winner,
    created_at: new Date().toISOString(),
    source: "local",
  };
}

function buildAiReportFromPayload(payload: any, label: string): string {
  const rounds = normalizeRoundsPayload(payload);
  if (!rounds.length) {
    return "No valid rounds found. Unable to generate report.";
  }

  const finalRound = rounds[rounds.length - 1] ?? {};
  const finalScore = finalRound?.world_state?.score ?? {};
  const redScore = safeNumber(finalScore.red ?? finalRound?.red_score, 0);
  const blueScore = safeNumber(finalScore.blue ?? finalRound?.blue_score, 0);
  const winner = redScore > blueScore ? "Red Team" : blueScore > redScore ? "Blue Team" : "Draw";

  const totalRounds = inferTotalRoundsFromNormalized(rounds);
  const scenario = String(finalRound?.scenario ?? rounds[0]?.scenario ?? "level_1_basic_web");

  let blockedCount = 0;
  let successCount = 0;
  const tacticCounter = new Map<string, number>();
  let maxCompromised = 0;

  rounds.forEach((item: any) => {
    const redAction = String(
      item?.red_action?.action_type ?? item?.red_action?.technique ?? item?.red_action?.technique_id ?? "",
    ).trim();
    if (redAction) {
      tacticCounter.set(redAction, (tacticCounter.get(redAction) ?? 0) + 1);
    }

    if (item?.judge_result?.success === false) {
      blockedCount += 1;
    } else if (item?.judge_result?.success === true) {
      successCount += 1;
    }

    const compromised = Array.isArray(item?.world_state?.nodes)
      ? item.world_state.nodes.filter((node: any) =>
          ["compromised", "down", "isolated"].includes(String(node?.status ?? "").toLowerCase()),
        ).length
      : 0;
    maxCompromised = Math.max(maxCompromised, compromised);
  });

  const topTactics = [...tacticCounter.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([name, count]) => `${name} (${count})`);

  const defenseEfficiency = successCount + blockedCount > 0
    ? Math.round((blockedCount / (successCount + blockedCount)) * 100)
    : 0;

  return [
    `AI ANALYSIS REPORT - ${label}`,
    "",
    `Scenario: ${scenario}`,
    `Rounds: ${totalRounds}`,
    `Final Score: RED ${redScore} | BLUE ${blueScore}`,
    `Winner: ${winner}`,
    "",
    "Key Findings:",
    `1. Defense block rate estimated at ${defenseEfficiency}% (${blockedCount} blocked / ${successCount + blockedCount} judged actions).`,
    `2. Peak compromised node count reached ${maxCompromised}.`,
    `3. Most frequent red tactics: ${topTactics.length ? topTactics.join(", ") : "No action pattern detected"}.`,
    "",
    "Strategic Notes:",
    "1. If Red score spike occurs in late rounds, prioritize pre-emptive segmentation and early patching.",
    "2. If block rate is below 40%, strengthen blue-side policy timing and IDS/patch coordination.",
    "3. Use replay to inspect the first pivot success round and optimize blue intervention window.",
  ].join("\n");
}

function PlaceholderPage({ title, description }: { title: string; description: string }) {
  return (
    <div className="flex h-full items-center justify-center p-8">
      <div className="w-full max-w-2xl rounded-2xl bg-white/[0.04] p-8 text-center shadow-[0_20px_45px_rgba(2,8,22,0.4)]">
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-slate-500">{title}</p>
        <h2 className="mt-3 text-2xl font-semibold text-slate-100">Module Under Construction</h2>
        <p className="mt-3 text-sm leading-7 text-slate-400">{description}</p>
      </div>
    </div>
  );
}

function App() {
  const [activeTab, setActiveTab] = useState<AppTabKey>("dashboard");
  const [rounds, setRounds] = useState(() => FALLBACK_ROUNDS);
  const [roundIndex, setRoundIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [serverHistoryItems, setServerHistoryItems] = useState<SimulationHistoryItem[]>([]);
  const [localHistoryItems, setLocalHistoryItems] = useState<SimulationHistoryItem[]>([]);
  const [localReplayStore, setLocalReplayStore] = useState<Record<string, any>>({});
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [runningSimulation, setRunningSimulation] = useState(false);
  const [playingHistoryFile, setPlayingHistoryFile] = useState<string | null>(null);
  const [reportingHistoryFile, setReportingHistoryFile] = useState<string | null>(null);
  const [deletingHistoryFile, setDeletingHistoryFile] = useState<string | null>(null);
  const [importingHistoryFile, setImportingHistoryFile] = useState(false);
  const [notice, setNotice] = useState<UiNotice | null>(null);
  const [reportViewer, setReportViewer] = useState<ReportViewerState | null>(null);

  const showNotice = useCallback((text: string, tone: NoticeTone = "info") => {
    setNotice({
      id: Date.now(),
      text,
      tone,
    });
  }, []);

  useEffect(() => {
    if (!notice) {
      return undefined;
    }

    const timer = window.setTimeout(() => {
      setNotice((current) => (current?.id === notice.id ? null : current));
    }, 2200);
    return () => window.clearTimeout(timer);
  }, [notice]);

  const historyItems = useMemo(() => {
    const merged = [...localHistoryItems, ...serverHistoryItems];
    return merged.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }, [localHistoryItems, serverHistoryItems]);

  const upsertLocalReplay = useCallback((file: string, payload: any, simulationId: string) => {
    const normalized = normalizeRoundsPayload(payload);
    if (!normalized.length) {
      return;
    }

    const item = buildLocalHistoryItem(file, normalized, simulationId);
    setLocalReplayStore((current) => ({ ...current, [file]: payload }));
    setLocalHistoryItems((current) => [item, ...current.filter((entry) => entry.file !== file)]);
  }, []);

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
          upsertLocalReplay("local_current_replay.json", payload, "CURRENT-REPLAY");
        }
      })
      .catch((error) => {
        // Keep local mock rounds when replay payload is unavailable.
        console.error("Failed to load replay data, fallback to mock rounds:", error);
      });

    return () => {
      cancelled = true;
    };
  }, [upsertLocalReplay]);

  useEffect(() => {
    setRoundIndex((current) => Math.min(current, Math.max(rounds.length - 1, 0)));
  }, [rounds.length]);

  useEffect(() => {
    if (!playing || rounds.length <= 1) {
      return undefined;
    }

    const timer = window.setInterval(() => {
      setRoundIndex((current) => {
        if (current >= rounds.length - 1) {
          setPlaying(false);
          return current;
        }
        return current + 1;
      });
    }, 2200);

    return () => window.clearInterval(timer);
  }, [playing, rounds.length]);

  const frameCount = rounds.length || FALLBACK_ROUNDS.length;
  const safeIndex = Math.min(roundIndex, Math.max(frameCount - 1, 0));
  const currentRound = useMemo(
    () => rounds[safeIndex] ?? FALLBACK_ROUNDS[Math.min(safeIndex, FALLBACK_ROUNDS.length - 1)],
    [rounds, safeIndex],
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
  const rawRoundValue = Number(safeIndex);
  const displayRound = Number.isFinite(rawRoundValue)
    ? Math.min(Math.max(rawRoundValue, 0), totalRounds)
    : Math.min(Math.max(safeIndex, 0), totalRounds);

  const score = currentRound?.world_state?.score ?? {
    red: currentRound?.red_score ?? 0,
    blue: currentRound?.blue_score ?? 0,
  };

  const handleSeek = (nextIndex: number) => {
    setPlaying(false);
    const clamped = Math.min(Math.max(nextIndex, 0), Math.max(frameCount - 1, 0));
    setRoundIndex(clamped);
  };

  const handleNext = () => {
    setPlaying(false);
    setRoundIndex((current) => Math.min(current + 1, Math.max(frameCount - 1, 0)));
  };

  const loadSimulationHistory = useCallback(async () => {
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const payload = await requestJson<{ items?: SimulationHistoryItem[] }>(`${API_BASE_URL}/api/simulation/history`);
      const serverItems = Array.isArray(payload.items)
        ? payload.items.map((item) => ({ ...item, source: "server" as const }))
        : [];
      setServerHistoryItems(serverItems);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to load simulation history";
      setHistoryError(message);
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "scenarios") {
      void loadSimulationHistory();
    }
  }, [activeTab, loadSimulationHistory]);

  const handleReplayFromHistory = useCallback(async (item: SimulationHistoryItem) => {
    setPlayingHistoryFile(item.file);
    setHistoryError(null);
    try {
      let payload: any;
      if (item.source === "local" && localReplayStore[item.file]) {
        payload = localReplayStore[item.file];
      } else {
        payload = await requestJson<any>(
          `${API_BASE_URL}/api/simulation/download?file=${encodeURIComponent(item.file)}`,
        );
      }
      const normalized = normalizeRoundsPayload(payload);
      if (normalized.length) {
        setRounds(normalized);
        setRoundIndex(0);
        setPlaying(false);
        setActiveTab("replay");
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to load replay file";
      setHistoryError(message);
      showNotice(message, "error");
    } finally {
      setPlayingHistoryFile(null);
    }
  }, [localReplayStore, showNotice]);

  const handleGenerateReport = useCallback(async (item: SimulationHistoryItem) => {
    setReportingHistoryFile(item.file);
    setHistoryError(null);
    try {
      let payload: any;
      if (item.source === "local" && localReplayStore[item.file]) {
        payload = localReplayStore[item.file];
      } else {
        payload = await requestJson<any>(
          `${API_BASE_URL}/api/simulation/download?file=${encodeURIComponent(item.file)}`,
        );
      }

      const reportText = buildAiReportFromPayload(payload, item.simulation_id);
      setReportViewer({
        title: `AI Report • ${item.simulation_id}`,
        content: reportText,
      });
      showNotice("AI report generated.", "success");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to generate report";
      setHistoryError(message);
      showNotice(message, "error");
    } finally {
      setReportingHistoryFile(null);
    }
  }, [localReplayStore, showNotice]);

  const handleDeleteRecord = useCallback(async (item: SimulationHistoryItem) => {
    const confirmed = window.confirm(`Delete record "${item.simulation_id}"?`);
    if (!confirmed) {
      return;
    }

    setDeletingHistoryFile(item.file);
    setHistoryError(null);
    try {
      if (item.source === "local") {
        setLocalHistoryItems((current) => current.filter((entry) => entry.file !== item.file));
        setLocalReplayStore((current) => {
          const next = { ...current };
          delete next[item.file];
          return next;
        });
      } else {
        await requestJson<{ status: string }>(
          `${API_BASE_URL}/api/simulation/delete?file=${encodeURIComponent(item.file)}`,
          { method: "DELETE" },
        );
        await loadSimulationHistory();
      }
      showNotice(`Deleted ${item.simulation_id}.`, "success");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to delete record";
      setHistoryError(message);
      showNotice(message, "error");
    } finally {
      setDeletingHistoryFile(null);
    }
  }, [loadSimulationHistory, showNotice]);

  const openReplayTab = () => {
    setActiveTab("replay");
  };

  const runSimulationTask = useCallback(
    async (config: SimulationLaunchConfig) => {
      setRunningSimulation(true);
      setHistoryError(null);
      showNotice(`Simulation started (${config.rounds} rounds).`, "info");
      try {
        await requestJson<{ status: string }>(`${API_BASE_URL}/api/simulation/run`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ rounds: config.rounds, scenario: config.scenario }),
        });
        await loadSimulationHistory();
        showNotice("Simulation completed. Result saved to Simulation History.", "success");
      } catch (error) {
        const message = error instanceof Error ? error.message : "Simulation run failed";
        setHistoryError(message);
        showNotice(message, "error");
      } finally {
        setRunningSimulation(false);
      }
    },
    [loadSimulationHistory, showNotice],
  );

  const handleStartNewSimulation = useCallback(
    (config: SimulationLaunchConfig) => {
      setActiveTab("dashboard");
      void runSimulationTask(config);
    },
    [runSimulationTask],
  );

  const handleImportHistoryJson = useCallback(
    async (file: File) => {
      setImportingHistoryFile(true);
      setHistoryError(null);
      try {
        const text = await file.text();
        const payload = JSON.parse(text);
        const normalized = normalizeRoundsPayload(payload);
        if (!normalized.length) {
          throw new Error("Imported JSON has no replay frames");
        }

        const key = `local_import_${Date.now()}_${file.name.replace(/[^a-zA-Z0-9_.-]/g, "_")}`;
        const simulationId = file.name.replace(/\.json$/i, "") || "LOCAL-IMPORT";
        upsertLocalReplay(key, payload, simulationId.toUpperCase());
        showNotice(`Imported ${file.name} into Simulation History.`, "success");
      } catch (error) {
        const message = error instanceof Error ? error.message : "Failed to import JSON";
        setHistoryError(message);
        showNotice(message, "error");
      } finally {
        setImportingHistoryFile(false);
      }
    },
    [showNotice, upsertLocalReplay],
  );

  const noticeToneClass =
    notice?.tone === "success"
      ? "border-emerald-400/35 bg-emerald-500/10 text-emerald-200"
      : notice?.tone === "error"
        ? "border-red-400/35 bg-red-500/10 text-red-200"
        : "border-cyan-400/35 bg-cyan-500/10 text-cyan-200";

  return (
    <div className="relative h-screen w-screen overflow-hidden bg-[#07090f] text-slate-100">
      {notice ? (
        <div className="pointer-events-none absolute left-1/2 top-1/2 z-[120] -translate-x-1/2 -translate-y-1/2">
          <div className={`rounded-lg border px-6 py-3 font-mono text-sm uppercase tracking-[0.1em] shadow-[0_14px_36px_rgba(2,8,20,0.5)] ${noticeToneClass}`}>
            {notice.text}
          </div>
        </div>
      ) : null}
      {reportViewer ? (
        <div className="absolute inset-0 z-[130] flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-sm">
          <div className="w-full max-w-4xl rounded-2xl border border-white/[0.08] bg-[#050913]/95 p-5 shadow-[0_24px_68px_rgba(2,8,22,0.68)]">
            <div className="mb-3 flex items-center justify-between">
              <h3 className="font-mono text-sm uppercase tracking-[0.16em] text-slate-200">{reportViewer.title}</h3>
              <button
                type="button"
                onClick={() => setReportViewer(null)}
                className="rounded-md bg-white/[0.05] px-3 py-1.5 font-mono text-xs uppercase tracking-[0.12em] text-slate-300 transition hover:bg-white/[0.1]"
              >
                Close
              </button>
            </div>
            <pre className="cyber-scrollbar max-h-[65vh] overflow-auto rounded-xl bg-black/35 p-4 text-sm leading-6 text-slate-200">
              {reportViewer.content}
            </pre>
          </div>
        </div>
      ) : null}
      <div className="flex h-full overflow-hidden bg-[radial-gradient(circle_at_70%_0%,rgba(30,58,138,0.22),transparent_48%),radial-gradient(circle_at_10%_18%,rgba(14,116,144,0.14),transparent_42%)]">
        <aside className="relative w-56 shrink-0 bg-[#070a14]/80 shadow-[10px_0_35px_rgba(2,8,24,0.45)] backdrop-blur-sm">
          <span className="pointer-events-none absolute right-0 top-0 h-full w-px bg-gradient-to-b from-transparent via-cyan-900/45 to-transparent" />

          <div className="px-5 pb-4 pt-7">
            <div className="flex items-center">
              <div className="origin-left scale-[1.65]">
                <CyberArenaLogo />
              </div>
              <p className="ml-8 font-mono text-[12px] uppercase tracking-[0.2em] text-cyan-200">MACSim</p>
            </div>
            <div className="mt-4">
              <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-slate-300">Multi-Agent CyberSec Simulator</p>
              <p className="text-[11px] text-slate-500">Attack/Defense Replay Console</p>
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
                      ? "bg-white/[0.04] shadow-[0_8px_22px_rgba(2,8,22,0.32)]"
                      : "bg-transparent hover:bg-white/[0.03]"
                  }`}
                >
                  <span
                    className={`absolute left-0 top-1/2 h-8 w-[2px] -translate-y-1/2 rounded-r-full transition ${
                      isActive ? "bg-cyan-300 shadow-[0_0_12px_rgba(34,211,238,0.85)]" : "bg-transparent"
                    }`}
                  />
                  <p className={`font-mono text-[11px] uppercase tracking-[0.11em] ${isActive ? "text-slate-100" : "text-slate-400 group-hover:text-slate-200"}`}>
                    {item.label}
                  </p>
                  <p className={`mt-1 text-[11px] ${isActive ? "text-slate-400" : "text-slate-500 group-hover:text-slate-400"}`}>{item.subtitle}</p>
                </button>
              );
            })}
          </nav>
        </aside>

        <section className="min-w-0 flex-1 overflow-hidden bg-[#07090f]">
          {activeTab === "dashboard" ? (
            <div className="flex h-full flex-col overflow-hidden">
              <TopBar
                roundIndex={safeIndex}
                displayRound={displayRound}
                totalRounds={totalRounds}
                frameCount={frameCount}
                redScore={score.red}
                blueScore={score.blue}
                playing={playing}
                simulationRunning={runningSimulation}
                onTogglePlay={() => setPlaying((current) => !current)}
                onNext={handleNext}
                onSeek={handleSeek}
                immersive
              />

              <HomeDashboard
                onStartNewSimulation={handleStartNewSimulation}
                onViewReplay={openReplayTab}
                runningSimulation={runningSimulation}
                rounds={rounds}
                currentRound={currentRound}
                roundIndex={safeIndex}
                totalRounds={totalRounds}
              />
            </div>
          ) : null}

          {activeTab === "replay" ? (
            <div className="flex h-full flex-col overflow-hidden">
              <TopBar
                roundIndex={safeIndex}
                displayRound={displayRound}
                totalRounds={totalRounds}
                frameCount={frameCount}
                redScore={score.red}
                blueScore={score.blue}
                playing={playing}
                simulationRunning={runningSimulation}
                onTogglePlay={() => setPlaying((current) => !current)}
                onNext={handleNext}
                onSeek={handleSeek}
                immersive
              />

              <main className="flex min-h-0 flex-1 overflow-hidden px-3 pb-3 pt-2">
                <section className="min-w-0 flex-[3] overflow-hidden pr-3">
                  <div className="relative flex h-full min-h-0 flex-col overflow-hidden rounded-[24px] bg-[#060b16]/35">
                    <span className="pointer-events-none absolute inset-x-12 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/35 to-transparent" />
                    <span className="pointer-events-none absolute inset-x-12 bottom-0 h-px bg-gradient-to-r from-transparent via-red-400/45 to-transparent" />
                    <div className="flex shrink-0 items-center justify-end gap-2 px-4 pt-3 text-[10px] font-mono uppercase tracking-[0.16em]">
                      <span className="rounded-full border border-blue-500/35 bg-blue-950/30 px-2 py-0.5 text-blue-300">Normal</span>
                      <span className="rounded-full bg-red-500/15 px-2 py-0.5 text-red-300">Compromised</span>
                      <span className="rounded-full bg-slate-500/20 px-2 py-0.5 text-slate-300">Down</span>
                    </div>
                    <div className="min-h-0 flex-1 overflow-hidden p-2">
                      <TopologyVisualizer round={currentRound} rounds={rounds} roundIndex={safeIndex} variant="embedded" />
                    </div>
                  </div>
                </section>

                <aside className="flex min-w-[350px] max-w-[420px] flex-1 overflow-hidden">
                  <ReasoningPanel round={currentRound} />
                </aside>
              </main>

              <section className="h-40 shrink-0 md:h-44 xl:h-48">
                <TerminalLogs round={currentRound} />
              </section>
            </div>
          ) : null}

          {activeTab === "scenarios" ? (
            <SimulationHistory
              items={historyItems}
              loading={historyLoading}
              error={historyError}
              playingFile={playingHistoryFile}
              reportingFile={reportingHistoryFile}
              deletingFile={deletingHistoryFile}
              importing={importingHistoryFile}
              onRefresh={() => void loadSimulationHistory()}
              onImportJson={handleImportHistoryJson}
              onPlayReplay={handleReplayFromHistory}
              onGenerateReport={handleGenerateReport}
              onDeleteRecord={handleDeleteRecord}
            />
          ) : null}

          {activeTab === "settings" ? (
            <PlaceholderPage
              title="Settings"
              description="Settings placeholder has been added to navigation. This page can host model keys, inference parameters, log levels, and export strategy."
            />
          ) : null}
        </section>
      </div>
    </div>
  );
}

export default App;
