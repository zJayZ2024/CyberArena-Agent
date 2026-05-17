import { useEffect, useMemo, useState } from "react";

import HomeDashboard from "./components/HomeDashboard";
import ReasoningPanel from "./components/ReasoningPanel";
import ScenarioSelection, { type ScenarioCatalogItem } from "./components/ScenarioSelection";
import TerminalLogs from "./components/TerminalLogs";
import TopBar, { CyberArenaLogo } from "./components/TopBar";
import TopologyVisualizer from "./components/TopologyVisualizer";
import { DEFAULT_ROUNDS, normalizeRoundsPayload } from "./components/NetworkTopology/data";

const FALLBACK_ROUNDS = normalizeRoundsPayload(DEFAULT_ROUNDS);

type AppTabKey = "dashboard" | "replay" | "scenarios" | "settings";

const NAV_ITEMS: Array<{ key: AppTabKey; label: string; subtitle: string }> = [
  { key: "dashboard", label: "仪表盘", subtitle: "总览" },
  { key: "replay", label: "仿真回放", subtitle: "攻防过程回放" },
  { key: "scenarios", label: "场景配置", subtitle: "拓扑选择" },
  { key: "settings", label: "设置", subtitle: "系统控制" },
];

function PlaceholderPage({ title, description }: { title: string; description: string }) {
  return (
    <div className="flex h-full items-center justify-center p-8">
      <div className="w-full max-w-2xl rounded-2xl bg-white/[0.04] p-8 text-center shadow-[0_20px_45px_rgba(2,8,22,0.4)]">
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-slate-500">{title}</p>
        <h2 className="mt-3 text-2xl font-semibold text-slate-100">模块建设中</h2>
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
  const [selectedScenario, setSelectedScenario] = useState<ScenarioCatalogItem | null>(null);

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
        }
      })
      .catch((error) => {
        // 回放数据不可用时，继续使用本地示例帧。
        console.error("回放数据加载失败，使用本地示例帧：", error);
      });

    return () => {
      cancelled = true;
    };
  }, []);

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

  const openReplayTab = () => {
    setActiveTab("replay");
  };

  const handleStartScenario = (scenario: ScenarioCatalogItem) => {
    const normalized = normalizeRoundsPayload([scenario.initial_frame]);
    setSelectedScenario(scenario);
    setRounds(normalized.length ? normalized : FALLBACK_ROUNDS);
    setActiveTab("replay");
    setRoundIndex(0);
    setPlaying(false);
  };

  const handleStartNewSimulation = () => {
    if (selectedScenario) {
      handleStartScenario(selectedScenario);
      return;
    }
    setActiveTab("scenarios");
    setPlaying(false);
  };

  return (
    <div className="h-screen w-screen overflow-hidden bg-[#07090f] text-slate-100">
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
              <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-slate-300">多智能体网络安全仿真器</p>
              <p className="text-[11px] text-slate-500">攻防回放控制台</p>
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
                onTogglePlay={() => setPlaying((current) => !current)}
                onNext={handleNext}
                onSeek={handleSeek}
                immersive
              />

              <HomeDashboard
                onStartNewSimulation={handleStartNewSimulation}
                onViewReplay={openReplayTab}
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
                      <span className="rounded-full border border-blue-500/35 bg-blue-950/30 px-2 py-0.5 text-blue-300">正常</span>
                      <span className="rounded-full bg-red-500/15 px-2 py-0.5 text-red-300">已失陷</span>
                      <span className="rounded-full bg-slate-500/20 px-2 py-0.5 text-slate-300">离线</span>
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
            <ScenarioSelection
              selectedScenario={selectedScenario}
              onSelectScenario={setSelectedScenario}
              onStartScenario={handleStartScenario}
            />
          ) : null}

          {activeTab === "settings" ? (
            <PlaceholderPage
              title="设置"
              description="设置页已加入导航，后续可承载模型密钥、推理参数、日志级别和导出策略。"
            />
          ) : null}
        </section>
      </div>
    </div>
  );
}

export default App;
