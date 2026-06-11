import { useEffect, useMemo, useState } from "react";

import TopologyVisualizer from "./TopologyVisualizer";
import { DEFAULT_ROUNDS, normalizeRoundsPayload } from "./NetworkTopology/data";
import { translateDifficulty, translateScenarioName } from "../utils/localization";

export type ScenarioCatalogItem = {
  id: string;
  name: string;
  difficulty: string;
  summary: string;
  scenario_path: string;
  tags: string[];
  objectives: {
    red: string;
    blue: string;
  };
  stats: {
    nodes: number;
    edges: number;
    vulnerabilities: number;
    core_assets: string[];
  };
  initial_frame: any;
};

type ScenarioSelectionProps = {
  selectedScenario?: ScenarioCatalogItem | null;
  onSelectScenario?: (scenario: ScenarioCatalogItem) => void;
  onStartScenario?: (scenario: ScenarioCatalogItem, rounds: number) => Promise<void> | void;
  onStopSimulation?: () => Promise<void> | void;
};

const FALLBACK_SCENARIOS: ScenarioCatalogItem[] = [
  {
    id: "fallback_basic_web",
    name: "等级 1 基础网站",
    difficulty: "入门",
    summary: "紧凑型网站服务栈，包含一条从公网进入应用、存储和数据库资产的路径。",
    scenario_path: "backend_engine/scenarios/level_1_basic_web.json",
    tags: ["网站", "隔离区", "备用"],
    objectives: {
      red: "通过公网网站层获得初始访问，并推进到 db。",
      blue: "在红方将网站访问转化为数据库影响前修补暴露服务。",
    },
    stats: {
      nodes: 6,
      edges: 6,
      vulnerabilities: 7,
      core_assets: ["db"],
    },
    initial_frame: DEFAULT_ROUNDS[0],
  },
];

function isCatalogItem(value: any): value is ScenarioCatalogItem {
  return !!(
    value
    && typeof value.id === "string"
    && typeof value.name === "string"
    && typeof value.scenario_path === "string"
    && value.initial_frame
  );
}

function normalizeCatalogPayload(payload: any): ScenarioCatalogItem[] {
  const rows = Array.isArray(payload?.scenarios) ? payload.scenarios : [];
  const normalized = rows.filter(isCatalogItem);
  return normalized.length ? normalized : FALLBACK_SCENARIOS;
}

function difficultyTone(difficulty = "") {
  const lowered = difficulty.toLowerCase();
  if (lowered.includes("expert") || difficulty.includes("专家")) {
    return "border-red-400/50 bg-[rgba(255,107,122,0.12)] text-red-200";
  }
  if (lowered.includes("advanced") || difficulty.includes("高级")) {
    return "border-amber-400/50 bg-amber-500/10 text-amber-200";
  }
  if (lowered.includes("intermediate") || difficulty.includes("中级")) {
    return "border-violet-400/50 bg-violet-500/10 text-violet-200";
  }
  return "border-emerald-400/50 bg-emerald-500/10 text-emerald-200";
}

function ScenarioSelection({
  selectedScenario,
  onSelectScenario,
  onStartScenario,
  onStopSimulation,
}: ScenarioSelectionProps) {
  const [catalog, setCatalog] = useState<ScenarioCatalogItem[]>(FALLBACK_SCENARIOS);
  const [localSelectedId, setLocalSelectedId] = useState<string>(selectedScenario?.id ?? FALLBACK_SCENARIOS[0].id);
  const [catalogSource, setCatalogSource] = useState<"catalog" | "fallback">("fallback");
  const [showLaunchDialog, setShowLaunchDialog] = useState(false);
  const [simulationRounds, setSimulationRounds] = useState(20);
  const [launching, setLaunching] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [launchError, setLaunchError] = useState("");

  useEffect(() => {
    let cancelled = false;

    fetch("/scenario_catalog.json")
      .then((response) => {
        if (!response.ok) {
          throw new Error(`场景目录请求失败：${response.status}`);
        }
        return response.json();
      })
      .then((payload) => {
        if (cancelled) {
          return;
        }
        const nextCatalog = normalizeCatalogPayload(payload);
        setCatalog(nextCatalog);
        setCatalogSource(nextCatalog === FALLBACK_SCENARIOS ? "fallback" : "catalog");
        const nextSelected = selectedScenario && nextCatalog.some((item) => item.id === selectedScenario.id)
          ? selectedScenario
          : nextCatalog[0];
        setLocalSelectedId(nextSelected.id);
        onSelectScenario?.(nextSelected);
      })
      .catch((error) => {
        if (cancelled) {
          return;
        }
        console.error("场景目录加载失败，使用备用场景：", error);
        setCatalog(FALLBACK_SCENARIOS);
        setCatalogSource("fallback");
        setLocalSelectedId(FALLBACK_SCENARIOS[0].id);
        onSelectScenario?.(FALLBACK_SCENARIOS[0]);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (selectedScenario?.id) {
      setLocalSelectedId(selectedScenario.id);
    }
  }, [selectedScenario?.id]);

  const activeScenario = useMemo(() => {
    return catalog.find((item) => item.id === localSelectedId) ?? catalog[0] ?? FALLBACK_SCENARIOS[0];
  }, [catalog, localSelectedId]);

  const previewRounds = useMemo(() => {
    return normalizeRoundsPayload([activeScenario.initial_frame]);
  }, [activeScenario]);

  const previewRound = previewRounds[0];
  const coreAssets = activeScenario.stats.core_assets.join(", ");

  const selectScenario = (scenario: ScenarioCatalogItem) => {
    setLocalSelectedId(scenario.id);
    onSelectScenario?.(scenario);
  };

  const openLaunchDialog = () => {
    setLaunchError("");
    setShowLaunchDialog(true);
  };

  const launchSimulation = async () => {
    if (!onStartScenario || launching) {
      return;
    }
    const rounds = Math.min(100, Math.max(1, Math.round(Number(simulationRounds) || 20)));
    setSimulationRounds(rounds);
    setLaunching(true);
    setLaunchError("");
    try {
      await onStartScenario(activeScenario, rounds);
      setShowLaunchDialog(false);
    } catch (error) {
      setLaunchError(error instanceof Error ? error.message : "仿真启动失败，请检查后端服务和模型配置。");
    } finally {
      setLaunching(false);
      setStopping(false);
    }
  };

  const stopSimulation = async () => {
    if (!onStopSimulation || stopping) {
      return;
    }
    setStopping(true);
    setLaunchError("");
    try {
      await onStopSimulation();
    } catch (error) {
      setStopping(false);
      setLaunchError(error instanceof Error ? error.message : "停止仿真失败，请重试。");
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col overflow-y-auto px-5 py-4">
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-3 pb-4">
        <div className="min-w-0">
          <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-slate-400">场景</p>
          <h1 className="mt-1 text-xl font-light tracking-wide text-slate-100">拓扑选择</h1>
        </div>
        <div className="flex min-w-0 flex-wrap items-center gap-2 font-mono text-[10px] uppercase tracking-[0.14em] text-slate-400">
          <span className={`rounded-md border px-2 py-1 ${catalogSource === "catalog" ? "border-blue-400/50 text-blue-200" : "border-amber-400/50 text-amber-200"}`}>
            {catalogSource === "catalog" ? "目录" : "备用"}
          </span>
          <span className="rounded-md border border-slate-600/60 px-2 py-1 text-slate-400">{catalog.length} 张拓扑</span>
          <button
            type="button"
            onClick={openLaunchDialog}
            className="rounded-md border border-blue-300/45 bg-gradient-to-r from-[#5b9fff] to-[#7c8fff] px-3 py-1 text-white transition hover:brightness-110"
          >
            开始
          </button>
        </div>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 xl:grid-cols-[360px_minmax(0,1fr)]">
        <aside className="min-h-[260px] overflow-y-auto pr-1 xl:min-h-0">
          <div className="space-y-3">
            {catalog.map((scenario) => {
              const active = scenario.id === activeScenario.id;
              return (
                <button
                  key={scenario.id}
                  type="button"
                  onClick={() => selectScenario(scenario)}
                  className={`w-full rounded-lg border p-4 text-left transition ${
                    active
                      ? "border-blue-400/60 border-l-[3px] border-l-[#5b9fff] bg-[rgba(91,159,255,0.10)] shadow-[0_0_18px_rgba(91,159,255,0.16)]"
                      : "border-[#304060] bg-[#162340] hover:border-[#5b9fff]/55 hover:bg-[#1c2d4a]"
                  }`}
                >
                  <div className="flex min-w-0 items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="break-words text-sm font-medium text-slate-100">{translateScenarioName(scenario.name)}</p>
                      <p className="mt-1 font-mono text-[10px] tracking-[0.12em] text-slate-400">场景 ID：{scenario.id}</p>
                    </div>
                    <span className={`shrink-0 rounded-md border px-2 py-1 font-mono text-[10px] uppercase ${difficultyTone(scenario.difficulty)}`}>
                      {translateDifficulty(scenario.difficulty)}
                    </span>
                  </div>

                  <p className="mt-3 break-words text-xs leading-5 text-slate-400">{scenario.summary}</p>

                  <div className="mt-4 grid grid-cols-3 gap-2 font-mono text-[10px] uppercase tracking-[0.08em]">
                    <span className="rounded-md bg-[#1c2d4a]/80 px-2 py-1 text-slate-400">节点 {scenario.stats.nodes}</span>
                    <span className="rounded-md bg-[#1c2d4a]/80 px-2 py-1 text-slate-400">连线 {scenario.stats.edges}</span>
                    <span className="rounded-md bg-[#1c2d4a]/80 px-2 py-1 text-slate-400">漏洞 {scenario.stats.vulnerabilities}</span>
                  </div>

                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {scenario.tags.slice(0, 3).map((tag) => (
                      <span key={tag} className="rounded-md bg-slate-800/80 px-2 py-1 font-mono text-[9px] uppercase tracking-[0.08em] text-slate-400">
                        {tag}
                      </span>
                    ))}
                  </div>
                </button>
              );
            })}
          </div>
        </aside>

        <section className="flex min-h-[560px] flex-col overflow-hidden rounded-lg border border-slate-700 bg-[#111a2e]/70 xl:min-h-0">
          <div className="grid shrink-0 grid-cols-1 gap-3 border-b border-slate-700 px-4 py-3 md:grid-cols-[minmax(0,1fr)_220px]">
            <div className="min-w-0">
              <div className="flex min-w-0 items-center gap-2">
                <h2 className="truncate text-lg font-light tracking-wide text-slate-100">{translateScenarioName(activeScenario.name)}</h2>
                <span className={`shrink-0 rounded-md border px-2 py-1 font-mono text-[10px] uppercase ${difficultyTone(activeScenario.difficulty)}`}>
                  {translateDifficulty(activeScenario.difficulty)}
                </span>
              </div>
              <p className="mt-1 truncate font-mono text-[10px] text-slate-400">场景文件：{activeScenario.scenario_path}</p>
            </div>

            <button
              type="button"
              onClick={openLaunchDialog}
              className="rounded-md border border-blue-300/45 bg-gradient-to-r from-[#5b9fff] to-[#7c8fff] px-4 py-2 font-mono text-xs uppercase tracking-[0.14em] text-white transition hover:brightness-110"
            >
              启动仿真
            </button>
          </div>

          <div className="grid shrink-0 grid-cols-4 gap-3 border-b border-slate-700 px-4 py-3 text-xs">
            <div>
              <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-slate-400">节点</p>
              <p className="mt-1 text-slate-200">{activeScenario.stats.nodes}</p>
            </div>
            <div>
              <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-slate-400">连线</p>
              <p className="mt-1 text-slate-200">{activeScenario.stats.edges}</p>
            </div>
            <div>
              <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-slate-400">漏洞</p>
              <p className="mt-1 text-slate-200">{activeScenario.stats.vulnerabilities}</p>
            </div>
            <div className="min-w-0">
              <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-slate-400">核心资产</p>
              <p className="mt-1 truncate text-slate-200">{coreAssets}</p>
            </div>
          </div>

          <div className="grid shrink-0 grid-cols-2 gap-3 border-b border-slate-700 px-4 py-3 text-xs leading-5">
            <div className="min-w-0">
              <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-red-300">红方目标</p>
              <p className="mt-1 break-words text-slate-400">{activeScenario.objectives.red}</p>
            </div>
            <div className="min-w-0">
              <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-[#5b9fff]">蓝方目标</p>
              <p className="mt-1 break-words text-slate-400">{activeScenario.objectives.blue}</p>
            </div>
          </div>

          <div className="min-h-0 flex-1 overflow-hidden p-3">
            <TopologyVisualizer round={previewRound} rounds={previewRounds} roundIndex={0} variant="embedded" />
          </div>
        </section>
      </div>
      {showLaunchDialog ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#060b16]/80 p-4 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl border border-blue-400/35 bg-[#111a2e] p-5 shadow-[0_24px_80px_rgba(0,0,0,0.55)]">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-blue-300">启动仿真</p>
                <h2 className="mt-2 text-lg font-medium text-[#f0f4ff]">{translateScenarioName(activeScenario.name)}</h2>
                <p className="mt-1 font-mono text-[10px] text-slate-400">{activeScenario.id}</p>
              </div>
              <button
                type="button"
                disabled={launching}
                onClick={() => setShowLaunchDialog(false)}
                className="rounded-md border border-white/[0.12] px-2 py-1 text-xs text-slate-400 transition hover:text-slate-100 disabled:opacity-40"
              >
                关闭
              </button>
            </div>

            <label className="mt-5 block">
              <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-slate-400">仿真轮数</span>
              <input
                type="number"
                min={1}
                max={100}
                value={simulationRounds}
                disabled={launching}
                onChange={(event) => setSimulationRounds(Number(event.target.value))}
                className="mt-2 w-full rounded-xl border border-[#304060] bg-[#162340] px-4 py-3 font-mono text-lg text-[#f0f4ff] outline-none transition focus:border-blue-400 focus:ring-2 focus:ring-blue-400/20 disabled:opacity-50"
              />
            </label>

            <div className="mt-4 grid grid-cols-3 gap-2 text-center font-mono text-[10px]">
              <div className="rounded-lg border border-white/[0.1] bg-[#162340] p-2 text-slate-400">节点<br /><span className="text-slate-100">{activeScenario.stats.nodes}</span></div>
              <div className="rounded-lg border border-white/[0.1] bg-[#162340] p-2 text-slate-400">连线<br /><span className="text-slate-100">{activeScenario.stats.edges}</span></div>
              <div className="rounded-lg border border-white/[0.1] bg-[#162340] p-2 text-slate-400">漏洞<br /><span className="text-slate-100">{activeScenario.stats.vulnerabilities}</span></div>
            </div>

            {launching ? (
              <div className="mt-4 rounded-xl border border-blue-400/25 bg-blue-500/[0.08] p-3">
                <div className="h-1.5 overflow-hidden rounded-full bg-[#0c1220]">
                  <div className="h-full w-1/2 animate-pulse rounded-full bg-gradient-to-r from-[#5b9fff] to-[#a78bfa]" />
                </div>
                <p className="mt-2 text-xs leading-5 text-blue-100">
                  {stopping ? "正在强制结束，等待当前 LLM 请求返回后保存已完成回合..." : "仿真正在后台运行，完成后将自动载入并加入回放结果。"}
                </p>
              </div>
            ) : null}

            {launchError ? <p className="mt-3 text-xs leading-5 text-red-300">{launchError}</p> : null}

            {launching ? (
              <button
                type="button"
                disabled={stopping}
                onClick={stopSimulation}
                className="mt-5 w-full rounded-xl border border-red-400/55 bg-red-500/15 px-4 py-3 font-mono text-xs uppercase tracking-[0.14em] text-red-100 transition hover:bg-red-500/25 disabled:cursor-wait disabled:opacity-60"
              >
                {stopping ? "正在强制结束..." : "强制结束仿真"}
              </button>
            ) : (
              <button
                type="button"
                onClick={launchSimulation}
                className="mt-5 w-full rounded-xl border border-blue-300/45 bg-gradient-to-r from-[#5b9fff] to-[#7c8fff] px-4 py-3 font-mono text-xs uppercase tracking-[0.14em] text-white transition hover:brightness-110"
              >
                确认启动 {simulationRounds} 轮仿真
              </button>
            )}
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default ScenarioSelection;
