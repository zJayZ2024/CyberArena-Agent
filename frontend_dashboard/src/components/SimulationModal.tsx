import { useEffect, useMemo, useState } from "react";

export type SimulationLaunchConfig = {
  redTeamSize: number;
  blueTeamSize: number;
  rounds: number;
  scenario: string;
};

type SimulationModalProps = {
  open: boolean;
  defaultRounds?: number;
  defaultScenario?: string;
  onCancel: () => void;
  onLaunch?: (config: SimulationLaunchConfig) => Promise<void> | void;
};

const LOADING_MESSAGES = [
  "Initializing AI agents...",
  "Syncing attack and defense contexts...",
  "Running LLM inference...",
  "Computing referee adjudication...",
];

function clampRounds(value: number): number {
  if (!Number.isFinite(value)) {
    return 20;
  }
  return Math.min(30, Math.max(5, Math.round(value)));
}

function SimulationModal({
  open,
  defaultRounds = 20,
  defaultScenario = "level_2_ransomware",
  onCancel,
  onLaunch,
}: SimulationModalProps) {
  const [rounds, setRounds] = useState(clampRounds(defaultRounds));
  const [isLaunching, setIsLaunching] = useState(false);
  const [errorText, setErrorText] = useState<string | null>(null);
  const [loadingIndex, setLoadingIndex] = useState(0);

  useEffect(() => {
    if (!open) {
      return;
    }
    setRounds(clampRounds(defaultRounds));
    setErrorText(null);
    setIsLaunching(false);
    setLoadingIndex(0);
  }, [defaultRounds, open]);

  useEffect(() => {
    if (!isLaunching) {
      return undefined;
    }
    const timer = window.setInterval(() => {
      setLoadingIndex((current) => (current + 1) % LOADING_MESSAGES.length);
    }, 1100);
    return () => window.clearInterval(timer);
  }, [isLaunching]);

  const loadingText = useMemo(() => LOADING_MESSAGES[loadingIndex], [loadingIndex]);

  if (!open) {
    return null;
  }

  const handleLaunch = async () => {
    setErrorText(null);
    setIsLaunching(true);
    try {
      await onLaunch?.({
        redTeamSize: 1,
        blueTeamSize: 1,
        rounds: clampRounds(rounds),
        scenario: defaultScenario,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Simulation failed";
      setErrorText(message);
      setIsLaunching(false);
      return;
    }
    setIsLaunching(false);
  };

  return (
    <div className="fixed inset-0 z-[90] flex items-center justify-center bg-slate-950/80 px-4 backdrop-blur-md">
      <div className="w-full max-w-3xl rounded-2xl border border-white/[0.08] bg-[#050913]/90 p-6 shadow-[0_24px_68px_rgba(2,8,22,0.68)]">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.26em] text-slate-500">Simulation Config</p>
            <h2 className="mt-2 text-2xl font-light tracking-wide text-slate-100">Launch New Cyber Battle</h2>
          </div>
        </div>

        <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-2">
          <label className="space-y-2">
            <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-slate-400">Red Team Size</span>
            <input
              type="number"
              value={1}
              disabled
              className="w-full rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-2.5 text-sm text-slate-300 outline-none"
            />
          </label>
          <label className="space-y-2">
            <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-slate-400">Blue Team Size</span>
            <input
              type="number"
              value={1}
              disabled
              className="w-full rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-2.5 text-sm text-slate-300 outline-none"
            />
          </label>
        </div>

        <div className="mt-5 rounded-xl bg-white/[0.02] px-4 py-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
          <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-slate-400">Target Network Scenario</p>
          <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px] font-mono uppercase tracking-[0.14em] text-slate-300">
            <span className="rounded-md border border-white/[0.08] bg-slate-800/40 px-3 py-2">Internet</span>
            <span className="text-slate-500">-&gt;</span>
            <span className="rounded-md border border-white/[0.08] bg-slate-800/40 px-3 py-2">DMZ</span>
            <span className="text-slate-500">-&gt;</span>
            <span className="rounded-md border border-white/[0.08] bg-slate-800/40 px-3 py-2">Internal</span>
            <span className="text-slate-500">-&gt;</span>
            <span className="rounded-md border border-white/[0.08] bg-slate-800/40 px-3 py-2">Database</span>
          </div>
          <p className="mt-3 text-xs text-slate-500">Topology nodes are read-only in demo mode.</p>
        </div>

        <div className="mt-5">
          <label className="space-y-2">
            <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-slate-400">Total Rounds</span>
            <input
              type="number"
              min={5}
              max={30}
              value={rounds}
              disabled={isLaunching}
              onChange={(event) => setRounds(clampRounds(Number(event.target.value)))}
              className="w-full rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-2.5 text-sm text-slate-200 outline-none transition focus:border-cyan-400/45"
            />
          </label>
        </div>

        {errorText ? <p className="mt-4 text-sm text-red-300">{errorText}</p> : null}
        {isLaunching ? (
          <div className="mt-4 rounded-lg border border-cyan-400/25 bg-cyan-500/8 px-4 py-3 text-sm text-cyan-200">
            {loadingText}
          </div>
        ) : null}

        <div className="mt-6 flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onCancel}
            disabled={isLaunching}
            className="rounded-md bg-white/[0.05] px-4 py-2 font-mono text-xs uppercase tracking-[0.16em] text-slate-300 transition hover:bg-white/[0.1] disabled:cursor-not-allowed disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleLaunch}
            disabled={isLaunching}
            className="rounded-md bg-gradient-to-r from-cyan-500/35 via-blue-500/35 to-cyan-400/25 px-5 py-2 font-mono text-xs uppercase tracking-[0.16em] text-cyan-100 shadow-[0_0_26px_rgba(34,211,238,0.28)] transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-70"
          >
            Launch Simulation
          </button>
        </div>
      </div>
    </div>
  );
}

export default SimulationModal;
