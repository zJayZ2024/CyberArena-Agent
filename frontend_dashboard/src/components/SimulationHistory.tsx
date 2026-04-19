export type SimulationHistoryItem = {
  file: string;
  simulation_id: string;
  scenario: string;
  rounds: number;
  red_score: number;
  blue_score: number;
  winner: "Red" | "Blue" | "Draw" | string;
  created_at: string;
  source?: "server" | "local";
};

type SimulationHistoryProps = {
  items: SimulationHistoryItem[];
  loading?: boolean;
  error?: string | null;
  onRefresh?: () => void;
  onPlayReplay?: (item: SimulationHistoryItem) => void;
  onGenerateReport?: (item: SimulationHistoryItem) => void;
  onDeleteRecord?: (item: SimulationHistoryItem) => void;
  playingFile?: string | null;
  reportingFile?: string | null;
  deletingFile?: string | null;
  importing?: boolean;
  onImportJson?: (file: File) => void | Promise<void>;
};

function formatScenario(value: string): string {
  if (!value) {
    return "level_1_basic_web";
  }
  return value.replace(/_/g, " ");
}

function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value || "-";
  }
  return date.toLocaleString();
}

function winnerStyle(winner: string): string {
  const token = winner.toLowerCase();
  if (token === "red") {
    return "text-red-300 bg-red-500/10";
  }
  if (token === "blue") {
    return "text-cyan-300 bg-cyan-500/10";
  }
  return "text-slate-300 bg-slate-500/10";
}

function SimulationHistory({
  items,
  loading = false,
  error = null,
  onRefresh,
  onPlayReplay,
  onGenerateReport,
  onDeleteRecord,
  playingFile = null,
  reportingFile = null,
  deletingFile = null,
  importing = false,
  onImportJson,
}: SimulationHistoryProps) {
  const triggerImport = () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json,application/json";
    input.onchange = () => {
      const file = input.files?.[0];
      if (file) {
        void onImportJson?.(file);
      }
    };
    input.click();
  };

  return (
    <div className="h-full overflow-hidden px-6 py-4">
      <div className="relative flex h-full min-h-0 flex-col overflow-hidden rounded-[24px] bg-[#0b1222]/55 px-5 py-5 shadow-[0_20px_45px_rgba(2,8,24,0.4)]">
        <span className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/40 to-transparent" />

        <div className="mb-4 flex items-center justify-between">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-slate-500">Simulation History</p>
            <h2 className="mt-2 text-2xl font-light tracking-wide text-slate-100">Stored Replay Runs</h2>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={triggerImport}
              disabled={importing}
              className="rounded-md bg-gradient-to-r from-blue-500/35 to-cyan-400/25 px-4 py-2 font-mono text-xs uppercase tracking-[0.14em] text-cyan-100 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {importing ? "Importing..." : "Import JSON"}
            </button>
            <button
              type="button"
              onClick={onRefresh}
              disabled={loading}
              className="rounded-md bg-white/[0.05] px-4 py-2 font-mono text-xs uppercase tracking-[0.16em] text-slate-300 transition hover:bg-white/[0.1] disabled:cursor-not-allowed disabled:opacity-50"
            >
              Refresh
            </button>
          </div>
        </div>

        {error ? <p className="mb-3 text-sm text-red-300">{error}</p> : null}

        <div className="min-h-0 flex-1 overflow-hidden rounded-xl bg-[#060b16]/35">
          <div className="cyber-scrollbar h-full overflow-auto">
            <table className="w-full min-w-[860px] text-left text-sm">
              <thead className="sticky top-0 z-10 bg-[#0b1222]/90 backdrop-blur">
                <tr className="font-mono text-[11px] uppercase tracking-[0.14em] text-slate-400">
                  <th className="px-4 py-3 font-medium">Simulation ID</th>
                  <th className="px-4 py-3 font-medium">Scenario</th>
                  <th className="px-4 py-3 font-medium">Rounds</th>
                  <th className="px-4 py-3 font-medium">Red Score</th>
                  <th className="px-4 py-3 font-medium">Blue Score</th>
                  <th className="px-4 py-3 font-medium">Winner</th>
                  <th className="px-4 py-3 font-medium">Created At</th>
                  <th className="px-4 py-3 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.03] text-slate-200">
                {loading ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-10 text-center text-slate-400">
                      Loading simulation history...
                    </td>
                  </tr>
                ) : null}

                {!loading && items.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-10 text-center text-slate-500">
                      No simulation results yet. Launch a new run from Dashboard.
                    </td>
                  </tr>
                ) : null}

                {!loading
                  ? items.map((item) => (
                      <tr key={item.file} className="transition hover:bg-white/[0.02]">
                        <td className="px-4 py-3 font-mono text-[12px] text-slate-200">{item.simulation_id}</td>
                        <td className="px-4 py-3 text-slate-300">{formatScenario(item.scenario)}</td>
                        <td className="px-4 py-3 text-slate-300">{item.rounds}</td>
                        <td className="px-4 py-3 text-red-300">{item.red_score}</td>
                        <td className="px-4 py-3 text-cyan-300">{item.blue_score}</td>
                        <td className="px-4 py-3">
                          <span className={`rounded-md px-2 py-1 text-xs ${winnerStyle(item.winner)}`}>{item.winner}</span>
                        </td>
                        <td className="px-4 py-3 text-slate-400">{formatDate(item.created_at)}</td>
                        <td className="px-4 py-3">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              type="button"
                              onClick={() => onGenerateReport?.(item)}
                              disabled={reportingFile === item.file}
                              className="rounded-md bg-white/[0.05] px-3 py-1.5 font-mono text-xs uppercase tracking-[0.12em] text-slate-200 transition hover:bg-white/[0.1] disabled:cursor-not-allowed disabled:opacity-60"
                            >
                              {reportingFile === item.file ? "Generating..." : "AI Report"}
                            </button>
                          <button
                            type="button"
                            onClick={() => onPlayReplay?.(item)}
                            disabled={playingFile === item.file}
                            className="rounded-md bg-gradient-to-r from-blue-500/35 to-cyan-400/25 px-3 py-1.5 font-mono text-xs uppercase tracking-[0.12em] text-cyan-100 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-60"
                          >
                            {playingFile === item.file ? "Loading..." : "Play Replay"}
                          </button>
                            <button
                              type="button"
                              onClick={() => onDeleteRecord?.(item)}
                              disabled={deletingFile === item.file}
                              className="rounded-md bg-red-500/15 px-3 py-1.5 font-mono text-xs uppercase tracking-[0.12em] text-red-200 transition hover:bg-red-500/25 disabled:cursor-not-allowed disabled:opacity-60"
                            >
                              {deletingFile === item.file ? "Deleting..." : "Delete"}
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  : null}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

export default SimulationHistory;
