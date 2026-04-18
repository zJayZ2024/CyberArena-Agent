type TopBarProps = {
  roundIndex?: number;
  displayRound?: number;
  totalRounds?: number;
  frameCount?: number;
  redScore?: number;
  blueScore?: number;
  playing?: boolean;
  onTogglePlay?: () => void;
  onNext?: () => void;
  onSeek?: (index: number) => void;
};

function CyberArenaLogo() {
  return (
    <div className="flex h-7 w-7 items-center justify-center rounded-md border border-[#3b82f6]/40 bg-[#080f1c] shadow-[0_0_12px_rgba(59,130,246,0.35)]">
      <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" aria-hidden="true">
        <defs>
          <linearGradient id="logo-blue" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#60a5fa" />
            <stop offset="100%" stopColor="#2563eb" />
          </linearGradient>
          <linearGradient id="logo-red" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#f87171" />
            <stop offset="100%" stopColor="#dc2626" />
          </linearGradient>
        </defs>
        <path d="M12 2.8 19.4 7v10L12 21.2 4.6 17V7L12 2.8Z" stroke="url(#logo-blue)" strokeWidth="1.4" />
        <path d="M7.2 15.5 12 12l4.8 3.5" stroke="#475569" strokeWidth="1.1" strokeLinecap="round" />
        <circle cx="7.2" cy="15.5" r="1.1" fill="#334155" />
        <circle cx="16.8" cy="15.5" r="1.1" fill="#334155" />
        <circle cx="12" cy="12" r="1.6" fill="url(#logo-red)" />
        <path d="M10 8.2h4" stroke="#93c5fd" strokeWidth="1.1" strokeLinecap="round" />
      </svg>
    </div>
  );
}

function TopBar({
  roundIndex = 0,
  displayRound = 1,
  totalRounds = 20,
  frameCount = 20,
  redScore = 118,
  blueScore = 104,
  playing = false,
  onTogglePlay,
  onNext,
  onSeek,
}: TopBarProps) {
  const safeTotal = Math.max(totalRounds, 1);
  const safeFrameCount = Math.max(frameCount, 1);
  const clampedIndex = Math.min(Math.max(roundIndex, 0), safeFrameCount - 1);
  const clampedDisplayRound = Math.min(Math.max(displayRound, 1), safeTotal);
  const redRatio = redScore + blueScore > 0 ? redScore / (redScore + blueScore) : 0.5;

  return (
    <header className="h-16 shrink-0 border-b border-[#1f2937] bg-[#0d1117]/95 px-4">
      <div className="grid h-full grid-cols-[240px_1fr_440px] items-center gap-4">
        <div className="flex items-center gap-3">
          <CyberArenaLogo />
          <div className="leading-tight">
            <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-slate-400">CyberArena-Agent</p>
            <p className="text-xs text-slate-500">Attack/Defense Replay Console</p>
          </div>
        </div>

        <div className="mx-auto flex w-full max-w-[520px] items-center justify-center gap-3 rounded-lg border border-[#1f2937] bg-[#07090f] px-4 py-2">
          <span className="font-mono text-xs uppercase tracking-[0.18em] text-slate-500">Round</span>
          <span className="font-mono text-sm text-slate-100">
            {clampedDisplayRound} / {safeTotal}
          </span>

          <div className="h-2 w-24 overflow-hidden rounded-full bg-[#1f2937]">
            <div className="h-full rounded-full bg-[#ef4444]" style={{ width: `${Math.round(redRatio * 100)}%` }} />
          </div>
          <span className="font-mono text-xs text-red-400">RED {redScore}</span>
          <span className="text-slate-600">:</span>
          <span className="font-mono text-xs text-blue-400">BLUE {blueScore}</span>
        </div>

        <div className="flex items-center justify-end gap-2">
          <button
            type="button"
            className="rounded-md border border-[#1f2937] bg-[#111827] px-3 py-1.5 font-mono text-xs text-slate-200 transition hover:border-[#3b82f6] hover:text-[#3b82f6]"
            onClick={onTogglePlay}
          >
            {playing ? "Pause" : "Play"}
          </button>
          <button
            type="button"
            className="rounded-md border border-[#1f2937] bg-[#111827] px-3 py-1.5 font-mono text-xs text-slate-200 transition hover:border-[#3b82f6] hover:text-[#3b82f6]"
            onClick={onNext}
          >
            Next
          </button>

          <div className="ml-2 w-56">
            <input
              type="range"
              min={0}
              max={Math.max(safeFrameCount - 1, 0)}
              value={clampedIndex}
              onChange={(event) => onSeek?.(Number(event.target.value))}
              className="h-1.5 w-full cursor-pointer appearance-none rounded-full bg-[#1f2937] accent-[#3b82f6]"
            />
          </div>
        </div>
      </div>
    </header>
  );
}

export default TopBar;
