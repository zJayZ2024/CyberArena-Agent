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
  immersive?: boolean;
};

export function CyberArenaLogo() {
  return (
    <div className="flex h-7 w-7 items-center justify-center rounded-md border border-cyan-300/50 bg-[#111a2e] shadow-[0_0_14px_rgba(34,211,238,0.32)]">
      <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" aria-hidden="true">
        <defs>
          <linearGradient id="logo-brand" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#67e8f9" />
            <stop offset="100%" stopColor="#22d3ee" />
          </linearGradient>
          <linearGradient id="logo-red" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#ff8793" />
            <stop offset="100%" stopColor="#ff6b7a" />
          </linearGradient>
        </defs>
        <path d="M12 2.8 19.4 7v10L12 21.2 4.6 17V7L12 2.8Z" stroke="url(#logo-brand)" strokeWidth="1.4" />
        <path d="M7.2 15.5 12 12l4.8 3.5" stroke="#7088b0" strokeWidth="1.1" strokeLinecap="round" />
        <circle cx="7.2" cy="15.5" r="1.1" fill="#5b9fff" />
        <circle cx="16.8" cy="15.5" r="1.1" fill="#5b9fff" />
        <circle cx="12" cy="12" r="1.6" fill="url(#logo-red)" />
        <path d="M10 8.2h4" stroke="#a5f3fc" strokeWidth="1.1" strokeLinecap="round" />
      </svg>
    </div>
  );
}

function TopBar({
  roundIndex = 0,
  displayRound = 0,
  totalRounds = 20,
  frameCount = 20,
  redScore = 118,
  blueScore = 104,
  playing = false,
  onTogglePlay,
  onNext,
  onSeek,
  immersive = false,
}: TopBarProps) {
  const safeTotal = Math.max(totalRounds, 1);
  const safeFrameCount = Math.max(frameCount, 1);
  const clampedIndex = Math.min(Math.max(roundIndex, 0), safeFrameCount - 1);
  const clampedDisplayRound = Math.min(Math.max(displayRound, 0), safeTotal);
  const redRatio = redScore + blueScore > 0 ? redScore / (redScore + blueScore) : 0.5;
  const headerClass = immersive ? "bg-transparent" : "border-b border-[#2a3f5f] bg-[#111a2e]";
  const panelClass = immersive
    ? "border-white/[0.14] bg-[#111a2e]"
    : "border-[#304060] bg-[#162340]";
  const buttonClass = immersive
    ? "border-white/[0.14] bg-[#162340]"
    : "border-[#304060] bg-[#1c2d4a]";

  return (
    <header className={`h-16 shrink-0 px-4 ${headerClass}`}>
      <div className="grid h-full grid-cols-[1fr_440px] items-center gap-4">
        <div className={`mx-auto flex w-full max-w-[520px] items-center justify-center gap-3 rounded-lg border px-4 py-2 ${panelClass}`}>
          <span className="font-mono text-xs uppercase tracking-[0.18em] text-[#8a9bc0]">回合</span>
          <span className="font-mono text-sm text-[#f0f4ff]">
            {clampedDisplayRound} / {safeTotal}
          </span>

          <div className="flex h-2 w-24 overflow-hidden rounded-full bg-[#1c2d4a]">
            <div className="h-full bg-[#ff6b7a]" style={{ width: `${Math.round(redRatio * 100)}%` }} />
            <div className="h-full flex-1 bg-[#5b9fff]" />
          </div>
          <span className="font-mono text-xs text-[#ff6b7a]">红方 {redScore}</span>
          <span className="text-[#7088b0]">:</span>
          <span className="font-mono text-xs text-[#5b9fff]">蓝方 {blueScore}</span>
        </div>

        <div className="flex items-center justify-end gap-2">
          <button
            type="button"
            className={`rounded-md border px-3 py-1.5 font-mono text-xs text-slate-200 transition hover:border-[#a78bfa] hover:text-[#c4b5fd] ${buttonClass}`}
            onClick={onTogglePlay}
          >
            {playing ? "暂停" : "播放"}
          </button>
          <button
            type="button"
            className={`rounded-md border px-3 py-1.5 font-mono text-xs text-slate-200 transition hover:border-[#a78bfa] hover:text-[#c4b5fd] ${buttonClass}`}
            onClick={onNext}
          >
            下一步
          </button>

          <div className="ml-2 w-56">
            <input
              type="range"
              min={0}
              max={Math.max(safeFrameCount - 1, 0)}
              value={clampedIndex}
              onChange={(event) => onSeek?.(Number(event.target.value))}
              className="h-1.5 w-full cursor-pointer appearance-none rounded-full bg-[#1c2d4a] accent-[#a78bfa]"
            />
          </div>
        </div>
      </div>
    </header>
  );
}

export default TopBar;
