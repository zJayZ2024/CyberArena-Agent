import { useId, useMemo } from "react";

type LiveScoreChartProps = {
  rounds?: any[];
  currentRoundIndex?: number;
  totalRounds?: number;
};

type ScorePoint = {
  round: number;
  red: number;
  blue: number;
};

function toFiniteNumber(value: unknown): number | null {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function niceCeil(value: number): number {
  if (!Number.isFinite(value) || value <= 0) {
    return 10;
  }
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const normalized = value / magnitude;
  let step = 1;
  if (normalized > 1) {
    step = 2;
  }
  if (normalized > 2) {
    step = 5;
  }
  if (normalized > 5) {
    step = 10;
  }
  return step * magnitude;
}

function hasRoundZeroFrame(rounds: any[]) {
  const first = rounds[0];
  const value = toFiniteNumber(first?.round ?? first?.turn ?? first?.world_state?.round);
  return value === 0;
}

function extractScoreTimelineByPlayback(rounds: any[], totalRounds: number) {
  const includesRoundZero = hasRoundZeroFrame(rounds);
  const timeline: ScorePoint[] = [];
  let lastRed = 0;
  let lastBlue = 0;

  for (let round = 0; round <= totalRounds; round += 1) {
    if (round === 0) {
      timeline.push({ round: 0, red: 0, blue: 0 });
      continue;
    }

    const sourceIndex = includesRoundZero ? round : round - 1;
    const item = rounds[sourceIndex];
    const red = toFiniteNumber(item?.world_state?.score?.red ?? item?.red_score);
    const blue = toFiniteNumber(item?.world_state?.score?.blue ?? item?.blue_score);

    if (typeof red === "number") {
      lastRed = red;
    }
    if (typeof blue === "number") {
      lastBlue = blue;
    }

    timeline.push({
      round,
      red: lastRed,
      blue: lastBlue,
    });
  }

  return timeline;
}

function buildPathFromY(yValues: number[], visibleRound: number, xForRound: (round: number) => number) {
  if (!yValues.length) {
    return "";
  }

  const cappedRound = Math.min(Math.max(visibleRound, 0), yValues.length - 1);
  const points: string[] = [`M ${xForRound(0)} ${yValues[0]}`];
  for (let round = 1; round <= cappedRound; round += 1) {
    const x = xForRound(round);
    const y = yValues[round] ?? yValues[round - 1] ?? yValues[0];
    points.push(`L ${x} ${y}`);
  }
  return points.join(" ");
}

function LiveScoreChart({
  rounds = [],
  currentRoundIndex = 0,
  totalRounds = 20,
}: LiveScoreChartProps) {
  const safeTotalRounds = Math.max(1, Math.round(totalRounds || 20));
  const clampedRoundIndex = Math.min(Math.max(Math.round(currentRoundIndex), 0), Math.max(rounds.length - 1, 0));
  const sourceHasRoundZero = useMemo(() => hasRoundZeroFrame(rounds), [rounds]);
  const visibleRound = Math.min(
    Math.max(
      rounds.length ? clampedRoundIndex + (sourceHasRoundZero ? 0 : 1) : 0,
      0,
    ),
    safeTotalRounds,
  );

  // Use full timeline only for a fixed Y-axis domain.
  const fullScoreTimeline = useMemo<ScorePoint[]>(
    () => extractScoreTimelineByPlayback(rounds, safeTotalRounds),
    [rounds, safeTotalRounds],
  );
  // Use live timeline (up to current frame only) for visible line growth.
  const liveScoreTimeline = useMemo<ScorePoint[]>(
    () => extractScoreTimelineByPlayback(rounds.slice(0, clampedRoundIndex + 1), safeTotalRounds),
    [rounds, clampedRoundIndex, safeTotalRounds],
  );

  const maxScore = useMemo(() => {
    const peak = Math.max(0, ...fullScoreTimeline.flatMap((point) => [point.red, point.blue]));
    if (peak <= 0) {
      return 10;
    }
    // Keep axis fixed for the whole replay; use smaller headroom so vertical variation is slightly stronger.
    return niceCeil(peak * 1.04);
  }, [fullScoreTimeline]);

  const latestIndex = Math.max(visibleRound, 0);
  const latestPoint = liveScoreTimeline[latestIndex] ?? liveScoreTimeline[0] ?? { red: 0, blue: 0 };
  const displayRed = latestPoint.red;
  const displayBlue = latestPoint.blue;

  const view = { width: 620, height: 210 };
  const padding = { top: 20, right: 14, bottom: 24, left: 16 };
  const plotWidth = view.width - padding.left - padding.right;
  const plotHeight = view.height - padding.top - padding.bottom;

  const xForRound = (round: number) => {
    const divider = Math.max(safeTotalRounds, 1);
    return padding.left + (round / divider) * plotWidth;
  };

  const yForScore = (score: number) => {
    const ratio = Math.max(0, Math.min(score / maxScore, 1));
    // Mild gamma stretch to make vertical changes more noticeable without being exaggerated.
    const stretchedRatio = Math.pow(ratio, 0.9);
    return padding.top + (1 - stretchedRatio) * plotHeight;
  };

  const redValues = liveScoreTimeline.map((point) => point.red);
  const blueValues = liveScoreTimeline.map((point) => point.blue);

  // When two lines overlap or are too close, apply a tiny visual split so both are visible.
  const baseRedYValues = redValues.map((value) => yForScore(value));
  const baseBlueYValues = blueValues.map((value) => yForScore(value));
  const redYValues = baseRedYValues.map((baseY, index) => {
    if (index === 0) {
      return baseY;
    }
    const blueY = baseBlueYValues[index] ?? baseY;
    if (Math.abs(baseY - blueY) < 1.5) {
      return Math.max(padding.top, baseY - 1.2);
    }
    return baseY;
  });
  const blueYValues = baseBlueYValues.map((baseY, index) => {
    if (index === 0) {
      return baseY;
    }
    const redY = baseRedYValues[index] ?? baseY;
    if (Math.abs(baseY - redY) < 1.5) {
      return Math.min(padding.top + plotHeight, baseY + 1.2);
    }
    return baseY;
  });

  const redPath = buildPathFromY(redYValues, visibleRound, xForRound);
  const bluePath = buildPathFromY(blueYValues, visibleRound, xForRound);

  const markerRound = Math.max(0, visibleRound);
  const markerX = xForRound(markerRound);
  const markerRedY = redYValues[markerRound] ?? redYValues[0] ?? yForScore(displayRed);
  const markerBlueY = blueYValues[markerRound] ?? blueYValues[0] ?? yForScore(displayBlue);

  const uid = useId().replace(/:/g, "");
  const redGlowId = `glow-red-${uid}`;
  const blueGlowId = `glow-blue-${uid}`;

  return (
    <article className="rounded-2xl border border-white/[0.05] bg-white/[0.02] p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]">
      <div className="mb-2 flex items-start justify-between gap-2">
        <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-slate-400">得分趋势（红方 vs 蓝方）</p>
        <div className="text-right font-mono leading-5">
          <p className="text-sm text-red-400">红方：{displayRed}</p>
          <p className="text-sm text-blue-400">蓝方：{displayBlue}</p>
        </div>
      </div>

      <svg className="h-44 w-full bg-transparent" viewBox={`0 0 ${view.width} ${view.height}`} preserveAspectRatio="none" role="img" aria-label="红蓝双方实时得分趋势">
        <defs>
          <filter id={redGlowId} x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="2.2" result="redBlur" />
            <feMerge>
              <feMergeNode in="redBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <filter id={blueGlowId} x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="2.2" result="blueBlur" />
            <feMerge>
              <feMergeNode in="blueBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {Array.from({ length: 4 }, (_, index) => {
          const ratio = index / 3;
          const y = padding.top + ratio * plotHeight;
          return (
            <line
              key={`grid-${index}`}
              x1={padding.left}
              y1={y}
              x2={view.width - padding.right}
              y2={y}
              stroke="rgba(255,255,255,0.08)"
              strokeWidth="1"
              strokeDasharray="4 4"
            />
          );
        })}

        {bluePath ? (
          <path d={bluePath} fill="none" stroke="#3b82f6" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" filter={`url(#${blueGlowId})`} />
        ) : null}
        {redPath ? (
          <path d={redPath} fill="none" stroke="#ef4444" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" filter={`url(#${redGlowId})`} />
        ) : null}

        {visibleRound >= 0 ? (
          <>
            <circle cx={markerX} cy={markerBlueY} r="3.2" fill="#3b82f6" filter={`url(#${blueGlowId})`}>
              <animate attributeName="r" values="3;5;3" dur="1.8s" repeatCount="indefinite" />
            </circle>
            <circle cx={markerX} cy={markerRedY} r="3.2" fill="#ef4444" filter={`url(#${redGlowId})`}>
              <animate attributeName="r" values="3;5;3" dur="1.8s" repeatCount="indefinite" />
            </circle>
          </>
        ) : null}

        <text x={padding.left} y={view.height - 6} fontSize="10" fill="#64748b" fontFamily="ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, Courier New, monospace">
          回合 0
        </text>
        <text x={view.width - padding.right} y={view.height - 6} textAnchor="end" fontSize="10" fill="#64748b" fontFamily="ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, Courier New, monospace">
          回合 {safeTotalRounds}
        </text>
      </svg>
    </article>
  );
}

export default LiveScoreChart;
