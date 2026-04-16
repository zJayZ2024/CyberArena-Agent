import { T } from "./constants";

function ScoreCurve({ rounds, idx }) {
  const width = 800;
  const height = 170;
  const padding = { top: 14, right: 20, bottom: 22, left: 40 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;

  const redScores = rounds.map((r) => r.world_state?.score?.red ?? 0);
  const blueScores = rounds.map((r) => r.world_state?.score?.blue ?? 0);
  const maxScore = 100;

  const round = rounds[idx] ?? rounds[rounds.length - 1];
  const currentRed = round?.world_state?.score?.red ?? 0;
  const currentBlue = round?.world_state?.score?.blue ?? 0;
  const currentAvail = Math.round((round?.world_state?.availability ?? 1) * 100);

  const getX = (i) => {
    if (rounds.length <= 1) return padding.left + chartWidth / 2;
    return padding.left + (i / (rounds.length - 1)) * chartWidth;
  };
  const getY = (score) => padding.top + chartHeight - (score / maxScore) * chartHeight;

  const buildPath = (scores) => {
    return scores
      .map((s, i) => `${i === 0 ? "M" : "L"} ${getX(i)} ${getY(s)}`)
      .join(" ");
  };

  const buildArea = (scores) => {
    const path = buildPath(scores);
    return `${path} L ${getX(scores.length - 1)} ${padding.top + chartHeight} L ${getX(0)} ${padding.top + chartHeight} Z`;
  };

  const xTicks = [1, Math.ceil(rounds.length / 2), rounds.length];

  return (
    <div
      style={{
        background: T.bgPanel,
        border: `1px solid ${T.border}`,
        borderRadius: 6,
        padding: "14px 16px",
      }}
    >
      {/* Header */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 10,
        }}
      >
        <div
          style={{
            fontFamily: T.fontMono,
            fontSize: 11,
            letterSpacing: 1.5,
            color: T.grayText,
            textTransform: "uppercase",
          }}
        >
          Reward Curve
        </div>
        <div style={{ display: "flex", gap: 14, alignItems: "center" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 14, height: 2, background: T.red, borderRadius: 1 }} />
            <span style={{ fontFamily: T.fontMono, fontSize: 10, color: T.grayText, textTransform: "uppercase" }}>ATK</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 14, height: 2, background: T.blue, borderRadius: 1 }} />
            <span style={{ fontFamily: T.fontMono, fontSize: 10, color: T.grayText, textTransform: "uppercase" }}>DEF</span>
          </div>
        </div>
      </div>

      {/* SVG Chart */}
      <svg viewBox={`0 0 ${width} ${height}`} style={{ width: "100%", height: "auto", display: "block" }}>
        <defs>
          <linearGradient id="redGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={T.red} stopOpacity={0.35} />
            <stop offset="100%" stopColor={T.red} stopOpacity={0.02} />
          </linearGradient>
          <linearGradient id="blueGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={T.blue} stopOpacity={0.35} />
            <stop offset="100%" stopColor={T.blue} stopOpacity={0.02} />
          </linearGradient>
        </defs>

        {/* Grid lines */}
        {[0, 25, 50, 75, 100].map((v, i) => {
          const y = getY(v);
          return (
            <line
              key={i}
              x1={padding.left}
              y1={y}
              x2={width - padding.right}
              y2={y}
              stroke={T.border}
              strokeWidth={1}
              strokeDasharray="2 2"
              opacity={0.5}
            />
          );
        })}

        {/* Y-axis labels */}
        {[0, 25, 50, 75, 100].map((v, i) => {
          const y = getY(v);
          return (
            <text key={i} x={padding.left - 10} y={y + 5} textAnchor="end" fill={T.grayText} fontFamily={T.fontMono} fontSize={11}>
              {v}
            </text>
          );
        })}

        {/* X-axis labels */}
        {xTicks.map((t, i) => {
          const x = getX(t - 1);
          return (
            <text key={i} x={x} y={height - 4} textAnchor="middle" fill={T.grayDim} fontFamily={T.fontMono} fontSize={9}>
              {t}
            </text>
          );
        })}

        {/* Areas */}
        <path d={buildArea(redScores)} fill="url(#redGradient)" />
        <path d={buildArea(blueScores)} fill="url(#blueGradient)" />

        {/* Lines */}
        <path d={buildPath(redScores)} fill="none" stroke={T.red} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        <path d={buildPath(blueScores)} fill="none" stroke={T.blue} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />

        {/* Current round indicator */}
        <line
          x1={getX(idx)}
          y1={padding.top}
          x2={getX(idx)}
          y2={padding.top + chartHeight}
          stroke={T.amber}
          strokeWidth={1}
          strokeDasharray="3 3"
          opacity={0.9}
        />

        {/* Dots for current round */}
        <circle cx={getX(idx)} cy={getY(redScores[idx])} r={4} fill={T.red} stroke="#fff" strokeWidth={1.5} />
        <circle cx={getX(idx)} cy={getY(blueScores[idx])} r={4} fill={T.blue} stroke="#fff" strokeWidth={1.5} />
      </svg>

      {/* Stats row */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(3, 1fr)",
          gap: 10,
          marginTop: 12,
        }}
      >
        <div
          style={{
            background: T.bg,
            border: `1px solid ${T.border}`,
            borderRadius: 4,
            padding: "10px 0",
            textAlign: "center",
          }}
        >
          <div style={{ fontFamily: T.fontMono, fontSize: 9, color: T.grayDim, letterSpacing: 1, textTransform: "uppercase" }}>ATK</div>
          <div style={{ fontFamily: T.fontMono, fontSize: 18, color: T.red, fontWeight: 600, marginTop: 4 }}>{currentRed}</div>
        </div>
        <div
          style={{
            background: T.bg,
            border: `1px solid ${T.border}`,
            borderRadius: 4,
            padding: "10px 0",
            textAlign: "center",
          }}
        >
          <div style={{ fontFamily: T.fontMono, fontSize: 9, color: T.grayDim, letterSpacing: 1, textTransform: "uppercase" }}>DEF</div>
          <div style={{ fontFamily: T.fontMono, fontSize: 18, color: T.blue, fontWeight: 600, marginTop: 4 }}>{currentBlue}</div>
        </div>
        <div
          style={{
            background: T.bg,
            border: `1px solid ${T.border}`,
            borderRadius: 4,
            padding: "10px 0",
            textAlign: "center",
          }}
        >
          <div style={{ fontFamily: T.fontMono, fontSize: 9, color: T.grayDim, letterSpacing: 1, textTransform: "uppercase" }}>AVAIL</div>
          <div style={{ fontFamily: T.fontMono, fontSize: 18, color: T.green, fontWeight: 600, marginTop: 4 }}>{currentAvail}%</div>
        </div>
      </div>
    </div>
  );
}

export default ScoreCurve;
