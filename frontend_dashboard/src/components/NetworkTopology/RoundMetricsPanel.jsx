import { T } from "./constants";
import { translateAction } from "../../utils/localization";

function MetricCard({ label, value, color, subtext }) {
  return (
    <div
      style={{
        background: T.bg,
        border: `1px solid ${T.border}`,
        borderRadius: 4,
        padding: "8px 0",
        textAlign: "center",
      }}
    >
      <div style={{ fontFamily: T.fontMono, fontSize: 8, color: T.grayDim, letterSpacing: 1, textTransform: "uppercase" }}>{label}</div>
      <div style={{ fontFamily: T.fontMono, fontSize: 16, color, fontWeight: 600, marginTop: 2 }}>{value}</div>
      {subtext && <div style={{ fontFamily: T.fontMono, fontSize: 8, color: T.grayDim, marginTop: 2 }}>{subtext}</div>}
    </div>
  );
}

function MiniBar({ label, value, max = 100, color }) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100));
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontFamily: T.fontMono, fontSize: 8, color: T.grayDim, marginBottom: 3 }}>
        <span>{label}</span>
        <span>{typeof value === "number" ? value.toFixed(value % 1 === 0 ? 0 : 1) : value}</span>
      </div>
      <div style={{ height: 5, background: T.bg, borderRadius: 2, overflow: "hidden", border: `0.5px solid ${T.border}` }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 2 }} />
      </div>
    </div>
  );
}

function RoundMetricsPanel({ round }) {
  const ws = round?.world_state || {};
  const systemHealth = ws.system_health ?? 100;
  const exposure = ws.exposure_level ?? 0;
  const redScore = ws.score?.red ?? 0;
  const blueScore = ws.score?.blue ?? 0;

  const logs = round?.action_logs || [];
  const redLog = logs.find((l) => l.agent_type === "Red" || l.metadata?.agent_type === "Red");
  const blueLog = logs.find((l) => l.agent_type === "Blue" || l.metadata?.agent_type === "Blue");
  const redMeta = redLog?.metadata || {};
  const blueMeta = blueLog?.metadata || {};

  const scoreSummary = logs.find((l) => l.agent_type === "Referee")?.metadata?.score_summary || {};

  return (
    <div
      style={{
        background: T.bgPanel,
        border: `1px solid ${T.border}`,
        borderRadius: 6,
        padding: "12px 14px",
        marginTop: 12,
      }}
    >
      <div style={{ fontFamily: T.fontMono, fontSize: 10, letterSpacing: 1.2, color: T.grayText, textTransform: "uppercase", marginBottom: 10 }}>
        回合指标
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginBottom: 12 }}>
        <MetricCard label="健康度" value={`${systemHealth}%`} color={T.green} />
        <MetricCard label="暴露面" value={`${exposure}%`} color={T.amber} />
        <MetricCard label="红方" value={redScore} color={T.red} />
        <MetricCard label="蓝方" value={blueScore} color={T.blue} />
      </div>

      {(typeof redMeta.probability === "number" || typeof blueMeta.score_value === "number") && (
        <div style={{ marginBottom: 10, paddingTop: 10, borderTop: `0.5px solid ${T.border}` }}>
          <div style={{ color: T.grayDim, fontSize: 8, letterSpacing: 0.5, marginBottom: 6 }}>概率事件</div>
          {typeof redMeta.probability === "number" && (
            <MiniBar label={`红方 ${translateAction(redMeta.action_type || "Action", redMeta.action_type || "动作")} 成功概率`} value={redMeta.probability * 100} max={100} color={T.red} />
          )}
          {typeof redMeta.roll === "number" && (
            <div style={{ display: "flex", justifyContent: "space-between", fontFamily: T.fontMono, fontSize: 8, color: T.grayText, marginBottom: 6 }}>
              <span>掷点结果</span>
              <span style={{ color: redMeta.roll <= redMeta.probability ? T.green : T.red }}>{redMeta.roll.toFixed(3)}</span>
            </div>
          )}
          {typeof blueMeta.score_value === "number" && (
            <MiniBar label={`蓝方 ${translateAction(blueMeta.action_type || "Action", blueMeta.action_type || "动作")} 得分值`} value={blueMeta.score_value} max={Math.max(blueMeta.score_value, 30)} color={T.blue} />
          )}
        </div>
      )}

      {(scoreSummary.red_delta != null || scoreSummary.blue_delta != null) && (
        <div style={{ paddingTop: 10, borderTop: `0.5px solid ${T.border}` }}>
          <div style={{ color: T.grayDim, fontSize: 8, letterSpacing: 0.5, marginBottom: 6 }}>得分变化</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 }}>
            <div style={{ textAlign: "center" }}>
              <div style={{ fontFamily: T.fontMono, fontSize: 8, color: T.grayDim }}>红方 Δ</div>
              <div style={{ fontFamily: T.fontMono, fontSize: 12, color: T.red, fontWeight: 600 }}>+{scoreSummary.red_delta}</div>
            </div>
            <div style={{ textAlign: "center" }}>
              <div style={{ fontFamily: T.fontMono, fontSize: 8, color: T.grayDim }}>蓝方 Δ</div>
              <div style={{ fontFamily: T.fontMono, fontSize: 12, color: T.blue, fontWeight: 600 }}>+{scoreSummary.blue_delta}</div>
            </div>
            {scoreSummary.interception_bonus != null && (
              <div style={{ textAlign: "center" }}>
                <div style={{ fontFamily: T.fontMono, fontSize: 8, color: T.grayDim }}>加成</div>
                <div style={{ fontFamily: T.fontMono, fontSize: 12, color: T.green, fontWeight: 600 }}>+{scoreSummary.interception_bonus}</div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default RoundMetricsPanel;
