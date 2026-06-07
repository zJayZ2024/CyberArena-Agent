import { T } from "./constants";
import { translateSeverity } from "../../utils/localization";

const EVENT_TYPE_LABELS = {
  ATK: "攻击",
  DEF: "防御",
  CRIT: "严重",
  WARN: "警告",
  INFO: "信息",
  ALERT: "告警",
};

function eventTypeLabel(type) {
  return EVENT_TYPE_LABELS[type] || translateSeverity(type, type);
}

function EventLog({ rounds, idx }) {
  const visibleRounds = rounds.slice(0, idx + 1);

  const events = [];
  visibleRounds.forEach((r) => {
    const red = r.red_action;
    const blue = r.blue_action;
    const judge = r.judge_result;

    const redLog = judge?.logs?.[0] || "";
    const redText = redLog
      ? `${red.technique_id} ${red.technique} -> ${red.target_node} ${redLog}`
      : `${red.technique_id} ${red.technique} -> ${red.target_node}`;
    events.push({
      round: r.round,
      type: "ATK",
      text: redText,
      rightBadge: red.technique_id,
      color: T.red,
      bg: T.redBg,
      dim: T.redDim,
    });

    const target = blue.target || blue.target_node || "系统";
    events.push({
      round: r.round,
      type: "DEF",
      text: `${target}: ${blue.reasoning}`,
      rightBadge: null,
      color: T.blue,
      bg: T.blueBg,
      dim: T.blueDim,
    });

    (r.security_alerts || []).forEach((alert) => {
      events.push({
        round: r.round,
        type: alert.severity || "ALERT",
        text: alert.message,
        rightBadge: alert.target,
        color: alert.severity === "CRIT" ? T.red : alert.severity === "WARN" ? T.amber : T.grayText,
        bg: alert.severity === "CRIT" ? T.redBg : alert.severity === "WARN" ? T.amberBg : T.bg,
        dim: alert.severity === "CRIT" ? T.redDim : alert.severity === "WARN" ? T.amber : T.border,
      });
    });
  });

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
            fontSize: 10,
            letterSpacing: 1.2,
            color: T.grayText,
            textTransform: "uppercase",
          }}
        >
          事件日志
        </div>
        <div style={{ fontFamily: T.fontMono, fontSize: 9, color: T.grayDim }}>
          {events.length} 条事件
        </div>
      </div>

      <div
        style={{
          display: "flex",
          flexDirection: "column",
          gap: 6,
          maxHeight: 280,
          overflowY: "auto",
        }}
      >
        {events.map((e, i) => (
          <div
            key={i}
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: 8,
              padding: "6px 8px",
              background: T.bg,
              border: `1px solid ${T.border}`,
              borderRadius: 4,
            }}
          >
            <span
              style={{
                fontFamily: T.fontMono,
                fontSize: 9,
                color: T.grayDim,
                minWidth: 20,
                paddingTop: 2,
              }}
            >
              R{e.round}
            </span>
            <span
              style={{
                fontFamily: T.fontMono,
                fontSize: 8,
                fontWeight: 600,
                color: e.color,
                background: e.bg,
                border: `1px solid ${e.dim}`,
                borderRadius: 2,
                padding: "1px 4px",
                textTransform: "uppercase",
                letterSpacing: 0.5,
                marginTop: 2,
              }}
            >
              {eventTypeLabel(e.type)}
            </span>
            <span
              style={{
                flex: 1,
                fontFamily: T.fontMono,
                fontSize: 10,
                color: e.type === "ATK" ? "#ffb3b3" : e.type === "DEF" ? "#a3cdff" : e.type === "CRIT" ? "#ffb3b3" : e.type === "WARN" ? "#ffe066" : "#b8c5db",
                lineHeight: 1.4,
                paddingTop: 2,
              }}
            >
              {e.text}
            </span>
            {e.rightBadge ? (
              <span
                style={{
                  fontFamily: T.fontMono,
                  fontSize: 9,
                  color: e.color,
                  paddingTop: 2,
                  minWidth: 36,
                  textAlign: "right",
                }}
              >
                {e.rightBadge}
              </span>
            ) : null}
          </div>
        ))}
      </div>
    </div>
  );
}

export default EventLog;
