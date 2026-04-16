import { T } from "./constants";

function EventLog({ rounds, idx }) {
  const visibleRounds = rounds.slice(0, idx + 1);

  const events = [];
  visibleRounds.forEach((r) => {
    const red = r.red_action;
    const blue = r.blue_action;
    const judge = r.judge_result;

    // ATK event
    const redLog = judge?.logs?.[0] || "";
    const redText = redLog
      ? `${red.technique_id} ${red.technique} → ${red.target_node} ${redLog}`
      : `${red.technique_id} ${red.technique} → ${red.target_node}`;
    events.push({
      round: r.round,
      type: "ATK",
      text: redText,
      rightBadge: red.technique_id,
    });

    // DEF event
    const target = blue.target || blue.target_node || "System";
    events.push({
      round: r.round,
      type: "DEF",
      text: `${target}: ${blue.reasoning}`,
    });
  });

  return (
    <div
      style={{
        background: T.bgPanel,
        border: `1px solid ${T.border}`,
        borderRadius: 6,
        padding: "14px 16px",
        marginTop: 14,
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
          Event Log
        </div>
        <div style={{ fontFamily: T.fontMono, fontSize: 10, color: T.grayDim }}
        >
          {events.length} events
        </div>
      </div>

      {/* List */}
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          gap: 8,
          maxHeight: 220,
          overflowY: "auto",
        }}
      >
        {events.map((e, i) => (
          <div
            key={i}
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: 10,
              padding: "8px 10px",
              background: T.bg,
              border: `1px solid ${T.border}`,
              borderRadius: 4,
            }}
          >
            <span
              style={{
                fontFamily: T.fontMono,
                fontSize: 10,
                color: T.grayDim,
                minWidth: 22,
                paddingTop: 1,
              }}
            >
              R{e.round}
            </span>
            <span
              style={{
                fontFamily: T.fontMono,
                fontSize: 9,
                fontWeight: 600,
                color: e.type === "ATK" ? T.red : T.blue,
                background: e.type === "ATK" ? T.redBg : T.blueBg,
                border: `1px solid ${e.type === "ATK" ? T.redDim : T.blueDim}`,
                borderRadius: 3,
                padding: "2px 6px",
                textTransform: "uppercase",
                letterSpacing: 0.5,
                marginTop: 1,
              }}
            >
              {e.type}
            </span>
            <span
              style={{
                flex: 1,
                fontFamily: T.fontMono,
                fontSize: 11,
                color: "#c9cdd4",
                lineHeight: 1.45,
                paddingTop: 1,
              }}
            >
              {e.text}
            </span>
            {e.rightBadge ? (
              <span
                style={{
                  fontFamily: T.fontMono,
                  fontSize: 10,
                  color: T.red,
                  paddingTop: 1,
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
