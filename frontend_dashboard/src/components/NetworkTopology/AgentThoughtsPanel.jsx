import { useState } from "react";
import { T } from "./constants";

function CollapsibleSection({ title, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{ marginTop: 8 }}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        style={{
          width: "100%",
          textAlign: "left",
          background: "none",
          border: "none",
          color: T.grayDim,
          fontFamily: T.fontMono,
          fontSize: 9,
          cursor: "pointer",
          padding: 0,
          letterSpacing: 0.5,
        }}
      >
        {open ? "[-]" : "[+]"} {title}
      </button>
      {open && <div style={{ marginTop: 6 }}>{children}</div>}
    </div>
  );
}

function AgentCard({ log }) {
  const agentType = log.agent_type || log.metadata?.agent_type || "Unknown";
  const color = agentType === "Red" ? T.red : agentType === "Blue" ? T.blue : T.amber;
  const bg = agentType === "Red" ? T.redBg : agentType === "Blue" ? T.blueBg : T.amberBg;

  const meta = log.metadata || {};
  const hasProb = typeof meta.probability === "number";
  const hasRoll = typeof meta.roll === "number";
  const intercepted = meta.intercepted;

  return (
    <div
      style={{
        background: bg,
        border: `0.5px solid ${color}44`,
        borderRadius: 6,
        padding: 10,
        marginBottom: 10,
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
        <div style={{ color, fontSize: 9, letterSpacing: 1, fontWeight: 600 }}>
          {agentType} · {log.action_type || meta.action_type || "Action"}
        </div>
        {intercepted != null && (
          <div
            style={{
              fontSize: 8,
              padding: "1px 5px",
              borderRadius: 2,
              background: intercepted ? T.greenBg : T.redBg,
              color: intercepted ? T.green : T.red,
              border: `0.5px solid ${intercepted ? T.green : T.red}`,
            }}
          >
            {intercepted ? `INTERCEPTED${meta.intercepted_by ? ` BY ${meta.intercepted_by}` : ""}` : "NOT INTERCEPTED"}
          </div>
        )}
      </div>

      <div style={{ color: T.grayText, fontSize: 10, lineHeight: 1.5, marginBottom: 6 }}>
        <span style={{ color: T.grayDim }}>Thought:</span> {log.thought || "-"}
      </div>

      <div style={{ color: T.grayText, fontSize: 10, lineHeight: 1.5, marginBottom: 6 }}>
        <span style={{ color: T.grayDim }}>Payload:</span> {log.payload || "-"}
      </div>

      <div style={{ color: color, fontSize: 9, lineHeight: 1.5, marginBottom: 4, opacity: 0.9 }}>
        <span style={{ color: T.grayDim }}>Result:</span> {log.referee_result || "-"}
      </div>

      {(hasProb || hasRoll || meta.score_value != null || meta.previous_status) && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(80px, 1fr))",
            gap: 8,
            marginTop: 8,
            paddingTop: 8,
            borderTop: `0.5px solid ${color}33`,
          }}
        >
          {hasProb && (
            <div>
              <div style={{ color: T.grayDim, fontSize: 8 }}>PROBABILITY</div>
              <div style={{ color: T.grayText, fontSize: 10, fontWeight: 600 }}>{(meta.probability * 100).toFixed(1)}%</div>
            </div>
          )}
          {hasRoll && (
            <div>
              <div style={{ color: T.grayDim, fontSize: 8 }}>ROLL</div>
              <div style={{ color: hasRoll <= meta.probability ? T.green : T.red, fontSize: 10, fontWeight: 600 }}>{meta.roll.toFixed(3)}</div>
            </div>
          )}
          {meta.score_value != null && (
            <div>
              <div style={{ color: T.grayDim, fontSize: 8 }}>SCORE</div>
              <div style={{ color: T.grayText, fontSize: 10, fontWeight: 600 }}>{meta.score_value}</div>
            </div>
          )}
          {meta.previous_status && (
            <div>
              <div style={{ color: T.grayDim, fontSize: 8 }}>PREV STATUS</div>
              <div style={{ color: T.grayText, fontSize: 10, fontWeight: 600 }}>{meta.previous_status}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function AgentThoughtsPanel({ round }) {
  const logs = round?.action_logs || [];
  const [expanded, setExpanded] = useState(false);

  const displayLogs = expanded ? logs : logs.slice(0, 3);

  return (
    <div
      style={{
        background: T.bgPanel,
        border: `1px solid ${T.border}`,
        borderRadius: 6,
        padding: "12px 14px",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
        <div style={{ fontFamily: T.fontMono, fontSize: 10, letterSpacing: 1.2, color: T.grayText, textTransform: "uppercase" }}>
          Agent Thoughts
        </div>
        <div style={{ fontFamily: T.fontMono, fontSize: 9, color: T.grayDim }}>{logs.length} entries</div>
      </div>

      <div style={{ maxHeight: 340, overflowY: "auto" }}>
        {logs.length === 0 && (
          <div style={{ color: T.grayDim, fontSize: 10, fontFamily: T.fontMono, padding: "8px 0" }}>No action logs for this round.</div>
        )}
        {displayLogs.map((log, i) => (
          <AgentCard key={i} log={log} />
        ))}
        {logs.length > 3 && (
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            style={{
              width: "100%",
              padding: "5px 0",
              background: "none",
              border: "none",
              color: T.blue,
              fontFamily: T.fontMono,
              fontSize: 9,
              cursor: "pointer",
              textAlign: "center",
            }}
          >
            {expanded ? "SHOW LESS" : `SHOW ALL ${logs.length} ENTRIES`}
          </button>
        )}
      </div>
    </div>
  );
}

export default AgentThoughtsPanel;
