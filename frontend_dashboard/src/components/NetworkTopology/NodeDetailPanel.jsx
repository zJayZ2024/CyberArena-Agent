import { STATUS_STYLE } from "./constants";

function NodeDetailPanel({ node, onClose }) {
  if (!node) {
    return null;
  }

  const statusStyle = STATUS_STYLE[node.status] || STATUS_STYLE.normal;

  return (
    <div
      style={{
        margin: "0 18px 14px",
        padding: "10px 14px",
        background: "#0f172a",
        borderRadius: 8,
        border: `1px solid ${statusStyle.ring}`,
        display: "flex",
        alignItems: "flex-start",
        gap: 20,
      }}
    >
      <div>
        <div style={{ color: "#e2e8f0", fontSize: 13, fontWeight: 700, marginBottom: 4 }}>
          {node.label}
          <span
            style={{
              marginLeft: 8,
              fontSize: 10,
              fontWeight: 600,
              color: statusStyle.ring,
              background: "#1e293b",
              padding: "2px 7px",
              borderRadius: 4,
            }}
          >
            {statusStyle.label.toUpperCase()}
          </span>
        </div>
        <div style={{ color: "#64748b", fontSize: 10, marginBottom: 2 }}>
          TYPE: {node.type.replaceAll("_", " ").toUpperCase()}
        </div>
        <div style={{ color: "#64748b", fontSize: 10, marginBottom: 2 }}>
          ZONE: {node.zone.toUpperCase()}
        </div>
        {node.port && (
          <div style={{ color: "#64748b", fontSize: 10 }}>
            PORT: <span style={{ color: "#94a3b8" }}>{node.port}</span>
          </div>
        )}
      </div>

      <div style={{ marginLeft: "auto" }}>
        <button
          onClick={onClose}
          style={{
            background: "none",
            border: "1px solid #334155",
            borderRadius: 4,
            color: "#94a3b8",
            cursor: "pointer",
            padding: "3px 10px",
            fontSize: 10,
          }}
        >
          Close
        </button>
      </div>
    </div>
  );
}

export default NodeDetailPanel;
