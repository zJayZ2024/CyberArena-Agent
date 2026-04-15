import { EDGE_LEGEND_ITEMS, LEGEND_ITEMS } from "./constants";

function LegendBar() {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        flexWrap: "wrap",
        gap: "14px 20px",
        padding: "8px 18px",
        borderTop: "1px solid #1e293b",
        background: "#060b18",
      }}
    >
      {LEGEND_ITEMS.map((item) => (
        <div key={item.label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <div style={{ width: 8, height: 8, borderRadius: "50%", background: item.color }} />
          <span style={{ color: "#94a3b8", fontSize: 10 }}>{item.label}</span>
        </div>
      ))}

      {EDGE_LEGEND_ITEMS.map((item) => (
        <div key={item.label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <svg width="30" height="10">
            <line
              x1="0"
              y1="5"
              x2="30"
              y2="5"
              stroke={item.color}
              strokeWidth={item.strokeWidth}
              strokeDasharray={item.strokeDasharray}
            />
          </svg>
          <span style={{ color: "#94a3b8", fontSize: 10 }}>{item.label}</span>
        </div>
      ))}
    </div>
  );
}

export default LegendBar;
