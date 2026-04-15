import { NODE_ICONS, STATUS_STYLE } from "./constants";

function NetworkNode({ node, selected, onClick, pulse }) {
  const statusStyle = STATUS_STYLE[node.status] || STATUS_STYLE.normal;
  const isRed = node.type === "red_agent";
  const isBlue = node.type === "blue_agent";
  const specialFill = isRed ? "#3d0a0a" : isBlue ? "#0a1f3d" : statusStyle.fill;
  const specialRing = isRed ? "#EF4444" : isBlue ? "#3B82F6" : statusStyle.ring;
  const ringWidth = selected ? 2.5 : 1.5;
  const radius = 22;

  const shouldPulse = (node.status === "compromised" || node.status === "scanning") && pulse;
  const pulseRadius = radius + 8 + Math.sin(pulse * 0.15) * 4;
  const pulseOpacity = 0.15 + Math.sin(pulse * 0.15) * 0.1;

  return (
    <g
      transform={`translate(${node.x}, ${node.y})`}
      onClick={() => onClick(node)}
      style={{ cursor: "pointer" }}
    >
      {shouldPulse && <circle r={pulseRadius} fill={specialRing} opacity={pulseOpacity} />}

      <circle r={radius} fill={specialFill} stroke={specialRing} strokeWidth={ringWidth} />

      <g stroke={specialRing} fill="none" strokeLinecap="round">
        {NODE_ICONS[node.type] || <circle r="8" strokeWidth="1.5" />}
      </g>

      <circle cx={radius - 4} cy={-(radius - 4)} r={4} fill={statusStyle.dot} stroke="#0f172a" strokeWidth="1" />

      <text
        y={radius + 12}
        textAnchor="middle"
        fontSize="9"
        fill="#e2e8f0"
        fontFamily="monospace"
        fontWeight="700"
        letterSpacing="0.5"
      >
        {node.label}
      </text>

      {node.port && (
        <text y={radius + 22} textAnchor="middle" fontSize="8" fill="#94a3b8" fontFamily="monospace">
          {node.port}
        </text>
      )}

      {node.status !== "normal" && (
        <text
          y={-(radius + 7)}
          textAnchor="middle"
          fontSize="7"
          fill={statusStyle.ring}
          fontFamily="monospace"
          fontWeight="600"
          letterSpacing="0.3"
        >
          {node.status.toUpperCase()}
        </text>
      )}
    </g>
  );
}

export default NetworkNode;
