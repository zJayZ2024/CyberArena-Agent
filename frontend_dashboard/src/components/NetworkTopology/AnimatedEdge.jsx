function AnimatedEdge({ from, to, type, label, nodes, tick }) {
  const n1 = nodes.find((node) => node.id === from);
  const n2 = nodes.find((node) => node.id === to);

  if (!n1 || !n2) {
    return null;
  }

  const dx = n2.x - n1.x;
  const dy = n2.y - n1.y;
  const len = Math.sqrt(dx * dx + dy * dy);
  const nx = dx / len;
  const ny = dy / len;
  const nodeRadius = 22;
  const x1 = n1.x + nx * nodeRadius;
  const y1 = n1.y + ny * nodeRadius;
  const x2 = n2.x - nx * nodeRadius;
  const y2 = n2.y - ny * nodeRadius;
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2;

  const isAttack = type === "attack";
  const isDefense = type === "defense";
  const isNetwork = type === "network";

  const strokeColor = isAttack ? "#EF4444" : isDefense ? "#3B82F6" : "#4b5563";
  const dashArray = isAttack || isDefense ? "6 4" : "4 4";
  const dashOffset = isAttack ? -(tick * 0.5) % 20 : isDefense ? (tick * 0.4) % 20 : 0;
  const strokeWidth = isNetwork ? 1 : 1.5;
  const opacity = isNetwork ? 0.3 : 0.85;
  const markerId = `arrow-${type}-${from}-${to}`;

  return (
    <g>
      <defs>
        <marker
          id={markerId}
          viewBox="0 0 10 10"
          refX="8"
          refY="5"
          markerWidth="5"
          markerHeight="5"
          orient="auto-start-reverse"
        >
          <path
            d="M2 2L8 5L2 8"
            fill="none"
            stroke={strokeColor}
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </marker>
      </defs>

      <line
        x1={x1}
        y1={y1}
        x2={x2}
        y2={y2}
        stroke={strokeColor}
        strokeWidth={strokeWidth}
        strokeDasharray={dashArray}
        strokeDashoffset={dashOffset}
        opacity={opacity}
        markerEnd={`url(#${markerId})`}
      />

      {label && (
        <g>
          <rect
            x={mx - label.length * 3.5}
            y={my - 10}
            width={label.length * 7 + 4}
            height={15}
            rx="3"
            fill="#0f172a"
            fillOpacity="0.9"
            stroke={strokeColor}
            strokeWidth="0.5"
          />
          <text
            x={mx}
            y={my + 1}
            textAnchor="middle"
            dominantBaseline="central"
            fontSize="8"
            fill={strokeColor}
            fontFamily="monospace"
            fontWeight="600"
          >
            {label}
          </text>
        </g>
      )}
    </g>
  );
}

export default AnimatedEdge;
