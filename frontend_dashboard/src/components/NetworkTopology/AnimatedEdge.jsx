function AnimatedEdge({ x1, y1, x2, y2, color, dasharray = "6 3", speed = 0.4, markerId, opacity = 0.9 }) {
  return (
    <line
      x1={x1}
      y1={y1}
      x2={x2}
      y2={y2}
      stroke={color}
      strokeWidth="1.8"
      strokeDasharray={dasharray}
      markerEnd={`url(#${markerId})`}
      opacity={opacity}
      style={{ animation: `cyberFlow ${speed}s linear infinite` }}
    />
  );
}

export default AnimatedEdge;
