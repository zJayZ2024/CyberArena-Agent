function AnimatedEdge({
  x1,
  y1,
  x2,
  y2,
  color,
  dasharray = "6 3",
  speed = 0.4,
  markerId,
  opacity = 0.9,
  onClick,
  title,
  endPadding = 0,
}) {
  const interactive = typeof onClick === "function";
  const dx = x2 - x1;
  const dy = y2 - y1;
  const length = Math.hypot(dx, dy) || 1;
  const safePadding = Math.max(0, Math.min(endPadding, length - 1));
  const tx2 = x2 - (dx / length) * safePadding;
  const ty2 = y2 - (dy / length) * safePadding;
  return (
    <g style={{ cursor: interactive ? "pointer" : "default" }}>
      {interactive && (
        <line
          x1={x1}
          y1={y1}
          x2={tx2}
          y2={ty2}
          stroke="transparent"
          strokeWidth="12"
          onClick={onClick}
        />
      )}
      <line
        x1={x1}
        y1={y1}
        x2={tx2}
        y2={ty2}
        stroke={color}
        strokeWidth="1.8"
        strokeDasharray={dasharray}
        markerEnd={`url(#${markerId})`}
        opacity={opacity}
        style={{ animation: `cyberFlow ${speed}s linear infinite` }}
        pointerEvents={interactive ? "none" : "auto"}
      />
      {title ? <title>{title}</title> : null}
    </g>
  );
}

export default AnimatedEdge;
