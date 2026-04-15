import AnimatedEdge from "./AnimatedEdge";
import NetworkNode from "./NetworkNode";
import { GRAPH_DIMENSIONS, ZONES } from "./constants";

function SvgGraph({ nodes, edges, redScore, blueScore, selectedNodeId, tick, onSelectNode }) {
  const { svgWidth, svgHeight, zoneHeight, zoneY } = GRAPH_DIMENSIONS;

  return (
    <div style={{ position: "relative" }}>
      <svg width="100%" viewBox={`0 0 ${svgWidth} ${svgHeight}`} style={{ display: "block" }}>
        {ZONES.map((zone) => (
          <g key={zone.id}>
            <rect
              x={zone.x}
              y={zoneY}
              width={zone.w}
              height={zoneHeight}
              rx="8"
              fill={zone.color}
              fillOpacity="0.6"
              stroke={zone.border}
              strokeWidth="1"
              strokeOpacity="0.25"
              strokeDasharray="4 4"
            />
            <text
              x={zone.x + zone.w / 2}
              y={zoneY + 18}
              textAnchor="middle"
              fontSize="9"
              fill={zone.border}
              fontFamily="monospace"
              letterSpacing="2"
              fontWeight="600"
              opacity="0.7"
            >
              {zone.label}
            </text>
          </g>
        ))}

        <rect
          x={32}
          y={zoneY + 10}
          width={92}
          height={zoneHeight - 20}
          rx="6"
          fill="none"
          stroke="#EF4444"
          strokeWidth="1"
          strokeDasharray="4 3"
          strokeOpacity="0.6"
        />
        <text
          x={78}
          y={zoneY + 25}
          textAnchor="middle"
          fontSize="8"
          fill="#EF4444"
          fontFamily="monospace"
          letterSpacing="1"
        >
          RED BASE
        </text>
        <text
          x={78}
          y={zoneY + zoneHeight - 18}
          textAnchor="middle"
          fontSize="10"
          fill="#EF4444"
          fontFamily="monospace"
          fontWeight="700"
        >
          {redScore} pts
        </text>

        <rect
          x={806}
          y={zoneY + 10}
          width={100}
          height={zoneHeight - 20}
          rx="6"
          fill="none"
          stroke="#3B82F6"
          strokeWidth="1"
          strokeDasharray="4 3"
          strokeOpacity="0.6"
        />
        <text
          x={856}
          y={zoneY + 25}
          textAnchor="middle"
          fontSize="8"
          fill="#3B82F6"
          fontFamily="monospace"
          letterSpacing="1"
        >
          BLUE BASE
        </text>
        <text
          x={856}
          y={zoneY + zoneHeight - 18}
          textAnchor="middle"
          fontSize="10"
          fill="#3B82F6"
          fontFamily="monospace"
          fontWeight="700"
        >
          {blueScore} pts
        </text>

        {edges.map((edge) => (
          <AnimatedEdge
            key={edge.id}
            from={edge.from}
            to={edge.to}
            type={edge.type}
            label={edge.label}
            nodes={nodes}
            tick={tick}
          />
        ))}

        {nodes.map((node) => (
          <NetworkNode
            key={node.id}
            node={node}
            selected={selectedNodeId === node.id}
            onClick={onSelectNode}
            pulse={tick}
          />
        ))}
      </svg>
    </div>
  );
}

export default SvgGraph;
