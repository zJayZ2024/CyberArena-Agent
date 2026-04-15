import { useEffect, useState } from "react";

import HeaderHUD from "./HeaderHUD";
import SvgGraph from "./SvgGraph";
import LegendBar from "./LegendBar";
import NodeDetailPanel from "./NodeDetailPanel";
import INITIAL_STATE from "./constants";

function NetworkTopology() {
  const [state, setState] = useState(INITIAL_STATE);
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const id = setInterval(() => setTick((value) => value + 1), 50);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    window.loadFrame = (json) => setState(json);

    return () => {
      delete window.loadFrame;
    };
  }, []);

  const selectedNode = selectedNodeId
    ? state.nodes.find((node) => node.id === selectedNodeId) ?? null
    : null;

  const handleSelectNode = (node) => {
    setSelectedNodeId((currentId) => (currentId === node.id ? null : node.id));
  };

  return (
    <div
      style={{
        background: "#0a0f1e",
        borderRadius: "12px",
        padding: 0,
        fontFamily: "monospace",
        userSelect: "none",
        border: "1px solid #1e293b",
        overflow: "hidden",
      }}
    >
      <HeaderHUD
        redScore={state.redScore}
        blueScore={state.blueScore}
        round={state.round}
        totalRounds={state.totalRounds}
      />

      <SvgGraph
        nodes={state.nodes}
        edges={state.edges}
        redScore={state.redScore}
        blueScore={state.blueScore}
        selectedNodeId={selectedNodeId}
        tick={tick}
        onSelectNode={handleSelectNode}
      />

      <LegendBar />
      <NodeDetailPanel node={selectedNode} onClose={() => setSelectedNodeId(null)} />

      <div
        style={{
          padding: "6px 18px 10px",
          color: "#334155",
          fontSize: 9,
          letterSpacing: 0.5,
        }}
      >
        DEV: call <code style={{ color: "#475569" }}>window.loadFrame(json)</code> to load replay data.
      </div>
    </div>
  );
}

export default NetworkTopology;
