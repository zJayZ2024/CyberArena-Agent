import NetworkTopology from "./components/NetworkTopology";

function App() {
  return (
    <div
      style={{
        minHeight: "100vh",
        margin: 0,
        background:
          "radial-gradient(circle at top, rgba(59,130,246,0.12), transparent 32%), linear-gradient(180deg, #050816 0%, #02040b 100%)",
        padding: "32px",
        boxSizing: "border-box",
      }}
    >
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        <div style={{ marginBottom: 18, fontFamily: "monospace" }}>
          <div style={{ color: "#e2e8f0", fontSize: 24, fontWeight: 700, marginBottom: 6 }}>
            CyberArena Network Topology
          </div>
          <div style={{ color: "#64748b", fontSize: 13 }}>
            Refactored into reusable components for state-driven replay and inspection.
          </div>
        </div>

        <NetworkTopology />
      </div>
    </div>
  );
}

export default App;
