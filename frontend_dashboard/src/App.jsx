import { useEffect, useState } from "react";

import TopologyGraph from "./components/TopologyGraph";

function App() {
  const [rounds, setRounds] = useState(null);

  useEffect(() => {
    fetch("/simulation_20_rounds_eval.json")
      .then((r) => r.json())
      .then((data) => setRounds(data))
      .catch((err) => {
        console.error("Failed to load replay:", err);
        setRounds(null);
      });
  }, []);

  return (
    <div style={{ minHeight: "100vh", margin: 0, background: "#07090f" }}>
      <TopologyGraph initialRounds={rounds ?? undefined} />
    </div>
  );
}

export default App;
