import React from "react";
import ReactDOM from "react-dom/client";

import "./index.css";
import App from "./App.tsx";
import { normalizeRoundsPayload } from "./components/NetworkTopology/data";

window.__topologyCallbacks = {};

window.loadFrame = (payload) => {
  const cb = window.__topologyCallbacks?.loadFrame;
  if (cb) {
    cb(payload);
  } else {
    window.__pendingTopologyPayload = payload;
  }
};
window.loadReplay = window.loadFrame;
window.setTopologyRounds = window.loadFrame;

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
