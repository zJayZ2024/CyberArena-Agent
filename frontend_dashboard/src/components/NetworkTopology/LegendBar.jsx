import React from "react";

import { T } from "./constants";

function LegendBar({ phase }) {
  const phases = ["Recon", "Weaponize", "Exploit", "LateralMove", "Exfiltrate"];
  const current = phases.indexOf(phase ?? "Recon");

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "14px 18px", borderTop: `1px solid ${T.border}`, background: T.bgPanel }}>
      {phases.map((item, index) => (
        <React.Fragment key={item}>
          <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
            <div style={{ height: 5, width: "100%", borderRadius: 3, background: index < current ? T.red : index === current ? T.amber : T.border, boxShadow: index === current ? `0 0 8px ${T.amber}` : "none", transition: "background .5s" }} />
            <span style={{ fontFamily: T.fontMono, fontSize: 10, color: index < current ? T.red : index === current ? T.amber : T.grayDim, fontWeight: index === current ? 700 : 400, letterSpacing: 0.5 }}>{item}</span>
          </div>
          {index < phases.length - 1 && <span style={{ color: T.border, fontSize: 12, marginBottom: 14, opacity: 0.6 }}>—</span>}
        </React.Fragment>
      ))}
    </div>
  );
}

export default LegendBar;
