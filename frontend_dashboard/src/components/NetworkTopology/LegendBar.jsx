import React from "react";

import { T } from "./constants";

function LegendBar({ phase }) {
  const phases = ["Recon", "Weaponize", "Exploit", "LateralMove", "Exfiltrate"];
  const current = phases.indexOf(phase ?? "Recon");

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 5, padding: "6px 14px", borderTop: `1px solid ${T.border}`, background: T.bgPanel }}>
      {phases.map((item, index) => (
        <React.Fragment key={item}>
          <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 2 }}>
            <div style={{ height: 3, width: "100%", borderRadius: 2, background: index < current ? T.red : index === current ? T.amber : T.border, boxShadow: index === current ? `0 0 6px ${T.amber}` : "none", transition: "background .5s" }} />
            <span style={{ fontFamily: T.fontMono, fontSize: 8, color: index < current ? T.red : index === current ? T.amber : T.grayDim, fontWeight: index === current ? 700 : 400 }}>{item}</span>
          </div>
          {index < phases.length - 1 && <span style={{ color: T.border, fontSize: 10, marginBottom: 10 }}>-</span>}
        </React.Fragment>
      ))}
    </div>
  );
}

export default LegendBar;
