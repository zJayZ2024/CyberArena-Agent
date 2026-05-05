import { T } from "./constants";

function Badge({ text, color, bg }) {
  return (
    <span
      style={{
        display: "inline-block",
        fontFamily: T.fontMono,
        fontSize: 8,
        padding: "2px 6px",
        borderRadius: 3,
        background: bg || T.bg,
        color,
        border: `0.5px solid ${color}66`,
        margin: "2px 3px 2px 0",
      }}
    >
      {text}
    </span>
  );
}

function severityColor(sev) {
  if (sev === "Critical") return T.red;
  if (sev === "High") return T.amber;
  return T.grayText;
}

function RedIntelPanel({ round }) {
  const visible = round?.red_visible_nodes || [];
  const recon = round?.red_recon_nodes || [];
  const services = round?.red_known_services || {};
  const vulns = round?.red_known_vulnerabilities || {};

  const hasAny = visible.length > 0 || recon.length > 0 || Object.keys(services).length > 0 || Object.keys(vulns).length > 0;

  return (
    <div
      style={{
        background: T.bgPanel,
        border: `1px solid ${T.border}`,
        borderRadius: 6,
        padding: "12px 14px",
        marginTop: 12,
      }}
    >
      <div style={{ fontFamily: T.fontMono, fontSize: 10, letterSpacing: 1.2, color: T.grayText, textTransform: "uppercase", marginBottom: 10 }}>
        Red Intel
      </div>

      {!hasAny && (
        <div style={{ color: T.grayDim, fontSize: 10, fontFamily: T.fontMono, padding: "4px 0" }}>No intelligence gathered yet.</div>
      )}

      {visible.length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ color: T.grayDim, fontSize: 8, letterSpacing: 0.5, marginBottom: 4 }}>VISIBLE NODES</div>
          <div>
            {visible.map((n) => (
              <Badge key={n} text={n.toUpperCase()} color={T.red} bg={T.redBg} />
            ))}
          </div>
        </div>
      )}

      {recon.length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ color: T.grayDim, fontSize: 8, letterSpacing: 0.5, marginBottom: 4 }}>RECON NODES</div>
          <div>
            {recon.map((n) => (
              <Badge key={n} text={n.toUpperCase()} color={T.amber} bg={T.amberBg} />
            ))}
          </div>
        </div>
      )}

      {Object.keys(services).length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ color: T.grayDim, fontSize: 8, letterSpacing: 0.5, marginBottom: 4 }}>KNOWN SERVICES</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {Object.entries(services).map(([node, ports]) => (
              <div key={node} style={{ fontFamily: T.fontMono, fontSize: 9, color: T.grayText }}>
                <span style={{ color: T.red }}>{node.toUpperCase()}</span>: {ports.join(", ")}
              </div>
            ))}
          </div>
        </div>
      )}

      {Object.keys(vulns).length > 0 && (
        <div>
          <div style={{ color: T.grayDim, fontSize: 8, letterSpacing: 0.5, marginBottom: 4 }}>KNOWN VULNERABILITIES</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {Object.entries(vulns).map(([node, nodeVulns]) =>
              Object.entries(nodeVulns).map(([vid, v]) => (
                <div key={`${node}-${vid}`} style={{ fontFamily: T.fontMono, fontSize: 9, color: T.grayText }}>
                  <span style={{ color: T.red }}>{node.toUpperCase()}</span>{" "}
                  <span style={{ color: severityColor(v.severity) }}>{v.severity}</span>{" "}
                  {v.vuln_id}
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default RedIntelPanel;
