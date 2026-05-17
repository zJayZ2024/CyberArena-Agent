import { T } from "./constants";
import { isHighSeverity, isSevere, translateSeverity } from "../../utils/localization";

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
  if (isSevere(sev)) return T.red;
  if (isHighSeverity(sev)) return T.amber;
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
        红方情报
      </div>

      {!hasAny && (
        <div style={{ color: T.grayDim, fontSize: 10, fontFamily: T.fontMono, padding: "4px 0" }}>尚未收集到情报。</div>
      )}

      {visible.length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ color: T.grayDim, fontSize: 8, letterSpacing: 0.5, marginBottom: 4 }}>可见节点</div>
          <div>
            {visible.map((n) => (
              <Badge key={n} text={n.toUpperCase()} color={T.red} bg={T.redBg} />
            ))}
          </div>
        </div>
      )}

      {recon.length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ color: T.grayDim, fontSize: 8, letterSpacing: 0.5, marginBottom: 4 }}>已侦察节点</div>
          <div>
            {recon.map((n) => (
              <Badge key={n} text={n.toUpperCase()} color={T.amber} bg={T.amberBg} />
            ))}
          </div>
        </div>
      )}

      {Object.keys(services).length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ color: T.grayDim, fontSize: 8, letterSpacing: 0.5, marginBottom: 4 }}>已知服务</div>
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
          <div style={{ color: T.grayDim, fontSize: 8, letterSpacing: 0.5, marginBottom: 4 }}>已知漏洞</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {Object.entries(vulns).map(([node, nodeVulns]) =>
              Object.entries(nodeVulns).map(([vid, v]) => (
                <div key={`${node}-${vid}`} style={{ fontFamily: T.fontMono, fontSize: 9, color: T.grayText }}>
                  <span style={{ color: T.red }}>{node.toUpperCase()}</span>{" "}
                  <span style={{ color: severityColor(v.severity) }}>{translateSeverity(v.severity)}</span>{" "}
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
