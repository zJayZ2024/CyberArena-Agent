import { ICONS, STATUS_STYLES, T } from "./constants";

function NetworkNode({ cfg, status, atkCnt = 0, defCnt = 0, isTarget, isDefended, hovered, onHover, onClick }) {
  const normalizedStatus = typeof status === "string" ? status.toLowerCase() : "normal";
  const st = STATUS_STYLES[normalizedStatus] || STATUS_STYLES.normal;
  const Icon = ICONS[cfg.id];
  const pulseAnim = normalizedStatus === "scanning" ? "cyberPulseAmber" : normalizedStatus === "compromised" ? "cyberPulseRed" : normalizedStatus === "defended" || normalizedStatus === "patched" ? "cyberPulseGreen" : "none";

  return (
    <g transform={`translate(${cfg.x},${cfg.y})`} onClick={onClick} onMouseEnter={() => onHover(cfg.id)} onMouseLeave={() => onHover(null)} style={{ cursor: "pointer" }}>
      {normalizedStatus !== "normal" && normalizedStatus !== "isolated" && <circle r={32} cx={0} cy={0} fill="none" stroke={st.border} strokeWidth="0.7" strokeDasharray="3 3" opacity="0.45" style={{ animation: "cyberSpin 8s linear infinite", transformOrigin: "0 0" }} />}
      <circle r={24} cx={0} cy={0} fill={st.bg} stroke={st.border} strokeWidth={isTarget ? 2.5 : 1.8} style={{ filter: st.glow !== "none" ? `drop-shadow(${st.glow})` : "none", animation: pulseAnim !== "none" ? `${pulseAnim} 1.8s ease-in-out infinite` : "none" }} />
      {hovered && <circle r={24} cx={0} cy={0} fill="white" opacity="0.04" />}
      <foreignObject x={-9} y={-19} width={18} height={18} style={{ pointerEvents: "none", overflow: "visible" }}>
        <div xmlns="http://www.w3.org/1999/xhtml" style={{ display: "flex", alignItems: "center", justifyContent: "center", width: "100%", height: "100%" }}>
          <Icon size={13} color={st.border} />
        </div>
      </foreignObject>
      <text y={6} textAnchor="middle" fontFamily={T.fontMono} fontSize={9} fontWeight="600" fill={st.border}>{cfg.label}</text>
      <text y={16} textAnchor="middle" fontFamily={T.fontMono} fontSize={7} fill={T.grayDim}>{cfg.sublabel}</text>
      <circle cx={18} cy={18} r={5} fill={T.bg} />
      <circle cx={18} cy={18} r={4} fill={st.dot} />
      {atkCnt > 0 && <g transform="translate(-21,-21)"><circle r={7} fill={T.redBg} stroke={T.red} strokeWidth="0.8" /><text textAnchor="middle" y={3} fontFamily={T.fontMono} fontSize={7} fill={T.red} fontWeight="700">{atkCnt}</text></g>}
      {defCnt > 0 && <g transform="translate(21,-21)"><circle r={7} fill={T.blueBg} stroke={T.blue} strokeWidth="0.8" /><text textAnchor="middle" y={3} fontFamily={T.fontMono} fontSize={7} fill={T.blue} fontWeight="700">{defCnt}</text></g>}
      {isTarget && <g transform="translate(0,-38)"><rect x={-20} y={-8} width={40} height={14} rx={3} fill={T.redBg} stroke={T.red} strokeWidth="0.8" /><text textAnchor="middle" y={2} fontFamily={T.fontMono} fontSize={7} fill={T.red}>TARGET</text></g>}
      {isDefended && !isTarget && <g transform="translate(0,-38)"><rect x={-24} y={-8} width={48} height={14} rx={3} fill={T.greenBg} stroke={T.green} strokeWidth="0.8" /><text textAnchor="middle" y={2} fontFamily={T.fontMono} fontSize={7} fill={T.green}>HARDENED</text></g>}
    </g>
  );
}

export default NetworkNode;
