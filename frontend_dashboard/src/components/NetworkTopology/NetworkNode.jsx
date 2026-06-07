import { STATUS_STYLES, T, resolveNodeIcon } from "./constants";

function CapabilityBadge({ x, y, label, kind, color = T.red, title }) {
  const icon = {
    eye: <><path d="M-5 0 Q0-5 5 0 Q0 5-5 0Z" fill="none" stroke={color} strokeWidth="1.2" /><circle r="1.7" fill={color} /></>,
    key: <><circle cx="-2.5" cy="-1.5" r="2.6" fill="none" stroke={color} strokeWidth="1.2" /><path d="M-.5.5 5 5M2 3l1.5-1.5M3.5 4.5 5 3" stroke={color} strokeWidth="1.2" /></>,
    session: <><path d="M-5-1h4v-3l5 4-5 4V1h-4M1-4h4v8H1" fill="none" stroke={color} strokeWidth="1.2" strokeLinejoin="round" /></>,
    anchor: <><path d="M0-5v9M-4 0h8M-5 2q5 6 10 0" fill="none" stroke={color} strokeWidth="1.2" /><circle cy="-5" r="1.3" fill="none" stroke={color} strokeWidth="1.1" /></>,
  }[kind];
  return (
    <g transform={`translate(${x},${y})`}>
      <circle r={9} fill={T.bgPanel} stroke={T.bgPanel} strokeWidth="3" opacity="0.96" />
      <circle r={8} fill={`${color}18`} stroke={color} strokeWidth="1.25" style={{ filter: `drop-shadow(0 0 3px ${color}88)` }} />
      {icon || <text textAnchor="middle" y={3} fontFamily={T.fontMono} fontSize={8} fill={color} fontWeight="700">{label}</text>}
      <title>{title}</title>
    </g>
  );
}

function NetworkNode({
  cfg,
  status,
  nodeState = {},
  atkCnt = 0,
  defCnt = 0,
  isTarget,
  isDefended,
  isChanged,
  hovered,
  onHover,
  onClick,
}) {
  const normalizedStatus = typeof status === "string" ? status.toLowerCase() : "normal";
  const st = STATUS_STYLES[normalizedStatus] || STATUS_STYLES.normal;
  const Icon = resolveNodeIcon(cfg.id, cfg.zone);
  const redState = nodeState?.red_state ?? {};
  const blueState = nodeState?.blue_state ?? {};
  const monitored = !!blueState.monitored;
  const isolated = normalizedStatus === "isolated" || !!blueState.isolated;
  const down = normalizedStatus === "down";
  const pulseAnim = normalizedStatus === "compromised"
    ? "cyberPulseRed"
    : normalizedStatus === "defended" || normalizedStatus === "patched"
      ? "cyberPulseGreen"
      : "none";

  const redBadges = [
    redState.recon_known && { kind: "eye", title: "红方已完成侦察" },
    redState.credential_known && { kind: "key", title: "红方已知凭据" },
    redState.session_active && { kind: "session", title: "红方活动 Session" },
    redState.foothold && { kind: "anchor", title: "红方 Foothold" },
    redState.persistence && { label: "P", title: "红方持久化残留", color: T.purple },
  ].filter(Boolean);
  const blueBadges = [
    blueState.restored && { label: "恢", title: "蓝方已恢复", color: T.green },
    blueState.isolated && { label: "锁", title: "蓝方已隔离", color: T.grayDim },
    blueState.hardened && { label: "盾", title: "蓝方已加固", color: T.blue },
  ].filter(Boolean);
  const privilege = redState.privilege && redState.privilege !== "none" ? String(redState.privilege).toUpperCase() : "";
  return (
    <g transform={`translate(${cfg.x},${cfg.y})`} onClick={onClick} onMouseEnter={() => onHover(cfg.id)} onMouseLeave={() => onHover(null)} style={{ cursor: "pointer" }}>
      {isChanged && (
        <g>
          <circle r={39} fill="none" stroke={T.amber} strokeWidth="1.4" strokeDasharray="5 3" opacity="0.8" style={{ animation: "stateDeltaPulse 1.25s ease-in-out infinite", transformOrigin: "0 0", filter: `drop-shadow(0 0 6px ${T.amber})` }} />
          <g transform="translate(28,-30)">
            <rect x={-14} y={-7} width={28} height={14} rx={4} fill={T.bgPanel} stroke={T.amber} strokeWidth="0.8" />
            <text textAnchor="middle" y={3} fontFamily={T.fontMono} fontSize={7} fill={T.amber} fontWeight="700">变化</text>
          </g>
        </g>
      )}
      {monitored && <circle r={35} fill="none" stroke={T.cyan} strokeWidth="1.1" strokeDasharray="2 3" opacity="0.8" style={{ animation: "cyberSpin 9s linear infinite", transformOrigin: "0 0", filter: `drop-shadow(0 0 5px ${T.cyan})` }} />}
      {isTarget && <circle r={31} fill="none" stroke={T.red} strokeWidth="1.4" opacity="0.9" style={{ animation: "cyberPulseRed 1.6s ease-in-out infinite" }} />}
      {isDefended && !isTarget && <circle r={31} fill="none" stroke={T.green} strokeWidth="1.1" strokeDasharray="4 3" opacity="0.8" />}
      <circle
        r={24}
        cx={0}
        cy={0}
        fill={down ? "#101622" : st.bg}
        stroke={st.border}
        strokeWidth={isTarget ? 2.4 : 1.8}
        strokeDasharray={isolated || down ? "4 3" : "none"}
        opacity={down ? 0.55 : 1}
        style={{ filter: st.glow !== "none" ? `drop-shadow(${st.glow})` : "none", animation: pulseAnim !== "none" ? `${pulseAnim} 1.8s ease-in-out infinite` : "none" }}
      />
      {isolated && <path d="M-18 18 18-18" stroke={T.grayDim} strokeWidth="1.2" opacity="0.7" />}
      {hovered && <circle r={24} cx={0} cy={0} fill="white" opacity="0.05" />}
      <foreignObject x={-9} y={-19} width={18} height={18} style={{ pointerEvents: "none", overflow: "visible" }}>
        <div xmlns="http://www.w3.org/1999/xhtml" style={{ display: "flex", alignItems: "center", justifyContent: "center", width: "100%", height: "100%" }}>
          <Icon size={13} color={st.border} />
        </div>
      </foreignObject>
      <text y={6} textAnchor="middle" fontFamily={T.fontMono} fontSize={9} fontWeight="600" fill={st.border}>{cfg.label}</text>
      <text y={16} textAnchor="middle" fontFamily={T.fontMono} fontSize={7} fill={T.grayDim}>{cfg.sublabel}</text>

      {redBadges.slice(0, 5).map((badge, index) => (
        <CapabilityBadge key={badge.title} x={-36 + index * 18} y={-34} label={badge.label} kind={badge.kind} title={badge.title} color={badge.color || T.red} />
      ))}
      {blueBadges.slice(0, 3).map((badge, index) => (
        <CapabilityBadge key={badge.title} x={34} y={-18 + index * 19} label={badge.label} title={badge.title} color={badge.color} />
      ))}
      {privilege && (
        <g transform="translate(0,32)">
          <rect x={-20} y={-6} width={40} height={12} rx={4} fill={T.redBg} stroke={T.red} strokeWidth="0.8" />
          <text textAnchor="middle" y={3} fontFamily={T.fontMono} fontSize={7.5} fill={T.red} fontWeight="700">{privilege}</text>
        </g>
      )}
      {atkCnt > 0 && <g transform="translate(-25,19)"><circle r={6} fill={T.redBg} stroke={T.red} strokeWidth="0.8" /><text textAnchor="middle" y={2.5} fontFamily={T.fontMono} fontSize={6.5} fill={T.red} fontWeight="700">{atkCnt}</text></g>}
      {defCnt > 0 && <g transform="translate(25,19)"><circle r={6} fill={T.blueBg} stroke={T.blue} strokeWidth="0.8" /><text textAnchor="middle" y={2.5} fontFamily={T.fontMono} fontSize={6.5} fill={T.blue} fontWeight="700">{defCnt}</text></g>}
    </g>
  );
}

export default NetworkNode;
