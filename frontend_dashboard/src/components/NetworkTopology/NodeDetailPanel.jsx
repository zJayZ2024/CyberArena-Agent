import { T } from "./constants";
import { translateAction } from "../../utils/localization";

function NodeDetailPanel({ round, onClose }) {
  if (!round) {
    return null;
  }

  const { red_action: ra, blue_action: ba, judge_result: jr } = round;

  return (
    <div style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 280, background: `${T.bgPanel}f8`, borderLeft: `1px solid ${T.border}`, padding: 16, overflowY: "auto", zIndex: 30, fontFamily: T.fontMono, fontSize: 11 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <span style={{ color: T.grayText, fontSize: 10, letterSpacing: 1 }}>智能体推理</span>
        <button type="button" onClick={onClose} style={{ background: "none", border: "none", color: T.grayDim, cursor: "pointer", fontSize: 14 }}>x</button>
      </div>
      {[
        { label: "红方动作", color: T.red, icon: "红方", text: ra?.reasoning, extra: `${ra?.technique_id} · ${translateAction(ra?.technique, ra?.technique)}` },
        { label: "裁判", color: T.amber, icon: "裁判", text: jr?.narrative, extra: `成功：${jr?.success ? "是" : "否"} · 伤害 ${jr?.damage ?? 0}` },
        { label: "蓝方动作", color: T.blue, icon: "防御", text: ba?.reasoning, extra: `类型：${translateAction(ba?.type, ba?.type)} · 成本 ${ba?.action_cost ?? 0} 分` },
      ].map(({ label, color, icon, text, extra }) => (
        <div key={label} style={{ marginBottom: 14, padding: 10, background: `${color}0d`, borderRadius: 6, border: `0.5px solid ${color}44` }}>
          <div style={{ color, fontSize: 9, letterSpacing: 1, marginBottom: 4 }}>{icon} {label}</div>
          <div style={{ color: T.grayDim, fontSize: 9, marginBottom: 6, borderBottom: `0.5px solid ${color}33`, paddingBottom: 4 }}>{extra}</div>
          <div style={{ color: T.grayText, fontSize: 10, lineHeight: 1.6 }}>{text ?? "-"}</div>
        </div>
      ))}
      {jr?.logs?.length > 0 && <div style={{ marginTop: 8 }}>
        <div style={{ color: T.grayDim, fontSize: 9, letterSpacing: 1, marginBottom: 6 }}>系统日志</div>
        {jr.logs.map((lg, index) => <div key={`${lg}-${index}`} style={{ fontFamily: T.fontMono, fontSize: 9, marginBottom: 3, color: lg.startsWith("[CRIT]") ? T.red : lg.startsWith("[OK]") ? T.green : lg.startsWith("[WARN]") ? T.amber : T.grayDim }}>{lg}</div>)}
      </div>}
    </div>
  );
}

export default NodeDetailPanel;
