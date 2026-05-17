import { useEffect, useRef, useState } from "react";

import AgentThoughtsPanel from "./AgentThoughtsPanel";
import EventLog from "./EventLog";
import HeaderHUD from "./HeaderHUD";
import LegendBar from "./LegendBar";
import RedIntelPanel from "./RedIntelPanel";
import RoundMetricsPanel from "./RoundMetricsPanel";
import ScoreCurve from "./ScoreCurve";
import SvgGraph from "./SvgGraph";
import { DEFAULT_ROUNDS, normalizeRoundsPayload } from "./data";
import { PAGE_STYLES, T } from "./constants";

function NetworkTopology({ initialRounds = DEFAULT_ROUNDS }) {
  const [rounds, setRounds] = useState(() => normalizeRoundsPayload(initialRounds));
  const [idx, setIdx] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [toast, setToast] = useState({ visible: false, text: "", color: T.red });
  const intervalRef = useRef(null);

  const round = rounds[idx] ?? rounds[0];
  const ws = round?.world_state ?? rounds[0]?.world_state ?? DEFAULT_ROUNDS[0].world_state;

  useEffect(() => {
    setRounds(normalizeRoundsPayload(initialRounds));
    setIdx(0);
    setPlaying(false);
  }, [initialRounds]);

  useEffect(() => {
    const loadReplay = (payload) => {
      const nextRounds = normalizeRoundsPayload(payload);
      setRounds(nextRounds);
      setIdx(0);
      setPlaying(false);
      setHoveredNode(null);
    };

    window.__topologyCallbacks = window.__topologyCallbacks || {};
    window.__topologyCallbacks.loadFrame = loadReplay;

    if (window.__pendingTopologyPayload) {
      loadReplay(window.__pendingTopologyPayload);
      window.__pendingTopologyPayload = null;
    }

    return () => {
      if (window.__topologyCallbacks?.loadFrame === loadReplay) {
        delete window.__topologyCallbacks.loadFrame;
      }
    };
  }, []);

  useEffect(() => {
    if (!playing) {
      return undefined;
    }

    intervalRef.current = setInterval(() => {
      setIdx((current) => {
        if (current >= rounds.length - 1) {
          setPlaying(false);
          return current;
        }
        return current + 1;
      });
    }, 2200 / speed);

    return () => clearInterval(intervalRef.current);
  }, [playing, rounds.length, speed]);

  useEffect(() => {
    const ra = round?.red_action;
    const jr = round?.judge_result;
    if (!ra) {
      return undefined;
    }

    setToast({
      visible: true,
      text: `R${round.round}: ${ra.technique_id} ${ra.technique} -> ${ra.target_node} ${jr?.success ? "成功" : "已阻断"}`,
      color: jr?.success ? T.red : T.grayDim,
    });

    const timeoutId = setTimeout(() => setToast((current) => ({ ...current, visible: false })), 3000);
    return () => clearTimeout(timeoutId);
  }, [round]);

  return (
    <div className="topology-page">
      <style>{PAGE_STYLES}</style>
      <HeaderHUD />

      <div style={{ display: "grid", gridTemplateColumns: "1fr 520px", gap: 32, alignItems: "start" }}>
        <div>
          <SvgGraph
            round={round}
            rounds={rounds}
            idx={idx}
            hoveredNode={hoveredNode}
            onHoverNode={setHoveredNode}
            toast={toast}
          />

          <div className="controls">
            <button type="button" className={`ctrl-btn${playing ? " active" : ""}`} onClick={() => setPlaying((current) => !current)}>{playing ? "暂停" : "播放"}</button>
            <button type="button" className="ctrl-btn" onClick={() => { setPlaying(false); setIdx(0); }}>重置</button>
            <button type="button" className="ctrl-btn" onClick={() => setIdx((current) => Math.max(0, current - 1))} disabled={idx === 0}>上一帧</button>
            <button type="button" className="ctrl-btn" onClick={() => setIdx((current) => Math.min(rounds.length - 1, current + 1))} disabled={idx === rounds.length - 1}>下一帧</button>
            {[0.5, 1, 2].map((value) => <button type="button" key={value} className={`ctrl-btn${speed === value ? " active" : ""}`} onClick={() => setSpeed(value)}>{value}x</button>)}
          </div>

          <div className="info-row">
            {rounds.map((item, i) => <div key={`${item.round}-${i}`} className="info-chip" style={{ cursor: "pointer", borderColor: i === idx ? T.blue : undefined, color: i === idx ? T.blue : undefined }} onClick={() => { setPlaying(false); setIdx(i); }}>R{item.round} {item.judge_result.success ? "成功" : "未成功"} {item.red_action.technique_id}</div>)}
          </div>

          <div style={{ marginTop: 16 }}>
            <ScoreCurve rounds={rounds} idx={idx} />
          </div>

          <div style={{ marginTop: 16 }}>
            <LegendBar phase={ws.red_phase} />
          </div>

          <div style={{ paddingTop: 10, color: "#4b5563", fontFamily: T.fontMono, fontSize: 10 }}>
            开发提示：调用 <code style={{ color: "#6b7280" }}>window.loadFrame(json)</code> 可用后端回放数据替换预览帧。
          </div>
        </div>

        <div>
          <AgentThoughtsPanel round={round} />
          <RoundMetricsPanel round={round} />
          <RedIntelPanel round={round} />
          <EventLog rounds={rounds} idx={idx} />
        </div>
      </div>
    </div>
  );
}

export default NetworkTopology;
export { normalizeRoundsPayload };
