import { useEffect, useMemo, useState } from "react";

import ReasoningPanel from "./components/ReasoningPanel";
import TerminalLogs from "./components/TerminalLogs";
import TopBar from "./components/TopBar";
import TopologyVisualizer from "./components/TopologyVisualizer";
import { DEFAULT_ROUNDS, normalizeRoundsPayload } from "./components/NetworkTopology/data";

const FALLBACK_ROUNDS = normalizeRoundsPayload(DEFAULT_ROUNDS);

function App() {
  const [rounds, setRounds] = useState(() => FALLBACK_ROUNDS);
  const [roundIndex, setRoundIndex] = useState(0);
  const [playing, setPlaying] = useState(false);

  useEffect(() => {
    let cancelled = false;

    fetch("/simulation_20_rounds_eval.json")
      .then((response) => response.json())
      .then((payload) => {
        if (cancelled) {
          return;
        }
        const normalized = normalizeRoundsPayload(payload);
        if (normalized.length) {
          setRounds(normalized);
        }
      })
      .catch((error) => {
        // Keep local mock rounds when replay payload is unavailable.
        console.error("Failed to load replay data, fallback to mock rounds:", error);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    setRoundIndex((current) => Math.min(current, Math.max(rounds.length - 1, 0)));
  }, [rounds.length]);

  useEffect(() => {
    if (!playing || rounds.length <= 1) {
      return undefined;
    }

    const timer = window.setInterval(() => {
      setRoundIndex((current) => {
        if (current >= rounds.length - 1) {
          setPlaying(false);
          return current;
        }
        return current + 1;
      });
    }, 2200);

    return () => window.clearInterval(timer);
  }, [playing, rounds.length]);

  const frameCount = rounds.length || FALLBACK_ROUNDS.length;
  const safeIndex = Math.min(roundIndex, Math.max(frameCount - 1, 0));
  const currentRound = useMemo(
    () => rounds[safeIndex] ?? FALLBACK_ROUNDS[Math.min(safeIndex, FALLBACK_ROUNDS.length - 1)],
    [rounds, safeIndex],
  );
  const totalRounds = useMemo(() => {
    const fromCurrent = Number(currentRound?.total_rounds ?? currentRound?.totalRounds);
    if (Number.isFinite(fromCurrent) && fromCurrent > 0) {
      return fromCurrent;
    }

    const fromList = rounds
      .map((item) => Number(item?.total_rounds ?? item?.totalRounds))
      .find((value) => Number.isFinite(value) && value > 0);
    if (typeof fromList === "number") {
      return fromList;
    }

    const turns = rounds
      .map((item) => Number(item?.round ?? item?.turn))
      .filter((value) => Number.isFinite(value) && value >= 0);
    if (turns.length) {
      return Math.max(...turns);
    }

    return Math.max(frameCount, 1);
  }, [currentRound, frameCount, rounds]);
  const rawRoundValue = Number(currentRound?.round ?? currentRound?.turn ?? safeIndex + 1);
  const displayRound = Number.isFinite(rawRoundValue)
    ? Math.min(Math.max(rawRoundValue, 1), totalRounds)
    : Math.min(safeIndex + 1, totalRounds);

  const score = currentRound?.world_state?.score ?? {
    red: currentRound?.red_score ?? 0,
    blue: currentRound?.blue_score ?? 0,
  };

  const handleSeek = (nextIndex: number) => {
    setPlaying(false);
    const clamped = Math.min(Math.max(nextIndex, 0), Math.max(frameCount - 1, 0));
    setRoundIndex(clamped);
  };

  const handleNext = () => {
    setPlaying(false);
    setRoundIndex((current) => Math.min(current + 1, Math.max(frameCount - 1, 0)));
  };

  return (
    <div className="h-screen w-screen overflow-hidden bg-[#07090f] text-slate-100">
      <div className="flex h-full flex-col overflow-hidden">
        <TopBar
          roundIndex={safeIndex}
          displayRound={displayRound}
          totalRounds={totalRounds}
          frameCount={frameCount}
          redScore={score.red}
          blueScore={score.blue}
          playing={playing}
          onTogglePlay={() => setPlaying((current) => !current)}
          onNext={handleNext}
          onSeek={handleSeek}
        />

        <main className="flex min-h-0 flex-1 overflow-hidden px-3 pb-3 pt-2">
          <section className="min-w-0 flex-[3] overflow-hidden pr-3">
            <TopologyVisualizer round={currentRound} rounds={rounds} roundIndex={safeIndex} />
          </section>

          <aside className="flex min-w-[350px] max-w-[420px] flex-1 overflow-hidden rounded-xl border border-[#1f2937] bg-[#0d1117]/90">
            <ReasoningPanel round={currentRound} />
          </aside>
        </main>

        <section className="h-40 shrink-0 border-t border-[#1f2937] bg-[#0a0f17] md:h-44 xl:h-48">
          <TerminalLogs round={currentRound} />
        </section>
      </div>
    </div>
  );
}

export default App;
