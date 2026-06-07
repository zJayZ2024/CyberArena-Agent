import { useEffect, useMemo, useState } from "react";

export type ReplayCatalogItem = {
  id: string;
  name: string;
  summary: string;
  path: string;
  rounds?: number;
  tags?: string[];
};

type ReplayPickerProps = {
  selectedReplayId?: string | null;
  compact?: boolean;
  onLoadReplay?: (replay: ReplayCatalogItem, options?: { autoplay?: boolean }) => Promise<void> | void;
};

const BUILTIN_REPLAY: ReplayCatalogItem = {
  id: "builtin_demo",
  name: "内置 5 回合演示",
  summary: "本地示例回放，用于快速查看拓扑动态、得分变化和攻防路径。",
  path: "__builtin_default_rounds__",
  rounds: 5,
  tags: ["内置", "演示"],
};

const FALLBACK_REPLAYS: ReplayCatalogItem[] = [
  BUILTIN_REPLAY,
  {
    id: "simulation_20_rounds_eval",
    name: "20 回合攻防评估回放",
    summary: "已完成模拟的红蓝双方 20 回合攻防过程。",
    path: "/simulation_20_rounds_eval.json",
    rounds: 20,
    tags: ["已模拟", "20 回合"],
  },
];

const REPLAY_NAME_FIXES: Record<string, Partial<ReplayCatalogItem>> = {
  simulation_20_rounds_eval: {
    name: "20 回合攻防评估回放",
    summary: "已完成模拟的红蓝双方 20 回合攻防过程，包含动作日志、裁判结果、告警和拓扑变化。",
    tags: ["已模拟", "攻防评估", "20 回合"],
  },
};

function isReplayCatalogItem(value: any): value is ReplayCatalogItem {
  return !!(
    value
    && typeof value.id === "string"
    && typeof value.name === "string"
    && typeof value.path === "string"
  );
}

function normalizeReplayCatalog(payload: any): ReplayCatalogItem[] {
  const remoteRows = Array.isArray(payload?.replays) ? payload.replays.filter(isReplayCatalogItem) : [];
  const rows = [BUILTIN_REPLAY, ...remoteRows].map((item) => ({
    ...item,
    ...(REPLAY_NAME_FIXES[item.id] ?? {}),
  }));
  const deduped = new Map<string, ReplayCatalogItem>();
  rows.forEach((item) => deduped.set(item.id, item));
  return deduped.size ? Array.from(deduped.values()) : FALLBACK_REPLAYS;
}

function ReplayPicker({ selectedReplayId, compact = false, onLoadReplay }: ReplayPickerProps) {
  const [catalog, setCatalog] = useState<ReplayCatalogItem[]>(FALLBACK_REPLAYS);
  const [localSelectedId, setLocalSelectedId] = useState(selectedReplayId ?? FALLBACK_REPLAYS[1]?.id ?? FALLBACK_REPLAYS[0].id);
  const [loading, setLoading] = useState(false);
  const [errorText, setErrorText] = useState("");

  useEffect(() => {
    let cancelled = false;

    fetch("/replay_catalog.json")
      .then((response) => {
        if (!response.ok) {
          throw new Error(`回放目录请求失败：${response.status}`);
        }
        return response.json();
      })
      .then((payload) => {
        if (cancelled) {
          return;
        }
        const nextCatalog = normalizeReplayCatalog(payload);
        setCatalog(nextCatalog);
        setLocalSelectedId((current) => {
          if (selectedReplayId && nextCatalog.some((item) => item.id === selectedReplayId)) {
            return selectedReplayId;
          }
          if (nextCatalog.some((item) => item.id === current)) {
            return current;
          }
          return nextCatalog[0]?.id ?? BUILTIN_REPLAY.id;
        });
      })
      .catch((error) => {
        if (cancelled) {
          return;
        }
        console.error("回放目录加载失败，使用内置回放目录。", error);
        setCatalog(FALLBACK_REPLAYS);
      });

    return () => {
      cancelled = true;
    };
  }, [selectedReplayId]);

  useEffect(() => {
    if (selectedReplayId) {
      setLocalSelectedId(selectedReplayId);
    }
  }, [selectedReplayId]);

  const activeReplay = useMemo(() => {
    return catalog.find((item) => item.id === localSelectedId) ?? catalog[0] ?? BUILTIN_REPLAY;
  }, [catalog, localSelectedId]);

  const loadReplay = async (autoplay = false) => {
    if (!onLoadReplay || !activeReplay) {
      return;
    }
    setLoading(true);
    setErrorText("");
    try {
      await onLoadReplay(activeReplay, { autoplay });
    } catch (error) {
      console.error("回放加载失败。", error);
      setErrorText("回放加载失败，请检查回放文件是否存在。");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={`rounded-xl border border-blue-400/20 bg-[#111a2e]/70 ${compact ? "px-3 py-2" : "px-4 py-3"}`}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-400">回放选择</p>
          <p className="mt-1 truncate text-sm font-light text-slate-200">{activeReplay.name}</p>
        </div>
        <span className="shrink-0 rounded-md border border-slate-600/60 px-2 py-1 font-mono text-[10px] text-slate-400">
          {activeReplay.rounds ?? "--"} 回合
        </span>
      </div>

      <select
        value={activeReplay.id}
        onChange={(event) => setLocalSelectedId(event.target.value)}
        className="mt-3 w-full rounded-lg border border-[#304060] bg-[#162340] px-3 py-2 text-xs text-slate-200 outline-none transition focus:border-[#a78bfa] focus:ring-1 focus:ring-[#a78bfa]/30"
      >
        {catalog.map((item) => (
          <option key={item.id} value={item.id}>
            {item.name}
          </option>
        ))}
      </select>

      {!compact ? (
        <p className="mt-2 text-xs leading-5 text-slate-400">{activeReplay.summary}</p>
      ) : null}

      <div className="mt-3 flex gap-2">
        <button
          type="button"
          onClick={() => loadReplay(false)}
          disabled={loading}
          className="flex-1 rounded-lg border border-blue-400/40 bg-blue-500/15 px-3 py-2 font-mono text-[11px] text-blue-100 transition hover:bg-blue-400/22 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loading ? "加载中" : "载入回放"}
        </button>
        <button
          type="button"
          onClick={() => loadReplay(true)}
          disabled={loading}
          className="flex-1 rounded-lg border border-blue-300/35 bg-blue-400/10 px-3 py-2 font-mono text-[11px] text-blue-100 transition hover:bg-blue-400/20 disabled:cursor-not-allowed disabled:opacity-50"
        >
          播放回放
        </button>
      </div>

      {errorText ? <p className="mt-2 text-xs text-amber-300">{errorText}</p> : null}
    </div>
  );
}

export default ReplayPicker;
