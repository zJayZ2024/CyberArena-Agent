import { useEffect, useMemo, useState } from "react";

import type { ReplayCatalogItem } from "./ReplayPicker";

type ReportPanelProps = {
  rounds: any[];
  selectedReplay?: ReplayCatalogItem | null;
};

function FindingList({ items }: { items: any[] }) {
  return (
    <div className="grid gap-2 xl:grid-cols-2">
      {items.map((item, index) => (
        <article key={`${item?.title}-${index}`} className="rounded-xl border border-white/[0.12] bg-[#162340] p-3">
          <div className="flex items-start justify-between gap-3">
            <h4 className="text-sm font-medium text-[#f0f4ff]">{item?.title || "关键发现"}</h4>
            <span className="rounded-md border border-amber-400/30 bg-amber-500/10 px-2 py-1 font-mono text-[9px] uppercase text-amber-200">
              {item?.severity || "medium"}
            </span>
          </div>
          <p className="mt-2 font-mono text-[10px] leading-5 text-slate-400">证据：{item?.evidence || "未提供"}</p>
          <p className="mt-2 text-xs leading-6 text-slate-300">{item?.analysis}</p>
        </article>
      ))}
    </div>
  );
}

function RecommendationList({ items, tone }: { items: any[]; tone: "red" | "blue" }) {
  const style = tone === "red"
    ? "border-red-400/25 bg-red-500/[0.07] text-red-200"
    : "border-blue-400/25 bg-blue-500/[0.07] text-blue-200";
  return (
    <div className="space-y-2">
      {items.map((item, index) => (
        <div key={`${item?.recommendation}-${index}`} className={`rounded-xl border p-3 ${style}`}>
          <p className="font-mono text-[10px] uppercase tracking-[0.14em]">{item?.priority || "P1"}</p>
          <p className="mt-1 text-sm font-medium text-[#f0f4ff]">{item?.recommendation}</p>
          <p className="mt-1 text-xs leading-5 text-slate-400">{item?.rationale}</p>
        </div>
      ))}
    </div>
  );
}

function statusLabel(status = "") {
  if (status === "running") return "生成中";
  if (status === "completed") return "已完成";
  if (status === "failed") return "失败";
  return status || "未知";
}

function ReportPanel({ rounds, selectedReplay }: ReportPanelProps) {
  const [reports, setReports] = useState<any[]>([]);
  const [selectedReportId, setSelectedReportId] = useState("");
  const [report, setReport] = useState<any>(null);
  const [generating, setGenerating] = useState(false);
  const [errorText, setErrorText] = useState("");

  const selectedJob = useMemo(
    () => reports.find((item) => item.id === selectedReportId),
    [reports, selectedReportId],
  );

  const refreshReports = async () => {
    const response = await fetch("/api/reports");
    if (!response.ok) return;
    const payload = await response.json();
    const nextReports = Array.isArray(payload?.reports) ? payload.reports : [];
    setReports(nextReports);
    if (!selectedReportId && nextReports.length) {
      setSelectedReportId(nextReports[0].id);
    }
  };

  useEffect(() => {
    refreshReports().catch(() => undefined);
    const timer = window.setInterval(() => {
      refreshReports().catch(() => undefined);
    }, 3500);
    return () => window.clearInterval(timer);
  }, []);

  const loadReport = async (reportId: string) => {
    setSelectedReportId(reportId);
    setErrorText("");
    const response = await fetch(`/api/reports/${reportId}`);
    const payload = await response.json();
    if (!response.ok) {
      setErrorText(payload?.detail || "报告读取失败");
      return;
    }
    if (payload.status !== "completed") {
      setReport(null);
      return;
    }
    setReport(payload.report);
  };

  const generate = async () => {
    if (generating) return;
    setGenerating(true);
    setErrorText("");
    try {
      const response = await fetch("/api/reports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          replay_name: selectedReplay?.name || "CyberArena 仿真回放",
          replay: {
            scenario: rounds[0]?.scenario || selectedReplay?.id || "cyberarena",
            total_rounds: Math.max(...rounds.map((round) => Number(round?.turn ?? round?.round ?? 0)), 0),
            frames: rounds,
          },
        }),
      });
      const job = await response.json();
      if (!response.ok) throw new Error(job?.detail || `报告任务启动失败：${response.status}`);
      setSelectedReportId(job.id);
      setReport(null);
      await refreshReports();
    } catch (error) {
      setErrorText(error instanceof Error ? error.message : "报告生成任务启动失败");
    } finally {
      setGenerating(false);
    }
  };

  useEffect(() => {
    if (selectedJob?.status === "completed" && selectedJob.id && !report) {
      loadReport(selectedJob.id).catch(() => undefined);
    }
  }, [selectedJob?.status, selectedJob?.id]);

  const analysis = report?.analysis ?? {};

  return (
    <section className="mt-5 rounded-2xl border border-violet-400/25 bg-[#111a2e] p-4 shadow-[0_18px_44px_rgba(0,0,0,0.22)]">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-violet-300">LLM Technical Report</p>
          <h2 className="mt-1 text-lg font-medium text-[#f0f4ff]">技术分析报告</h2>
          <p className="mt-1 text-xs leading-5 text-slate-400">报告生成是后台任务。提交后可以离开页面，稍后在下方报告历史中查看。</p>
        </div>
        <button type="button" disabled={generating} onClick={generate} className="rounded-lg border border-violet-300/45 bg-gradient-to-r from-[#7c8fff] to-[#a78bfa] px-4 py-2 font-mono text-[10px] text-white transition hover:brightness-110 disabled:cursor-wait disabled:opacity-60">
          {generating ? "正在提交..." : "生成技术报告"}
        </button>
      </div>

      {errorText ? <p className="mt-4 rounded-xl border border-red-400/25 bg-red-500/[0.08] p-3 text-xs text-red-200">{errorText}</p> : null}

      <div className="mt-4 grid gap-4 xl:grid-cols-[320px_minmax(0,1fr)]">
        <aside className="rounded-xl border border-white/[0.12] bg-[#162340] p-3">
          <div className="flex items-center justify-between gap-2">
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-slate-400">报告历史</p>
            <button type="button" onClick={() => refreshReports().catch(() => undefined)} className="rounded-md border border-white/[0.12] px-2 py-1 font-mono text-[9px] text-slate-300 hover:border-violet-400/40">刷新</button>
          </div>
          <div className="mt-3 max-h-80 space-y-2 overflow-y-auto pr-1">
            {reports.length ? reports.map((item) => {
              const active = item.id === selectedReportId;
              const running = item.status === "running";
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => loadReport(item.id)}
                  className={`w-full rounded-lg border p-3 text-left transition ${active ? "border-violet-400/50 bg-violet-500/10" : "border-white/[0.1] bg-[#111a2e] hover:border-violet-400/30"}`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <p className="line-clamp-2 text-xs font-medium text-slate-100">{item.replay_name || item.id}</p>
                    <span className={`shrink-0 rounded-md border px-2 py-1 font-mono text-[9px] ${running ? "border-amber-400/40 text-amber-200" : item.status === "completed" ? "border-emerald-400/40 text-emerald-200" : "border-red-400/40 text-red-200"}`}>
                      {statusLabel(item.status)}
                    </span>
                  </div>
                  <p className="mt-2 font-mono text-[9px] text-slate-500">{item.started_at}</p>
                </button>
              );
            }) : <p className="rounded-lg border border-dashed border-white/[0.12] p-4 text-center text-xs text-slate-500">暂无报告任务</p>}
          </div>
        </aside>

        <div className="min-w-0">
          {selectedJob?.status === "running" ? (
            <div className="rounded-xl border border-violet-400/20 bg-violet-500/[0.07] p-4">
              <div className="h-1.5 overflow-hidden rounded-full bg-[#0c1220]"><div className="h-full w-2/3 animate-pulse rounded-full bg-gradient-to-r from-[#5b9fff] to-[#a78bfa]" /></div>
              <p className="mt-3 text-xs text-violet-100">报告正在后台生成。你可以继续查看回放，回来后在报告历史中打开。</p>
            </div>
          ) : null}

          {selectedJob?.status === "failed" ? (
            <p className="rounded-xl border border-red-400/25 bg-red-500/[0.08] p-4 text-xs text-red-200">{selectedJob.error || "报告生成失败"}</p>
          ) : null}

          {report ? (
            <div className="space-y-5">
              <div className="flex flex-wrap justify-end gap-2">
                <a href={`/api/reports/${selectedReportId}/download?format=markdown`} className="rounded-lg border border-violet-400/35 bg-violet-500/10 px-3 py-2 font-mono text-[10px] text-violet-100 transition hover:bg-violet-500/20">导出 Markdown</a>
                <a href={`/api/reports/${selectedReportId}/download?format=json`} className="rounded-lg border border-white/[0.14] bg-[#162340] px-3 py-2 font-mono text-[10px] text-slate-200 transition hover:border-violet-400/40">导出 JSON</a>
              </div>
              <article className="rounded-xl border border-white/[0.12] bg-[#162340] p-4">
                <p className="font-mono text-[10px] uppercase tracking-[0.15em] text-violet-300">执行摘要</p>
                <p className="mt-3 text-sm leading-7 text-slate-200">{analysis.executive_summary}</p>
                <p className="mt-3 text-xs leading-6 text-slate-400">{analysis.technical_assessment}</p>
              </article>
              <div>
                <p className="mb-3 font-mono text-[10px] uppercase tracking-[0.16em] text-slate-400">关键发现</p>
                <FindingList items={analysis.key_findings || []} />
              </div>
              <div className="grid gap-4 xl:grid-cols-2">
                <article>
                  <p className="mb-3 font-mono text-[10px] uppercase tracking-[0.16em] text-red-300">红方改进建议</p>
                  <RecommendationList items={analysis.red_recommendations || []} tone="red" />
                </article>
                <article>
                  <p className="mb-3 font-mono text-[10px] uppercase tracking-[0.16em] text-blue-300">蓝方改进建议</p>
                  <RecommendationList items={analysis.blue_recommendations || []} tone="blue" />
                </article>
              </div>
            </div>
          ) : !selectedJob ? (
            <div className="rounded-xl border border-dashed border-white/[0.12] bg-[#162340]/60 p-8 text-center text-xs text-slate-500">生成报告后会出现在这里。</div>
          ) : null}
        </div>
      </div>
    </section>
  );
}

export default ReportPanel;
