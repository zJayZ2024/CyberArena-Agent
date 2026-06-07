import { useEffect, useMemo, useRef } from "react";

import { translateAction, translateRole } from "../utils/localization";

type TerminalLogsProps = {
  round?: any;
};

type Role = "RED" | "BLUE" | "SYS" | "ALERT";

type LogLine = {
  id: string;
  role: Role;
  message: string;
  detail?: string;
};

const ROLE_TEXT_CLASS: Record<Role, string> = {
  RED: "text-red-300",
  BLUE: "text-blue-300",
  SYS: "text-amber-300",
  ALERT: "text-yellow-300",
};

const MOCK_LOGS: LogLine[] = [
  {
    id: "mock-1",
    role: "RED",
    message: "服务利用 -> web",
    detail: "在 DMZ 节点建立初始访问。",
  },
  {
    id: "mock-2",
    role: "BLUE",
    message: "漏洞修补 -> storage",
    detail: "高危 SMB 漏洞已移除。",
  },
  {
    id: "mock-3",
    role: "ALERT",
    message: "db 出现可疑出站流量",
    detail: "检测到潜在外传链路。",
  },
  {
    id: "mock-4",
    role: "SYS",
    message: "回合已按裁判规则完成结算。",
  },
];

function trimText(text: string, maxLength = 180) {
  if (!text) {
    return "";
  }
  const cleaned = String(text).replace(/\s+/g, " ").trim();
  return cleaned.length > maxLength ? `${cleaned.slice(0, maxLength)}...` : cleaned;
}

function buildLogLines(round: any): LogLine[] {
  const logs = Array.isArray(round?.action_logs) ? round.action_logs : [];
  const securityAlerts = Array.isArray(round?.security_alerts) ? round.security_alerts : [];
  const judgeLogs = Array.isArray(round?.judge_result?.logs) ? round.judge_result.logs : [];

  const actionLines = logs.map((item: any, index: number) => {
    const roleKey = String(item?.agent_type || item?.metadata?.agent_type || "SYS").toLowerCase();
    const role: Role = roleKey === "red" ? "RED" : roleKey === "blue" ? "BLUE" : "SYS";
    const rawAction = item?.action_type || "Action";
    const action = translateAction(rawAction, rawAction);
    const target = item?.metadata?.target ? ` -> ${item.metadata.target}` : "";
    const detail = trimText(item?.referee_result || item?.payload || item?.thought || "");
    return {
      id: `action-${index}-${role}-${rawAction}`,
      role,
      message: `${action}${target}`,
      detail,
    };
  });

  const alertLines = securityAlerts.map((alert: any, index: number) => ({
    id: `alert-${index}-${alert?.target || "global"}`,
    role: "ALERT" as Role,
    message: trimText(alert?.message || "安全告警"),
    detail: alert?.target ? `目标=${alert.target}` : undefined,
  }));

  const systemLines = judgeLogs.map((entry: string, index: number) => ({
    id: `sys-${index}`,
    role: "SYS" as Role,
    message: trimText(entry),
  }));

  return [...actionLines, ...alertLines, ...systemLines];
}

function TerminalLogs({ round }: TerminalLogsProps) {
  const scrollerRef = useRef<HTMLDivElement | null>(null);
  const roundLabel = round?.round ?? round?.turn ?? 0;
  const lines = useMemo(() => {
    const next = round ? buildLogLines(round) : [];
    return next.length ? next : MOCK_LOGS;
  }, [round]);

  useEffect(() => {
    if (!scrollerRef.current) {
      return;
    }
    scrollerRef.current.scrollTop = scrollerRef.current.scrollHeight;
  }, [lines, roundLabel]);

  return (
    <div className="flex h-full min-h-0 flex-col rounded-2xl border border-white/[0.14] bg-[#111a2e]">
      <div className="flex shrink-0 items-center justify-between border-b border-white/[0.14] px-4 py-2">
        <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-slate-400">实时安全终端</p>
        <span className="font-mono text-[11px] text-slate-400">回合 {roundLabel}</span>
      </div>

      <div ref={scrollerRef} className="cyber-scrollbar min-h-0 flex-1 overflow-y-auto px-4 py-3 font-mono text-xs leading-6">
        {lines.map((line) => (
          <div key={line.id} className="whitespace-pre-wrap break-words">
            <span className={ROLE_TEXT_CLASS[line.role]}>[{translateRole(line.role)}]</span>
            <span className="ml-2 text-slate-300">{line.message}</span>
            {line.detail ? <span className="ml-2 text-slate-400">| {line.detail}</span> : null}
          </div>
        ))}
      </div>
    </div>
  );
}

export default TerminalLogs;
