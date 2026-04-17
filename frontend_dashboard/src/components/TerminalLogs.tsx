import { useEffect, useMemo, useRef } from "react";

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
  RED: "text-red-400",
  BLUE: "text-blue-400",
  SYS: "text-amber-300",
  ALERT: "text-amber-400",
};

const MOCK_LOGS: LogLine[] = [
  {
    id: "mock-1",
    role: "RED",
    message: "ExploitService -> web (CVE-2021-44228)",
    detail: "Initial foothold established on DMZ node.",
  },
  {
    id: "mock-2",
    role: "BLUE",
    message: "PatchNode -> storage (CVE-2017-0144)",
    detail: "Critical SMB vulnerability removed.",
  },
  {
    id: "mock-3",
    role: "ALERT",
    message: "Suspicious outbound traffic from db",
    detail: "Potential exfiltration chain detected.",
  },
  {
    id: "mock-4",
    role: "SYS",
    message: "Round resolved with deterministic scoring rules.",
  },
];

function trimText(text: string, maxLength = 180) {
  if (!text) {
    return "";
  }
  return text.length > maxLength ? `${text.slice(0, maxLength)}...` : text;
}

function buildLogLines(round: any): LogLine[] {
  const logs = Array.isArray(round?.action_logs) ? round.action_logs : [];
  const securityAlerts = Array.isArray(round?.security_alerts) ? round.security_alerts : [];
  const judgeLogs = Array.isArray(round?.judge_result?.logs) ? round.judge_result.logs : [];

  const actionLines = logs.map((item: any, index: number) => {
    const roleKey = String(item?.agent_type || item?.metadata?.agent_type || "SYS").toLowerCase();
    const role: Role = roleKey === "red" ? "RED" : roleKey === "blue" ? "BLUE" : "SYS";
    const action = item?.action_type || "Action";
    const target = item?.metadata?.target ? ` -> ${item.metadata.target}` : "";
    const detail = trimText(item?.referee_result || item?.payload || item?.thought || "");
    return {
      id: `action-${index}-${role}-${action}`,
      role,
      message: `${action}${target}`,
      detail,
    };
  });

  const alertLines = securityAlerts.map((alert: any, index: number) => ({
    id: `alert-${index}-${alert?.target || "global"}`,
    role: "ALERT" as Role,
    message: trimText(alert?.message || "Security alert"),
    detail: alert?.target ? `target=${alert.target}` : undefined,
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
  const roundLabel = round?.round ?? round?.turn ?? 1;
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
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex items-center justify-between border-b border-[#1f2937] px-3 py-2">
        <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-slate-400">Realtime Security Terminal</p>
        <span className="font-mono text-[11px] text-slate-500">Round {roundLabel}</span>
      </div>

      <div ref={scrollerRef} className="min-h-0 flex-1 overflow-y-auto px-3 py-2 font-mono text-xs leading-6">
        {lines.map((line) => (
          <div key={line.id} className="whitespace-pre-wrap break-words">
            <span className={ROLE_TEXT_CLASS[line.role]}>[{line.role}]</span>
            <span className="ml-2 text-slate-200">{line.message}</span>
            {line.detail ? <span className="ml-2 text-slate-500">| {line.detail}</span> : null}
          </div>
        ))}
      </div>
    </div>
  );
}

export default TerminalLogs;
