from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI


REPORT_SYSTEM_PROMPT = """你是一名资深网络攻防演练复盘专家。
请根据给定的仿真事实生成中文技术分析报告。禁止捏造事实；所有结论必须能从输入证据中推导。
建议必须具体、可执行，并分别面向红方和蓝方。
只输出合法 JSON 对象，不要输出 Markdown 代码围栏。"""


def _agent_log(frame: dict[str, Any], agent_type: str) -> dict[str, Any]:
    return next((log for log in frame.get("action_logs", []) if log.get("agent_type") == agent_type), {})


def _node_state_summary(frame: dict[str, Any]) -> dict[str, list[str]]:
    result = {
        "compromised": [],
        "isolated": [],
        "sessions": [],
        "footholds": [],
        "persistence": [],
        "monitored": [],
    }
    for node_name, node in (frame.get("network_nodes") or {}).items():
        red_state = node.get("red_state") or {}
        blue_state = node.get("blue_state") or {}
        if node.get("status") == "Compromised":
            result["compromised"].append(node_name)
        if node.get("status") == "Isolated" or blue_state.get("isolated"):
            result["isolated"].append(node_name)
        if red_state.get("session_active"):
            result["sessions"].append(node_name)
        if red_state.get("foothold"):
            result["footholds"].append(node_name)
        if red_state.get("persistence"):
            result["persistence"].append(node_name)
        if blue_state.get("monitored"):
            result["monitored"].append(node_name)
    return result


def build_replay_evidence(replay: dict[str, Any]) -> dict[str, Any]:
    frames = replay.get("frames") or replay.get("rounds") or []
    if not frames:
        raise ValueError("回放中没有可分析帧")

    action_counts: dict[str, Counter[str]] = {"red": Counter(), "blue": Counter()}
    target_counts: dict[str, Counter[str]] = {"red": Counter(), "blue": Counter()}
    effect_counts: dict[str, Counter[str]] = {"red": Counter(), "blue": Counter()}
    key_turns: list[dict[str, Any]] = []
    attack_graph_steps: list[dict[str, Any]] = []
    score_progression: list[dict[str, Any]] = []
    reflection_samples: dict[str, list[dict[str, Any]]] = {"red": [], "blue": []}

    for frame in frames:
        turn = frame.get("turn", frame.get("round", 0))
        score_progression.append(
            {
                "turn": turn,
                "red": frame.get("red_score", frame.get("world_state", {}).get("score", {}).get("red", 0)),
                "blue": frame.get("blue_score", frame.get("world_state", {}).get("score", {}).get("blue", 0)),
                "health": frame.get("system_health", frame.get("world_state", {}).get("system_health")),
                "exposure": frame.get("exposure_level", frame.get("world_state", {}).get("exposure_level")),
            }
        )
        referee = _agent_log(frame, "Referee")
        referee_meta = referee.get("metadata") or {}
        flow = frame.get("referee_flow") or referee_meta.get("referee_flow") or {}
        interaction = flow.get("same_turn_conflict") or referee_meta.get("interaction") or {}
        state_changes = flow.get("state_changes") or []

        for side, agent_type in (("red", "Red"), ("blue", "Blue")):
            log = _agent_log(frame, agent_type)
            metadata = log.get("metadata") or {}
            action = log.get("action_type")
            target = metadata.get("target")
            effect = metadata.get("referee_effect") or metadata.get("execution_effect")
            if action:
                action_counts[side][action] += 1
            if target:
                target_counts[side][target] += 1
            if effect:
                effect_counts[side][effect] += 1

        attack_progress = flow.get("attack_graph_progress") or {}
        if attack_progress.get("source") or attack_progress.get("target"):
            attack_graph_steps.append(
                {
                    "turn": turn,
                    "phase": attack_progress.get("phase"),
                    "technique": attack_progress.get("technique"),
                    "source": attack_progress.get("source"),
                    "target": attack_progress.get("target"),
                    "result": attack_progress.get("result"),
                    "progressed": attack_progress.get("progressed"),
                    "allowed": attack_progress.get("allowed"),
                    "active_blockers": attack_progress.get("active_blockers"),
                }
            )

        if interaction.get("type") not in {None, "", "independent"} or state_changes:
            key_turns.append(
                {
                    "turn": turn,
                    "interaction": interaction.get("type"),
                    "interaction_result": interaction.get("result") or interaction.get("explanation"),
                    "state_changes": state_changes[:8],
                    "score_changes": flow.get("score_changes"),
                }
            )

        memory = referee_meta.get("agent_memory") or {}
        for side in ("red", "blue"):
            recent = (memory.get(side) or {}).get("recent_reflections") or []
            if recent:
                sample = recent[-1]
                if sample not in reflection_samples[side]:
                    reflection_samples[side].append(sample)

    first = frames[0]
    final = frames[-1]
    return {
        "scenario": replay.get("scenario", ""),
        "total_rounds": replay.get("total_rounds", max(len(frames) - 1, 0)),
        "stopped_early": replay.get("stopped_early", False),
        "initial": {
            "health": first.get("system_health"),
            "exposure": first.get("exposure_level"),
            "nodes": len(first.get("network_nodes") or {}),
            "state": _node_state_summary(first),
        },
        "final": {
            "health": final.get("system_health"),
            "exposure": final.get("exposure_level"),
            "red_score": final.get("red_score", 0),
            "blue_score": final.get("blue_score", 0),
            "winner_side": final.get("winner_side"),
            "winner_reason": final.get("winner_reason"),
            "state": _node_state_summary(final),
        },
        "actions": {
            side: {
                "action_counts": dict(action_counts[side]),
                "target_counts": dict(target_counts[side]),
                "effect_counts": dict(effect_counts[side]),
            }
            for side in ("red", "blue")
        },
        "score_progression": score_progression,
        "attack_graph_steps": attack_graph_steps,
        "key_turns": key_turns,
        "reflection_samples": {
            side: reflection_samples[side][-5:]
            for side in ("red", "blue")
        },
    }


def generate_report(replay: dict[str, Any], replay_name: str = "") -> dict[str, Any]:
    load_dotenv(override=False, encoding="utf-8")
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("缺少 OPENAI_API_KEY，无法生成 LLM 技术报告")

    evidence = build_replay_evidence(replay)
    client = OpenAI(api_key=api_key, base_url=os.getenv("OPENAI_BASE_URL"))
    model = os.getenv("REPORT_MODEL_NAME") or os.getenv("LLM_MODEL_NAME", "ecnu-max")
    prompt = {
        "task": "基于仿真证据生成技术复盘报告",
        "replay_name": replay_name or evidence.get("scenario"),
        "required_schema": {
            "executive_summary": "string",
            "technical_assessment": "string",
            "key_findings": [{"title": "string", "severity": "critical|high|medium|low", "evidence": "string", "analysis": "string"}],
            "attack_chain_analysis": [{"step": "string", "assessment": "string"}],
            "defense_analysis": [{"topic": "string", "assessment": "string"}],
            "scoring_assessment": "string",
            "red_recommendations": [{"priority": "P0|P1|P2", "recommendation": "string", "rationale": "string"}],
            "blue_recommendations": [{"priority": "P0|P1|P2", "recommendation": "string", "rationale": "string"}],
            "conclusion": "string",
        },
        "evidence": evidence,
    }
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": REPORT_SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
        ],
        response_format={"type": "json_object"},
        temperature=0.25,
        top_p=0.8,
    )
    content = response.choices[0].message.content
    if not content:
        raise RuntimeError("LLM 未返回报告内容")
    report = json.loads(content)
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "model": model,
        "replay_name": replay_name or evidence.get("scenario"),
        "evidence_summary": evidence,
        "analysis": report,
    }


def report_to_markdown(report: dict[str, Any]) -> str:
    analysis = report.get("analysis") or {}
    lines = [
        f"# {report.get('replay_name', 'CyberArena')} 技术分析报告",
        "",
        f"- 生成时间：{report.get('generated_at', '')}",
        f"- 分析模型：{report.get('model', '')}",
        "",
        "## 执行摘要",
        "",
        str(analysis.get("executive_summary", "")),
        "",
        "## 技术评估",
        "",
        str(analysis.get("technical_assessment", "")),
        "",
        "## 关键发现",
        "",
    ]
    for item in analysis.get("key_findings") or []:
        lines.extend(
            [
                f"### [{item.get('severity', 'medium').upper()}] {item.get('title', '发现')}",
                "",
                f"**证据：** {item.get('evidence', '')}",
                "",
                str(item.get("analysis", "")),
                "",
            ]
        )
    lines.extend(["## 攻击链分析", ""])
    for item in analysis.get("attack_chain_analysis") or []:
        lines.extend([f"- **{item.get('step', '步骤')}：** {item.get('assessment', '')}"])
    lines.extend(["", "## 防御分析", ""])
    for item in analysis.get("defense_analysis") or []:
        lines.extend([f"- **{item.get('topic', '主题')}：** {item.get('assessment', '')}"])
    lines.extend(["", "## 评分合理性", "", str(analysis.get("scoring_assessment", "")), "", "## 红方建议", ""])
    for item in analysis.get("red_recommendations") or []:
        lines.append(f"- **{item.get('priority', 'P1')}** {item.get('recommendation', '')}：{item.get('rationale', '')}")
    lines.extend(["", "## 蓝方建议", ""])
    for item in analysis.get("blue_recommendations") or []:
        lines.append(f"- **{item.get('priority', 'P1')}** {item.get('recommendation', '')}：{item.get('rationale', '')}")
    lines.extend(["", "## 结论", "", str(analysis.get("conclusion", "")), ""])
    return "\n".join(lines)
