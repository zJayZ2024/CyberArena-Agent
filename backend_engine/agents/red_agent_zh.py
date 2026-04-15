from backend_engine.core.models import AgentDecision, WorldState


class RedAgent:
    agent_name = "Red"

    def decide(self, state: WorldState) -> AgentDecision:
        nodes = state.network_nodes

        if nodes["web"].status != "Compromised" and nodes["web"].vulnerabilities:
            return AgentDecision(
                agent_type="Red",
                thought="\u516c\u7f51 Web \u8282\u70b9\u4ecd\u7136\u5b58\u5728\u6f0f\u6d1e\uff0c\u662f\u5f53\u524d\u6700\u5bb9\u6613\u62ff\u4e0b\u7684\u7a81\u7834\u53e3\u3002",
                action_type="ExploitService",
                target="web",
                payload="\u901a\u8fc7\u516c\u7f51 HTTP \u670d\u52a1\u5229\u7528 CVE-WEB-2026-0001",
            )

        if (
            nodes["web"].status == "Compromised"
            and nodes["app"].status != "Compromised"
            and nodes["app"].vulnerabilities
        ):
            return AgentDecision(
                agent_type="Red",
                thought="Web \u5c42\u5df2\u7ecf\u5931\u9677\uff0c\u4e0b\u4e00\u6b65\u5e94\u6a2a\u5411\u79fb\u52a8\u5230\u5185\u90e8\u5e94\u7528\u5c42\u3002",
                action_type="LateralMove",
                target="app",
                payload="\u590d\u7528\u4ece Web \u8282\u70b9\u7a83\u53d6\u7684\u51ed\u636e\u6a2a\u5411\u8fdb\u5165 App",
            )

        if (
            nodes["app"].status == "Compromised"
            and nodes["db"].status != "Compromised"
            and nodes["db"].vulnerabilities
        ):
            return AgentDecision(
                agent_type="Red",
                thought="\u6570\u636e\u5e93\u53ef\u7531\u5e94\u7528\u5c42\u5230\u8fbe\uff0c\u4e14\u4ecd\u5b58\u5728\u8584\u5f31\u70b9\uff0c\u53ef\u4ee5\u5c1d\u8bd5\u8fdb\u4e00\u6b65\u6e17\u900f\u3002",
                action_type="ExfiltrateDatabase",
                target="db",
                payload="\u5229\u7528 App \u5230 DB \u7684\u4fe1\u4efb\u94fe\u8def\u5e76\u5c1d\u8bd5\u5bfc\u51fa\u8bb0\u5f55",
            )

        return AgentDecision(
            agent_type="Red",
            thought="\u5f53\u524d\u6ca1\u6709\u660e\u786e\u53ef\u5229\u7528\u8def\u5f84\uff0c\u5148\u7ee7\u7eed\u505a\u4f4e\u566a\u58f0\u4fa6\u5bdf\u3002",
            action_type="Recon",
            target="web",
            payload="\u5bf9 Web \u5165\u53e3\u6267\u884c\u4f4e\u566a\u58f0\u626b\u63cf",
        )
