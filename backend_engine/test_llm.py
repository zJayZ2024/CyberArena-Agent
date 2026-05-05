import os
from dotenv import load_dotenv
from openai import OpenAI
# 引入你刚才写好的 Pydantic 模型
from core.base_agent import ActionLog 

# 1. 加载 .env 文件中的环境变量
load_dotenv()

# 2. 初始化 OpenAI 客户端 (底层会自动读取 OPENAI_API_KEY 和 OPENAI_BASE_URL)
client = OpenAI()

def test_deepseek_json_mode():
    print("⏳ 正在向大模型发送请求，请稍候...")
    
    # 强制大模型输出 JSON 的系统提示词
    system_prompt = """
    你是一个渗透测试黑客（红方 Agent）。
    你的任务是对目标系统进行网络攻击。
    
    【重要指令】
    你必须且只能返回纯 JSON 格式的数据，绝对不要包含任何 Markdown 标记（如 ```json）。
    JSON 的结构必须严格包含以下字段：
    - "agent_type": 必须固定为 "Red"
    - "thought": 你的分析和决策过程
    - "action_type": 你的攻击方式 (例如: "SQL_Injection", "Port_Scan")
    - "payload": 你实际使用的命令行代码或注入载荷
    - "referee_result": 固定填入 "Pending" (等待裁判结算)
    """
    
    user_prompt = "目标靶机是 192.168.1.100 的 80 端口，请对我发起一次 SQL 注入攻击。"

    try:
       # 引入 os 用于读取模型名称
        model_name = os.getenv("LLM_MODEL_NAME", "ecnu-turbo")
        
        # 3. 发送 API 请求
        response = client.chat.completions.create(
            model=model_name,  # <--- 动态使用学校的模型名称
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            # 注意这里！如果学校模型报错说不支持 json_object，请把下面这一行注释掉！
            response_format={"type": "json_object"}, 
            temperature=0.7,
            top_p=0.8 # 从你的 config 搬过来的最佳实践
        )

        # 4. 提取返回的纯文本
        result_text = response.choices[0].message.content
        print("\n📥 原始返回文本 (JSON格式):")
        print(result_text)

        # 5. 使用 Pydantic 将 JSON 文本强类型反序列化为 Python 对象
        parsed_action = ActionLog.model_validate_json(result_text)
        
        print("\n✅ Pydantic 校验成功！提取出的强类型数据如下:")
        print(f"👤 身份: {parsed_action.agent_type}")
        print(f"🤔 思考: {parsed_action.thought}")
        print(f"⚔️ 动作: {parsed_action.action_type}")
        print(f"📦 载荷: {parsed_action.payload}")
        print(f"⚖️ 状态: {parsed_action.referee_result}")
        
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")

if __name__ == "__main__":
    test_deepseek_json_mode()