import os
import json
from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, Field
from typing import List, Dict, Literal, Optional, Type, TypeVar

# ==========================================
# 1. 数据契约定义 (Schemas)
# ==========================================
class NetworkNode(BaseModel):
    status: str = Field(..., description="General status of the node (e.g., 'Normal', 'Compromised', 'Down').")
    exposed_ports: Optional[List[int]] = Field(default_factory=list)
    vulnerabilities: Optional[List[str]] = Field(default_factory=list)

class ActionLog(BaseModel):
    agent_type: Literal["Red", "Blue", "Referee"] = Field(...)
    thought: str = Field(...)
    action_type: str = Field(...)
    payload: str = Field(...)
    referee_result: str = Field(...)

class WorldState(BaseModel):
    turn: int = Field(...)
    system_health: int = Field(..., ge=0, le=100)
    exposure_level: int = Field(..., ge=0, le=100)
    network_nodes: Dict[str, NetworkNode] = Field(...)
    action_logs: List[ActionLog] = Field(...)

# 用于泛型类型提示
T = TypeVar('T', bound=BaseModel)

# ==========================================
# 2. 核心智能体基类 (Base Agent)
# ==========================================
class BaseAgent:
    def __init__(self, agent_name: str, system_prompt: str):
        self.agent_name = agent_name
        self.system_prompt = system_prompt
        
        # 加载环境变量
        load_dotenv()
        self.client = OpenAI() # 自动读取 OPENAI_API_KEY 和 BASE_URL
        self.model_name = os.getenv("LLM_MODEL_NAME", "ecnu-turbo")

    def run(self, current_state_json: str, response_model: Type[T]) -> T:
        """
        核心执行方法：给 Agent 发送当前状态，获取结构化输出
        """
        print(f"[{self.agent_name}] 正在思考中...")
        
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": f"当前系统状态如下:\n{current_state_json}\n请做出你的下一步行动。"}
                ],
                temperature=0.7,
                top_p=0.8
            )
            
            # 获取原始文本
            raw_text = response.choices[0].message.content
            
            # 防御性编程：为了防止大模型输出带有 ```json 的 Markdown 格式
            # 我们做一层简单的清理
            clean_text = raw_text.strip()
            if clean_text.startswith("```json"):
                clean_text = clean_text[7:]
            if clean_text.startswith("```"):
                clean_text = clean_text[3:]
            if clean_text.endswith("```"):
                clean_text = clean_text[:-3]
                
            # 使用 Pydantic 校验并转换
            parsed_result = response_model.model_validate_json(clean_text.strip())
            return parsed_result
            
        except Exception as e:
            print(f"[{self.agent_name}] 执行失败: {str(e)}")
            # 在真实的生产环境中，这里应该加入重试机制 (Retry Logic)
            raise e
