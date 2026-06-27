# CyberArena-Agent

CyberArena-Agent 是一个面向网络安全攻防推演的多智能体仿真项目。它把红方攻击、蓝方防守、裁判结算、场景拓扑和前端回放放在同一个工作流中，用于生成可复盘的攻防过程、比分变化、节点状态变化和推理报告。

当前仓库包含两部分主要能力：

- 后端仿真引擎：基于 Python、FastAPI、Pydantic 与 OpenAI 兼容接口，负责加载场景、驱动红蓝智能体决策、执行裁判结算、导出回放和生成报告。
- 前端回放仪表盘：基于 Vite + React，负责展示场景选择、仿真任务、网络拓扑、回合日志、比分曲线、推理面板和报告导出。

## 目录结构

```text
.
├── backend_engine/              # 仿真引擎、智能体、裁判、场景、API 服务
│   ├── agents/                  # 红方、蓝方、裁判与 LLM 智能体封装
│   ├── core/                    # 核心状态模型、评分、拓扑、裁判引擎
│   ├── engine/                  # 行为空间、上下文构建、协议/决策辅助
│   ├── prompts/                 # 红蓝裁判系统提示词
│   ├── scenarios/               # 内置攻防场景 JSON
│   ├── benchmark/               # 批量评测与 smoke benchmark
│   ├── serve_replay.py          # FastAPI 服务入口
│   └── start_simulation_zh.py   # 中文仿真 CLI 入口
├── frontend_dashboard/          # 前端仪表盘
│   ├── public/                  # 前端静态回放、场景目录
│   └── src/                     # React 源码
├── schemas/                     # 顶层示例 schema
├── results/                     # 顶层示例结果
├── pyproject.toml               # Python 项目与依赖
├── uv.lock                      # uv 锁文件
└── README.md
```

## 环境要求

- Python >= 3.13
- uv
- Node.js >= 18
- npm >= 9
- 一个 OpenAI 兼容的 Chat Completions 服务

Windows 终端建议使用 UTF-8，避免中文日志显示异常：

```powershell
chcp 65001
```

## 配置 LLM

复制环境变量模板：

```powershell
Copy-Item .env.example .env
```

然后在 `.env` 中填写：

```env
OPENAI_API_KEY="your_key"
OPENAI_BASE_URL="https://your-openai-compatible-endpoint/v1"
LLM_MODEL_NAME="your-model"
```

后端通过 `python-dotenv` 加载 `.env`。如果没有可用的 LLM 配置，严格模式下的红蓝决策会失败；部分离线评测命令可使用回退策略。

## 快速启动

安装后端依赖：

```powershell
uv sync --locked
```

安装前端依赖：

```powershell
cd frontend_dashboard
npm install
cd ..
```

启动后端 API：

```powershell
uv run uvicorn backend_engine.serve_replay:app --host 127.0.0.1 --port 8000 --reload
```

启动前端开发服务器：

```powershell
cd frontend_dashboard
npm run dev
```

打开 Vite 输出的地址，通常是：

```text
http://localhost:5173
```

前端开发服务器会把 `/api` 请求代理到 `http://127.0.0.1:8000`。

## 运行一次命令行仿真

推荐使用中文入口：

```powershell
uv run python -m backend_engine.start_simulation_zh `
  --scenario backend_engine/scenarios/level_1_basic_web.json `
  --rounds 20 `
  --use_probability `
  --random_seed 42 `
  --output backend_engine/results/mock_simulation_zh.json `
  --output_lite frontend_dashboard/public/latest_replay.json
```

常用参数：

- `--scenario`：场景 JSON 路径。
- `--rounds`：仿真回合数。
- `--use_probability`：启用漏洞利用和修补概率门控。
- `--random_seed`：固定随机种子，便于复现实验。
- `--allow_fallback`：LLM 决策失败时允许回退到规则策略。
- `--stop_on_winner`：胜负锁定后提前停止。
- `--output`：完整回放输出路径。
- `--output_lite`：前端友好的精简回放输出路径。

## 前后端联调

后端服务提供这些主要接口：

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/api/health` | 健康检查 |
| `POST` | `/api/simulations` | 创建仿真任务 |
| `GET` | `/api/simulations` | 查看仿真任务列表 |
| `GET` | `/api/simulations/{job_id}` | 查看单个任务状态 |
| `POST` | `/api/simulations/{job_id}/stop` | 请求停止正在运行的任务 |
| `GET` | `/api/simulations/{job_id}/replay` | 获取已完成任务的回放 |
| `POST` | `/api/reports` | 基于回放生成报告 |
| `GET` | `/api/reports` | 查看报告任务列表 |
| `GET` | `/api/reports/{report_id}` | 查看报告内容 |
| `GET` | `/api/reports/{report_id}/download?format=markdown` | 下载 Markdown 报告 |

仿真任务产物默认写入：

```text
backend_engine/results/frontend_runs/
```

报告产物默认写入：

```text
backend_engine/results/reports/
```

## 场景与回放数据

内置场景位于：

```text
backend_engine/scenarios/
```

当前包括从基础网站、勒索传播、企业分支、云 SaaS 到混合身份危机场景的多级拓扑。前端场景目录位于：

```text
frontend_dashboard/public/scenario_catalog.json
```

如果新增场景，通常需要同时确认：

- 场景 JSON 放在 `backend_engine/scenarios/` 下。
- 场景路径没有越出后端允许目录。
- 前端 `scenario_catalog.json` 中有对应条目。
- 节点、边、漏洞、核心资产字段符合后端模型与 schema 约定。

## Benchmark

运行快速 smoke benchmark：

```powershell
uv run python -m backend_engine.benchmark.run_benchmark --smoke
```

运行指定场景的批量评测：

```powershell
uv run python -m backend_engine.benchmark.run_benchmark `
  --scenario backend_engine/scenarios/level_2_ransomware.json `
  --rounds 20 `
  --runs 10 `
  --seed_base 42 `
  --use_probability
```

默认输出：

```text
backend_engine/results/benchmark/benchmark.json
backend_engine/results/benchmark/benchmark.md
```

## 前端常用命令

```powershell
cd frontend_dashboard
npm install
npm run dev
npm run build
npm run preview
```

建议提交前至少执行：

```powershell
cd frontend_dashboard
npm run build
```

## 开发约定

- 后端新增行为时，优先补充 `backend_engine/engine/actions.py`、上下文构建逻辑和裁判结算规则。
- 场景文件应保持可复现，涉及随机性的实验建议传入 `--random_seed`。
- 回放 JSON 是前后端之间的关键契约，改动字段时需要同步检查前端组件。
- API 服务只允许从 `backend_engine/scenarios/` 加载场景，避免任意路径读取。
- 中文 CLI 优先使用 `backend_engine.start_simulation_zh`，旧的 `start_simulation.py` 中仍可能存在历史编码问题。

## 常见问题

### 前端能打开，但启动仿真失败

确认后端服务正在运行，并检查：

```powershell
curl http://127.0.0.1:8000/api/health
```

如果直接访问后端正常，但前端失败，检查 Vite 是否运行在 `localhost:5173` 或 `127.0.0.1:5173`，以及 `frontend_dashboard/vite.config.js` 中的代理配置。

### LLM 决策失败

检查 `.env` 中的 `OPENAI_API_KEY`、`OPENAI_BASE_URL` 和 `LLM_MODEL_NAME`。如果只是做本地流程验证，可以在 CLI 中加 `--allow_fallback`，或在 benchmark 中不启用 `--strict_llm`。

### 中文输出乱码

优先运行：

```powershell
chcp 65001
```

并使用：

```powershell
uv run python -m backend_engine.start_simulation_zh
```

### 端口冲突

- 后端默认使用 `8000`，可通过 `--port` 修改。
- 前端默认使用 `5173`，Vite 会在冲突时提示新的端口。
- 如果前端端口变化，需要同步确认后端 CORS 配置是否允许该地址。
