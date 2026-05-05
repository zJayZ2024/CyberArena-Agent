# Benchmark 使用说明

该目录提供离线基线评测脚本，用于固定场景下批量运行并导出量化指标。

## 快速 smoke（推荐先跑）

```bash
python -m backend_engine.benchmark.run_benchmark --smoke
```

默认输出目录：

- `backend_engine/results/benchmark/benchmark.json`
- `backend_engine/results/benchmark/benchmark.md`

## 完整评测示例

```bash
python -m backend_engine.benchmark.run_benchmark \
  --scenario backend_engine/scenarios/level_2_ransomware.json \
  --rounds 20 \
  --runs 10 \
  --seed_base 42
```

## 关键参数

- `--scenario`: 场景文件路径
- `--rounds`: 每次运行回合数
- `--runs`: 批量运行次数
- `--seed_base`: 随机种子起点（第 N 次运行 seed = `seed_base + N - 1`）
- `--strict_llm`: 启用严格 LLM 模式（默认关闭，默认使用可回退模式）
- `--use_probability`: 启用概率门控
- `--stop_on_winner`: 达到胜利锁定后提前停止
- `--output_dir`: 结果输出目录

## 指标定义

- 回合成功率：有完整红蓝动作日志且两者均非非法动作的回合占比
- 非法动作率：红蓝动作中 `validation=failed` 或 `referee_effect=rejected` 的占比
- 平均响应时延：单次模拟总耗时 / 执行回合数
- 回放导出耗时：`build_replay_lite + 写盘` 耗时

