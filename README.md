# CyberArena-Agent

## 文档定位

本文档面向仓库内部开发成员，当前只维护前端相关说明。

后端仍在整理和封装中，后端环境、运行方式、接口约定与数据流说明暂不在本文档展开，等项目包装完成后再补充。

## 当前状态

- 前端已可独立启动，位于 `frontend_dashboard/`
- 前端基于 `Vite + React`
- 当前页面用于展示网络拓扑、攻防路径、节点状态、回合推进和推理面板
- 根目录中的 `topology_preview.html` 与 `TopologyGraph.jsx` 主要作为设计/实现参考
- 后端目录已存在，但暂不作为当前联调入口

## 目录约定

- `frontend_dashboard/`
  前端工程目录，日常前端开发默认在这里进行
- `frontend_dashboard/src/`
  React 源码目录
- `frontend_dashboard/public/`
  静态资源目录
- `backend_engine/`
  后端相关代码，暂不在本阶段说明
- `topology_preview.html`
  前端预览参考稿
- `TopologyGraph.jsx`
  根目录下的历史参考组件稿
- `results/`、`schemas/`
  示例数据与结构定义

## 前端环境要求

建议统一使用以下环境：

- `Node.js >= 18`
- `npm >= 9`

如果本机安装了多个 Node 版本，启动前先确认当前终端实际使用的版本符合要求。

## 前端初始化

首次拉取仓库后，在项目根目录执行：

```bash
cd frontend_dashboard
npm install
```

说明：

- 依赖安装只需要在 `frontend_dashboard/` 下执行
- 如果 `package.json` 或 `package-lock.json` 发生变化，需要重新执行一次 `npm install`
- 不建议直接复用来源不明的 `node_modules`

## 启动前端

开发模式启动：

```bash
cd frontend_dashboard
npm run dev
```

默认情况下，Vite 会输出一个本地地址，通常类似：

```text
http://localhost:5173
```

浏览器打开该地址即可查看当前前端页面。

## 前端常用命令

安装依赖：

```bash
cd frontend_dashboard
npm install
```

启动开发环境：

```bash
cd frontend_dashboard
npm run dev
```

打包前端：

```bash
cd frontend_dashboard
npm run build
```

本地预览生产包：

```bash
cd frontend_dashboard
npm run preview
```

## 新成员最短上手路径

1. 拉取仓库
2. 进入项目根目录
3. 执行 `cd frontend_dashboard`
4. 执行 `npm install`
5. 执行 `npm run dev`
6. 打开终端输出的本地地址

## 开发注意事项

- 前端开发默认工作目录为 `frontend_dashboard/`
- 当前 README 不包含后端启动说明，不要基于本文档自行假设后端运行方式
- 如果页面样式与预期不一致，先检查字体资源是否成功加载
- 如果端口被占用，Vite 会自动提示新的端口地址，按终端输出访问即可
- 如需验证改动是否可提交，至少执行一次 `npm run build`

## 待补充

以下内容后续补：

- 后端环境配置
- 后端启动命令
- 前后端联调方式
- 数据格式说明
- 部署与发布流程

测试