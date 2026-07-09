# 冗余精简与模块化重构说明

## 基线

- 输入基线：`CGN_Pen-testing_V5.6.1-maintainable-source.zip`
- 重构目标：减少可靠性层与扫描调度层中的职责堆叠、重复状态模型和 UI 适配耦合。
- 硬性约束：不修改原有扫描业务逻辑、不改变请求模板/字典/Scope/重试/预算语义，不调整既有 UI 布局和样式。

## P0：冗余精简

### 1. 从 `CgnReliability` 抽离扫描状态模型

原先 `CgnReliability` 同时承担：

- Burp 生命周期代理；
- Scope 校验；
- 主动探针执行；
- 反射缓存；
- 路径工具；
- 任务状态枚举；
- 任务计划 DTO；
- 任务记录；
- 执行结果；
- 软 404 基线结果；
- 右键菜单 Handler；
- Worker ThreadFactory。

本轮将纯模型与执行辅助抽离到 `burp.scan`：

- `ScanSource`
- `TaskState`
- `ScanPlan`
- `TaskRecord`
- `ExecutionResult`
- `BaselineFetch`
- `ReliabilityThreadFactory`

`CgnReliability` 保留生命周期、Scope、主动探针和 legacy 兼容入口。

### 2. 抽离 Probe 去重缓存

新增：

- `burp.scan.ProbeRegistry`

将原来散落在 `ScanOrchestratorCore` 的：

- 运行中 Probe 锁；
- 完成 Probe 去重；
- 达到上限后的完成缓存清理；
- 失败释放锁；

收敛成单一组件，避免调度主流程中直接操作多个 Map。

### 3. 抽离分层字典路径规划

新增：

- `burp.scan.ScanPathPlanner`

收敛以下纯逻辑：

- 字典组匹配请求模板；
- 按层级解析扫描基准目录；
- 按路径策略拼接候选路径；
- 构造含字典组维度的 Probe Key。

这样 `ScanOrchestratorCore` 的主循环只保留“执行扫描”的流程控制，路径规划逻辑可独立测试与维护。

### 4. 右键菜单从可靠性核心抽离

新增：

- `burp.ui.ContextMenuHandler`

原 `CgnReliability.ContextMenuHandler` 被移出可靠性层，避免 Swing 菜单构造和调度核心混在一起。菜单文字、动作和可用性未改变。

### 5. 清理核心类中的宽泛 import

对核心改动类进行了 import 收敛，减少 `import burp.*`、`import burp.xxx.*` 等宽泛引用在核心类中的扩散，便于后续判断真实依赖边界。

已收敛类包括：

- `CgnReliability`
- `ScanOrchestratorCore`
- `ScanOrchestrator`
- `ScanResultRepository`
- `ScanConfig`

## P1：模块化整合

### 新增包结构

```text
burp.scan
  ScanSource.java
  TaskState.java
  ScanPlan.java
  TaskRecord.java
  ExecutionResult.java
  BaselineFetch.java
  ProbeRegistry.java
  ScanPathPlanner.java
  ReliabilityThreadFactory.java

burp.ui
  ContextMenuHandler.java
```

### 模块职责变化

| 模块 | 重构前 | 重构后 |
|---|---|---|
| `CgnReliability` | 生命周期 + 状态模型 + 右键菜单 + 线程工厂 + 工具函数 | 生命周期、Scope、主动探针、legacy 兼容入口 |
| `ScanOrchestratorCore` | 调度 + Probe Map + 路径规划 + 执行 | 调度与执行主流程 |
| `ProbeRegistry` | 不存在 | 集中管理运行中/完成 Probe 去重 |
| `ScanPathPlanner` | 不存在 | 集中管理字典路径与模板规划 |
| `ContextMenuHandler` | 嵌套在可靠性类中 | 独立 UI 适配器 |

## 保持不变的逻辑

以下行为保持不变：

- 自动扫描来源配置；
- Burp Scope 强制策略；
- 失败重试次数与退避策略；
- 任务状态机语义；
- Probe 成功后才提交最终去重；
- 分层字典层级、路径策略、模板绑定；
- 写操作模板默认拦截；
- EDT / Worker 隔离；
- 结果分页与索引刷新；
- 现有 UI 布局和按钮文案。

## 验证

已执行：

```bash
./build.sh CGN_Pen-testing_V5.6.1\(1\).jar CGN_Pen-testing_V5.6.1-refined.jar
./test.sh CGN_Pen-testing_V5.6.1-refined.jar
```

通过项：

- JAR 构建；
- `java -Xverify:all`；
- Repeater 自动扫描；
- Scope 外拦截；
- 空响应重试；
- 主动探针重试与去重；
- 结果分页索引；
- EDT / Worker 边界检查。

## 后续可继续做但本轮未动的点

为了严格遵守“不动 UI 与业务逻辑”，本轮没有继续拆以下大类：

- `BurpViewModel`
- `ConfigurationWorkflowView`
- `ScanResultViewModel`
- `LayeredDictionaryConfigView`

这些类主要是 Swing UI 组装和 legacy 适配，后续若允许进行 UI 内部结构重构，可继续拆为：

- `StatusPanelBuilder`
- `FailureTaskPanel`
- `SourceSelectorPanel`
- `DictionaryGroupForm`
- `ResultPaginationModel`
- `ResultFilterIndex`
