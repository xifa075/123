# 维护性重构说明

本版本基于 `CGN_Pen-testing_V5.6.1-layered-dict` 继续做维护性重构，目标是让后续迭代时能按职责定位代码，而不是继续在单一 `burp` 包中堆叠功能。

## 已完成

### 1. Java package 分层

新增并迁移以下包：

| 包 | 职责 |
|---|---|
| `burp.bootstrap` | Burp 生命周期组合入口 |
| `burp.traffic` | Burp HTTP 流量入口与自动扫描触发边界 |
| `burp.config` | 不可变运行配置、配置持久化、UI 快照 |
| `burp.request` | 请求构造、模板方法安全策略 |
| `burp.fingerprint` | 指纹表达式匹配 |
| `burp.js` | JS / 响应信息提取委托 |
| `burp.dictionary` | 分层字典模型、导入导出、持久化 |
| `burp.result` | 结果视图索引、分页、表格投影 |
| `burp.scan` | 可独立复用的扫描辅助策略，如重试退避与 Scope 判断 |

`CgnEnhancement`、`CgnReliability`、`ScanOrchestratorCore`、`RuleLibraryRepository` 等兼容层核心仍保留在 `burp` 包下，原因是原始插件 JAR 中存在多个 package-private 类型和字段，例如 `RuleLibraryStore`、`BurpExtender` 内部表格模型与部分 legacy UI 字段。强行迁移会导致反射与包级访问风险升高。因此本轮采用“新模块分层 + legacy 兼容边界保留”的安全迁移策略。

### 2. 大类职责继续外移

新增：

- `burp.scan.RetryPolicy`：集中维护重试次数与退避时间计算。
- `burp.scan.ScopeGuard`：集中维护 Burp Scope 判断边界。

同时继续保留前序版本已有职责拆分：

- `ScanResultViewModel`：结果索引、分页与节流刷新。
- `UiScanSnapshot`：EDT 中生成的不可变 UI 快照。
- `RequestBuilder`：请求模板组装与写操作模板拦截。
- `LayeredDictionaryStore`：分层字典组模型与持久化。

### 3. 字典组维护元数据

`LayeredDictionaryStore.DictionaryGroup` 新增团队维护元数据字段：

- `category`
- `tags`
- `version`
- `description`
- `updatedAt`

旧构造函数仍保留，旧配置文件仍可读取。新字段会进入持久化与字典指纹计算，方便后续做团队字典版本管理、标签筛选和变更追踪。

### 4. 构建脚本支持递归源码编译

`build.sh` 已从单目录编译：

```bash
src/burp/*.java
```

改为递归编译：

```bash
find "$ROOT/src" -name "*.java" ! -name "PatchCgn.java"
```

后续新增 package 不需要再修改构建脚本。

## 验证

已执行：

- JAR 构建；
- `java -Xverify:all` 集成测试；
- Repeater 自动扫描；
- Scope 拦截；
- 空响应重试；
- 主动探针重试与成功后去重；
- 结果索引与分页；
- EDT / Worker 边界检查；
- 分层字典兼容组和持久化测试；
- 新 package 模块加载检查。

## 后续建议

下一阶段可继续拆分：

- `ScanPlanner`：生成扫描计划；
- `ScanTaskExecutor`：执行单个任务；
- `BudgetManager`：预算控制；
- `DedupRegistry`：去重状态；
- `FailureRepository`：失败任务诊断与重放；
- `DictionaryTagFilter`：按 category / tags / version 筛选字典组。

这些需要进一步替换原始 JAR 的 legacy 私有逻辑，建议在拥有完整原始源码后做彻底迁移。
