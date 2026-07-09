# CGN Pen-testing V5.6.1 — 配置工作流增强版

本补丁以 `CGN_Pen-testing_V5.6.1(1).jar` 为基线构建，保留此前版本的：

- 多来源自动扫描、Burp Scope 边界、可靠任务队列、失败重试与最终去重；
- 安全主动探针与指纹表达式增强；
- 模块化重构与 Swing EDT 配置快照；
- 结果索引、350ms 节流、分页投影和增量 JTable 更新；
- 扫描控制台、失败任务诊断、暂停/恢复与右键菜单兼容状态。

## 本版新增：配置向导

配置中心新增 **配置向导** Tab，以任务流而不是控件堆叠组织配置：

1. 扫描边界与安全模式；
2. 启用扫描能力；
3. 访问控制检查；
4. 请求模板与认证策略；
5. 高级调度、字典和规则库。

向导不会移除原有专家页，而是提供深链入口，避免 Body、Header、规则表达式和导入导出出现两份不同步的配置。

## 安全默认值

- 默认强制 Burp Scope；
- 默认启用 Target / Proxy / Repeater，关闭 Intruder / Scanner；
- 默认只允许 GET / HEAD / OPTIONS 模板；
- POST / PUT / PATCH / DELETE 等可能改变状态的方法必须在向导中显式确认后才会被调度器使用；
- 模板预览不展示 Cookie、Authorization、Token 和 Header 值，只显示 Header 名称与 Body 长度。

详细改动见 [CONFIG_WORKFLOW_CHANGELOG_CN.md](CONFIG_WORKFLOW_CHANGELOG_CN.md)。

## 构建

需要 JDK 21：

```bash
./build.sh CGN_Pen-testing_V5.6.1(1).jar CGN_Pen-testing_V5.6.1-config.jar
./test.sh CGN_Pen-testing_V5.6.1-config.jar
```

## 测试范围

`test.sh` 会验证：

1. JAR 字节码与模拟 Burp 集成；
2. EDT 配置快照、Scope、失败重试、主动探针与最终去重；
3. 650 条连续扫描日志的索引、分页与增量刷新；
4. 扫描控制台及暂停/恢复命令；
5. 配置向导已挂载到配置中心；
6. 写操作模板默认阻止，显式许可后才允许；
7. `ScanOrchestratorCore` 与 `RequestBuilder` 不直接依赖 Swing。

## 已知边界

- 右键菜单依赖 Burp 的 `IContextMenuFactory`；控制台会显示注册状态。
- 原插件仍最多保留约 2000 条原始扫描结果，本补丁优化的是展示与操作流程，不扩大该会话存储上限。
- 写操作模板许可只控制本补丁的可靠调度路径；请继续在真实授权环境中审查原插件其余手工能力。
- 这是对闭源编译 JAR 的兼容补丁。请先在隔离、授权环境验证 Burp 版本、主题和高并发流量兼容性。

## V5.6.1-layered-dict：分层字典扫描

本版本在配置工作流增强版基础上新增“分层字典”页签，支持按扫描目录层级配置不同字典组。

核心模型：

```text
字典组决定扫什么路径
请求模板决定怎么请求
层级策略决定在哪里扫
Burp Scope / 黑白名单决定能不能扫
```

未配置字典组时会自动使用旧字典兼容组，保持旧行为；创建自定义组后，调度器会按字典组的层级范围、路径策略、关联模板和最大请求数执行。

详细说明见 `LAYERED_DICTIONARY_CHANGELOG_CN.md`。

## 维护性重构版补充说明

本版本新增 Java package 分层，详见 `MAINTAINABILITY_REFACTOR_CN.md`。核心变化包括：

- 构建脚本支持递归源码编译；
- `ScanConfig`、`UiScanSnapshot`、`RequestBuilder`、`FingerprintEngine`、`LayeredDictionaryStore`、`ScanResultViewModel` 等已迁移到独立 package；
- 新增 `RetryPolicy` 与 `ScopeGuard`，将重试退避和 Scope 边界从调度核心中外移；
- 字典组新增 `category`、`tags`、`version`、`description`、`updatedAt` 维护元数据；
- 保留 legacy 兼容层在 `burp` 包下，避免破坏原始 JAR 中 package-private 类型访问。

## 2026-07-08 分层字典预设修复

本版已将此前外部示例包中的 12 个字典组内置到插件中。首次打开“配置中心 → 分层字典”且没有自定义分层字典配置时，会自动生成这些组；已有自定义配置不会被覆盖。
