# 架构、线程与配置工作流边界

## 依赖方向

```text
Burp API / 原始 BurpExtender
           ↑
BurpExtensionAccess  ←  RequestBuilder / RuleLibraryRepository / JsExtractionEngine / BurpViewModel
           ↑
ScanOrchestratorCore ← ScanOrchestrator ← BurpTrafficListener ← ExtensionBootstrap
           ↑
ScanConfig / ScanResultRepository / FingerprintEngine
```

## 配置工作流边界

```text
配置向导（EDT）
    ├── ScanConfig：Scope、来源、写操作模板许可、重试、队列
    ├── 原始扫描开关：通过兼容层写回并保存
    └── 专家页深链：请求模板 / 访问控制 / 字典 / 规则库 / 可靠性

原始 Swing 控件（EDT）
           ↓
UiScanSnapshot（不可变）
           ↓
ScanOrchestratorCore / RequestBuilder（后台，不引用 Swing）
```

- `ConfigurationWorkflowView` 只管理安全边界、开关、预设、摘要与导航，不复制 Body / Header / 规则编辑器；
- 原始控件编辑后由 `BurpViewModel.refreshLegacySnapshotFromEdt()` 生成新 `UiScanSnapshot`；
- `ScanConfig.unsafeTemplateMethodsAllowed` 是独立的不可变运行时设置，写入 `cgn_reliability.properties`；
- `RequestBuilder` 在构造请求前根据该设置拒绝未许可的写操作方法；
- 已创建的 `ScanPlan` 继续持有创建时的 `ScanConfig` 与 `UiScanSnapshot`，因此运行中配置修改不会污染排队任务。

## UX 边界

```text
调度器 TaskRecord（并发状态）
           ↓  不可变 TaskView
BurpViewModel（EDT）
           ↓
扫描控制台 / 可靠性页 / 配置向导 / 结果投影
```

- Worker 只生成不可变 `TaskView`，不操作 JTable、标签或按钮；
- `BurpViewModel` 是所有 Swing 读写、定时刷新、失败任务表、配置快照和暂停按钮的唯一边界；
- `ScanResultViewModel` 继续负责结果索引、分页与 JTable 增量事件；
- `IContextMenuFactory` 通过兼容层注册，注册结果作为用户可见状态而不是隐藏日志。

## 不变量

1. Scope 未通过时不排队自动/右键目录扫描，也不执行主动探针。
2. 只有得到有效 HTTP 响应的 probe 才进入 completed 去重并消耗旧版预算。
3. 失败不污染最终去重；按配置执行有限退避重试。
4. Host、状态码和层级是结果视图筛选；Burp Scope、白名单/黑名单和自动来源是扫描边界。
5. 未显式许可时，POST / PUT / PATCH / DELETE 等写操作模板不得进入可靠调度请求构造。
6. 所有后台到 UI 的任务信息以不可变快照传递，并在 EDT 渲染。
