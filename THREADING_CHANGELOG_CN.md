# Swing 线程模型修复变更清单

| 原风险路径 | 修复方式 |
|---|---|
| Listener / worker 调用 `JCheckBox.isSelected()` | EDT 捕获为 `UiScanSnapshot`，后台仅读取 `AtomicReference` |
| Listener / worker 调用 `JTextField/JTextArea.getText()` | 字典、过滤规则、间隔、排除项在 EDT 冻结到快照 |
| 扫描请求构造回调原 `buildScanRequestForTarget()` | 新 `RequestBuilder` 使用任务快照自主构建 HTTP 请求 |
| 模板或 Header 编辑期间读取到半成品 | 125 ms EDT 防抖；任务只使用完整快照 |
| 可靠性配置使用裸 `volatile` | `AtomicReference<ScanConfig>` 原子替换不可变对象 |
| 后台直接刷新表格/状态 | `BurpViewModel` 统一通过 EDT 执行 UI 更新 |

## 关键类

- `ScanConfig`：可靠性配置，不可变。
- `UiScanSnapshot`：遗留 Swing 扫描设置、规则快照、Header 快照，不可变。
- `BurpViewModel`：唯一 UI 读写边界与快照发布者。
- `ScanOrchestratorCore`：只消费快照，不依赖 `javax.swing`。
- `RequestBuilder`：只消费快照，不依赖 `javax.swing`。
