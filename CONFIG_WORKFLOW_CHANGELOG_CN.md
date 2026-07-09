# 配置中心工作流优化说明

## 目标

原始配置中心保留了完整能力，但按控件和数据结构组织：请求模板、访问控制、字典、规则库、可靠性彼此独立。新用户需要自己判断先配置什么、哪些设置会发包、哪些只影响结果显示。

本版新增 **配置向导**，不删除专家能力，而是在原有配置中心上增加一个面向任务的入口：

```text
扫描边界与安全模式
        ↓
启用扫描能力
        ↓
访问控制检查
        ↓
请求模板与认证策略
        ↓
高级调度、字典与规则库
```

## 新增：配置向导

配置中心新增末尾 Tab：`配置向导`。添加在末尾而不是插入旧 Tab 索引，避免破坏原插件帮助中心对“请求模板 / 访问控制 / 字典 / 规则库”旧索引的导航。

### 步骤 1：扫描边界与安全模式

- 清晰显示 Burp Scope 是否强制；
- 可选择 Target、Proxy、Repeater、Intruder、Scanner 自动来源；
- 提供两个真实可执行的预设：
  - **推荐安全预设**：Scope 强制，启用 Target / Proxy / Repeater，禁用 Intruder / Scanner，阻止写操作模板；
  - **扩展覆盖预设**：Scope 强制，启用全部自动来源，仍阻止写操作模板；
- 明确说明 Host、状态码和层级只过滤结果，不改变扫描发包边界。

### 步骤 2：启用本次扫描能力

- 集中控制“启用 CGN 扫描模块”和“启用目录扫描”；
- 变更写回原插件控件，并调用原始 `saveScanSettings()` 持久化；
- UI 修改后由 EDT 重新生成不可变 `UiScanSnapshot`，后台任务不读取 Swing。

### 步骤 3：访问控制检查

- 摘要显示白名单 / 黑名单启用状态和规则数量；
- 不在向导重复编辑大段规则，避免出现两份配置来源；
- 点击“打开访问控制”直接进入原专家页。

### 请求与认证策略

- 只显示模板名称、方法、路径、Body 长度、Header 名称、规则是否存在和目录层级；
- 不展示 Cookie、Authorization、Token 或 Header 值；
- 一键跳转到完整请求模板编辑器；
- 对 POST / PUT / PATCH / DELETE 等方法给出风险状态。

## 新增：写操作模板显式许可

`ScanConfig` 增加 `unsafeTemplateMethodsAllowed`，默认 `false` 并写入 `cgn_reliability.properties`：

```properties
template.unsafe.methods.allowed=false
```

- GET / HEAD / OPTIONS 始终允许；
- POST / PUT / PATCH / DELETE 等方法在默认策略下由 `RequestBuilder` 阻止；
- 用户只能在“请求与认证”页勾选开关，并通过风险确认对话框后允许；
- 许可变更只影响新建任务，已经进入队列的任务继续使用其创建时的 `ScanConfig` 快照。

## 高级设置与规则

向导不复制复杂专家表单，而提供稳定的深链入口：

- 请求模板；
- 访问控制；
- 路径字典；
- 规则库；
- 队列与重试。

这样可以防止 Body、Header、匹配表达式、规则导入导出出现“向导与专家页双向不同步”的问题。

## 配置检查

向导内置只读配置检查，会提示：

- 扫描模块或目录扫描是否关闭；
- Burp Scope 是否未强制；
- 是否未启用任何自动来源；
- 是否未选择任何目录层级；
- 白名单已启用但为空；
- 是否已允许写操作模板；
- 是否配置 Authorization、Cookie、Token、API Key、Secret 等敏感额外 Header。

检查只提示风险，不会自动修改用户配置。

## 线程与持久化边界

- `ConfigurationWorkflowView` 是 EDT 组件；
- 它写入原始 Swing 控件后，调用 `BurpViewModel.refreshLegacySnapshotFromEdt()` 发布新的不可变快照；
- `RequestBuilder` 和 `ScanOrchestratorCore` 依旧不包含 `javax.swing` 依赖；
- `ScanConfigStore` 将新增许可字段用 UTF-8 原子写方式持久化。
