package burp;
import burp.scan.*;

import burp.*;
import burp.bootstrap.*;
import burp.config.*;
import burp.dictionary.*;
import burp.fingerprint.*;
import burp.js.*;
import burp.request.*;
import burp.result.*;
import burp.traffic.*;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.text.JTextComponent;

/**
 * Task-oriented configuration entry point layered on top of the original expert panels.
 * It intentionally owns only the safe defaults and navigation. Complex Header/Body/Rule fields
 * remain in the legacy panels, reached through explicit links rather than duplicated forms.
 */
public final class ConfigurationWorkflowView {
    static final String TAB_TITLE = "配置向导";

    private final BurpExtender extender;
    private final BurpViewModel viewModel;
    private volatile BurpViewModel.ReliabilityController controller;
    private volatile Timer refreshTimer;

    private volatile JCheckBox moduleEnabled;
    private volatile JCheckBox directoryEnabled;
    private volatile JCheckBox scopeRequired;
    private volatile JCheckBox targetSource;
    private volatile JCheckBox proxySource;
    private volatile JCheckBox repeaterSource;
    private volatile JCheckBox intruderSource;
    private volatile JCheckBox scannerSource;
    private volatile JCheckBox unsafeMethods;
    private volatile JComboBox<String> templatePicker;
    private volatile JLabel boundarySummary;
    private volatile JLabel accessSummary;
    private volatile JLabel templateRiskSummary;
    private volatile JLabel applyStatus;
    private volatile JTextArea templatePreview;
    private volatile JTextArea validationOutput;
    private boolean synchronizing;

    ConfigurationWorkflowView(BurpExtender extender, BurpViewModel viewModel) {
        this.extender = extender;
        this.viewModel = viewModel;
    }

    /** Must be called on the EDT by BurpViewModel. */
    void install(BurpViewModel.ReliabilityController value) {
        this.controller = value;
        if (!SwingUtilities.isEventDispatchThread()) {
            viewModel.onEdt(new Runnable() { public void run() { install(value); } });
            return;
        }
        try {
            Object field = BurpExtensionAccess.readField(extender, "configurationTabs");
            if (!(field instanceof JTabbedPane)) return;
            JTabbedPane tabs = (JTabbedPane) field;
            if (findTab(tabs, TAB_TITLE) < 0) {
                tabs.addTab(TAB_TITLE, buildPanel());
            }
            refreshFromRuntime();
            startRefreshTimer();
        } catch (Exception error) {
            log("[CGN] 配置向导加载失败: " + message(error));
        }
    }

    void shutdown() {
        Timer timer = refreshTimer;
        if (timer != null) timer.stop();
    }

    private JComponent buildPanel() {
        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        JLabel title = new JLabel("配置向导 · 先安全范围，再模板与高级规则");
        title.setFont(title.getFont().deriveFont(Font.BOLD, title.getFont().getSize() + 2.0f));
        header.add(title);
        JLabel subtitle = new JLabel("变更会立即用于新建任务；已排队任务保留创建时的不可变配置快照。");
        header.add(subtitle);
        root.add(header, BorderLayout.NORTH);

        JTabbedPane steps = new JTabbedPane();
        steps.addTab("1. 快速开始", buildQuickStartPanel());
        steps.addTab("2. 请求与认证", buildRequestPanel());
        steps.addTab("3. 高级设置与规则", buildAdvancedPanel());
        root.add(steps, BorderLayout.CENTER);

        applyStatus = new JLabel("状态：配置向导已加载。建议先确认 Burp Scope，再启用自动扫描来源。");
        root.add(applyStatus, BorderLayout.SOUTH);
        return root;
    }

    private JComponent buildQuickStartPanel() {
        JPanel content = verticalPanel();
        content.add(scanBoundaryPanel());
        content.add(modulePanel());
        content.add(accessControlPanel());
        content.add(new JLabel("说明：Host、状态码和目录层级位于结果页，仅用于筛选显示，不会改变真实扫描范围。"));
        return new JScrollPane(content);
    }

    private JComponent scanBoundaryPanel() {
        JPanel root = new JPanel(new BorderLayout(6, 6));
        root.setBorder(BorderFactory.createTitledBorder("步骤 1 · 扫描边界与安全模式"));

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        scopeRequired = new JCheckBox("强制遵守 Burp Scope（推荐）");
        scopeRequired.setToolTipText("开启后，插件只对 Burp Scope 内的 URL 创建扫描任务。");
        scopeRequired.addActionListener(event -> updateConfigFromControls());
        controls.add(scopeRequired);

        targetSource = sourceBox("Target", ScanSource.TARGET);
        proxySource = sourceBox("Proxy", ScanSource.PROXY);
        repeaterSource = sourceBox("Repeater", ScanSource.REPEATER);
        intruderSource = sourceBox("Intruder", ScanSource.INTRUDER);
        scannerSource = sourceBox("Scanner", ScanSource.SCANNER);
        controls.add(targetSource);
        controls.add(proxySource);
        controls.add(repeaterSource);
        controls.add(intruderSource);
        controls.add(scannerSource);

        JButton safe = new JButton("应用推荐安全预设");
        safe.setToolTipText("启用 Scope、Target / Proxy / Repeater；禁用 Intruder / Scanner 和写操作模板。");
        safe.addActionListener(event -> applyProfile(false));
        controls.add(safe);
        JButton extended = new JButton("应用扩展覆盖预设");
        extended.setToolTipText("保留 Scope 与只读模板限制，同时启用 Intruder / Scanner 来源。");
        extended.addActionListener(event -> applyProfile(true));
        controls.add(extended);
        root.add(controls, BorderLayout.NORTH);

        boundarySummary = new JLabel("扫描边界加载中…");
        boundarySummary.setBorder(BorderFactory.createEmptyBorder(0, 6, 5, 6));
        root.add(boundarySummary, BorderLayout.CENTER);
        return root;
    }

    private JCheckBox sourceBox(String label, final ScanSource source) {
        JCheckBox box = new JCheckBox(label);
        box.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                if (!synchronizing) updateConfigFromControls();
            }
        });
        return box;
    }

    private JComponent modulePanel() {
        JPanel root = new JPanel(new BorderLayout(6, 6));
        root.setBorder(BorderFactory.createTitledBorder("步骤 2 · 启用本次扫描能力"));
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        moduleEnabled = new JCheckBox("启用 CGN 扫描模块");
        moduleEnabled.setToolTipText("关闭后，不会从自动来源创建目录扫描任务。");
        directoryEnabled = new JCheckBox("启用目录扫描");
        directoryEnabled.setToolTipText("关闭后，信息提取仍可由原插件处理；目录请求不会排队。 ");
        controls.add(moduleEnabled);
        controls.add(directoryEnabled);
        JButton apply = new JButton("应用并保存扫描开关");
        apply.addActionListener(event -> applyLegacyScanSwitches());
        controls.add(apply);
        root.add(controls, BorderLayout.NORTH);
        JLabel note = new JLabel("安全提示：此处只控制插件和目录扫描开关；范围仍由 Burp Scope、白名单和黑名单共同决定。");
        note.setBorder(BorderFactory.createEmptyBorder(0, 6, 5, 6));
        root.add(note, BorderLayout.CENTER);
        return root;
    }

    private JComponent accessControlPanel() {
        JPanel root = new JPanel(new BorderLayout(6, 6));
        root.setBorder(BorderFactory.createTitledBorder("步骤 3 · 访问控制检查"));
        accessSummary = new JLabel("白名单 / 黑名单读取中…");
        accessSummary.setBorder(BorderFactory.createEmptyBorder(0, 6, 5, 6));
        root.add(accessSummary, BorderLayout.CENTER);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton access = new JButton("打开访问控制");
        access.addActionListener(event -> selectConfigTab("访问控制"));
        actions.add(access);
        JButton diagnosis = new JButton("运行配置检查");
        diagnosis.addActionListener(event -> {
            runConfigurationCheck();
            selectWorkflowStep(2);
        });
        actions.add(diagnosis);
        root.add(actions, BorderLayout.SOUTH);
        return root;
    }

    private JComponent buildRequestPanel() {
        JPanel content = verticalPanel();
        JPanel root = new JPanel(new BorderLayout(6, 6));
        root.setBorder(BorderFactory.createTitledBorder("步骤 4 · 请求模板与认证策略"));

        JPanel chooser = new JPanel(new FlowLayout(FlowLayout.LEFT));
        chooser.add(new JLabel("当前请求模板："));
        templatePicker = new JComboBox<String>();
        templatePicker.setToolTipText("选择后仅切换原有编辑器中的当前模板；编辑内容请使用“打开完整模板编辑器”。");
        templatePicker.addActionListener(event -> {
            if (!synchronizing) selectLegacyTemplate(templatePicker.getSelectedIndex());
        });
        chooser.add(templatePicker);
        JButton refresh = new JButton("刷新预览");
        refresh.addActionListener(event -> refreshFromRuntime());
        chooser.add(refresh);
        JButton edit = new JButton("打开完整模板编辑器");
        edit.addActionListener(event -> selectConfigTab("请求模板"));
        chooser.add(edit);
        root.add(chooser, BorderLayout.NORTH);

        templatePreview = new JTextArea(11, 80);
        templatePreview.setEditable(false);
        templatePreview.setLineWrap(true);
        templatePreview.setWrapStyleWord(true);
        root.add(new JScrollPane(templatePreview), BorderLayout.CENTER);

        JPanel safety = new JPanel(new FlowLayout(FlowLayout.LEFT));
        unsafeMethods = new JCheckBox("允许 POST / PUT / PATCH / DELETE 等可能改变状态的方法");
        unsafeMethods.setToolTipText("默认关闭。开启后，插件可能按照已启用模板向目标发送有副作用的方法。仅限已授权环境。 ");
        unsafeMethods.addActionListener(event -> changeUnsafeMethodPermission());
        safety.add(unsafeMethods);
        templateRiskSummary = new JLabel("模板风险加载中…");
        safety.add(templateRiskSummary);
        root.add(safety, BorderLayout.SOUTH);
        content.add(root);

        JPanel hint = new JPanel(new FlowLayout(FlowLayout.LEFT));
        hint.setBorder(BorderFactory.createTitledBorder("认证与敏感 Header"));
        hint.add(new JLabel("模板预览只显示 Header 名称，不显示 Cookie / Authorization 值。"));
        JButton headers = new JButton("配置 Header / Body");
        headers.addActionListener(event -> selectConfigTab("请求模板"));
        hint.add(headers);
        content.add(hint);
        return new JScrollPane(content);
    }

    private JComponent buildAdvancedPanel() {
        JPanel content = verticalPanel();
        content.add(advancedNavigationPanel());
        content.add(configurationCheckPanel());
        content.add(dataLifecyclePanel());
        return new JScrollPane(content);
    }

    private JComponent advancedNavigationPanel() {
        JPanel root = new JPanel(new FlowLayout(FlowLayout.LEFT));
        root.setBorder(BorderFactory.createTitledBorder("高级配置入口"));
        root.add(new JLabel("复杂字段保留在专家面板中，避免快速配置误改请求、规则或字典。"));
        root.add(navigationButton("请求模板", "请求模板"));
        root.add(navigationButton("访问控制", "访问控制"));
        root.add(navigationButton("路径字典", "字典配置"));
        root.add(navigationButton("规则库", "规则库中心"));
        root.add(navigationButton("队列与重试", "可靠性"));
        return root;
    }

    private JButton navigationButton(String label, String tab) {
        JButton button = new JButton(label);
        button.addActionListener(event -> selectConfigTab(tab));
        return button;
    }

    private JComponent configurationCheckPanel() {
        JPanel root = new JPanel(new BorderLayout(6, 6));
        root.setBorder(BorderFactory.createTitledBorder("配置检查与风险提示"));
        validationOutput = new JTextArea(12, 80);
        validationOutput.setEditable(false);
        validationOutput.setLineWrap(true);
        validationOutput.setWrapStyleWord(true);
        root.add(new JScrollPane(validationOutput), BorderLayout.CENTER);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton check = new JButton("运行配置检查");
        check.addActionListener(event -> runConfigurationCheck());
        actions.add(check);
        JButton safe = new JButton("恢复推荐安全预设");
        safe.addActionListener(event -> applyProfile(false));
        actions.add(safe);
        root.add(actions, BorderLayout.SOUTH);
        return root;
    }

    private JComponent dataLifecyclePanel() {
        JPanel root = new JPanel(new FlowLayout(FlowLayout.LEFT));
        root.setBorder(BorderFactory.createTitledBorder("配置生效与数据边界"));
        root.add(new JLabel("保存后：新任务读取新配置；已排队任务保留快照。导入/导出规则库请在“规则库”中完成。"));
        return root;
    }

    private JPanel verticalPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        return panel;
    }

    private void updateConfigFromControls() {
        if (synchronizing || controller == null) return;
        ScanConfig current = controller.config();
        ScanConfig next = new ScanConfig(
                targetSource != null && targetSource.isSelected(),
                proxySource != null && proxySource.isSelected(),
                scannerSource != null && scannerSource.isSelected(),
                intruderSource != null && intruderSource.isSelected(),
                repeaterSource != null && repeaterSource.isSelected(),
                scopeRequired != null && scopeRequired.isSelected(),
                current.unsafeTemplateMethodsAllowed,
                current.maxRetries, current.retryInitialMillis, current.pendingLimit);
        controller.updateConfig(next);
        setStatus("扫描边界已保存；变更仅影响新建任务。");
        refreshFromRuntime();
    }

    private void applyProfile(boolean extendedCoverage) {
        if (controller == null) return;
        ScanConfig current = controller.config();
        ScanConfig next = new ScanConfig(true, true, extendedCoverage, extendedCoverage, true,
                true, false, current.maxRetries, current.retryInitialMillis, current.pendingLimit);
        controller.updateConfig(next);
        setStatus(extendedCoverage
                ? "已应用扩展覆盖预设：Scope 强制、全部自动来源、写操作模板仍被阻止。"
                : "已应用推荐安全预设：Scope 强制，仅 Target / Proxy / Repeater，写操作模板被阻止。");
        refreshFromRuntime();
    }

    /** Applies only the two legacy scan toggles and persists them through the original owner. */
    private void applyLegacyScanSwitches() {
        if (!SwingUtilities.isEventDispatchThread()) {
            viewModel.onEdt(new Runnable() { public void run() { applyLegacyScanSwitches(); } });
            return;
        }
        boolean updated = false;
        try {
            Object module = BurpExtensionAccess.readField(extender, "switchs");
            if (module instanceof JCheckBox && moduleEnabled != null) {
                ((JCheckBox) module).setSelected(moduleEnabled.isSelected());
                updated = true;
            }
            Object directory = BurpExtensionAccess.readField(extender, "jp_host_uri_scan_2_jb");
            if (directory instanceof JCheckBox && directoryEnabled != null) {
                ((JCheckBox) directory).setSelected(directoryEnabled.isSelected());
                updated = true;
            }
            BurpExtensionAccess.invokePrivate(extender, "saveScanSettings", new Class<?>[0], new Object[0]);
            viewModel.refreshLegacySnapshotFromEdt();
            setStatus(updated ? "扫描开关已保存；新任务立即使用新设置。" : "未找到原始扫描开关，未写入设置。");
        } catch (Exception error) {
            setStatus("保存扫描开关失败：" + message(error));
        }
        refreshFromRuntime();
    }

    private void changeUnsafeMethodPermission() {
        if (synchronizing || controller == null || unsafeMethods == null) return;
        boolean requested = unsafeMethods.isSelected();
        if (requested && !controller.config().unsafeTemplateMethodsAllowed) {
            int choice = JOptionPane.showConfirmDialog(null,
                    "启用后，已启用的 POST / PUT / PATCH / DELETE 模板可能改变目标状态。\n"
                            + "仅在已授权、可承受副作用的环境继续。",
                    "确认允许有副作用的请求模板", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice != JOptionPane.YES_OPTION) {
                synchronizing = true;
                unsafeMethods.setSelected(false);
                synchronizing = false;
                setStatus("已取消启用写操作模板。安全限制保持开启。");
                return;
            }
        }
        controller.updateConfig(controller.config().withUnsafeTemplateMethodsAllowed(requested));
        setStatus(requested ? "已允许写操作模板。请复核 Body、Header 与 Burp Scope。"
                : "已阻止写操作模板。只读方法仍可用于扫描。");
        refreshFromRuntime();
    }

    private void selectLegacyTemplate(int index) {
        if (!SwingUtilities.isEventDispatchThread()) {
            viewModel.onEdt(new Runnable() { public void run() { selectLegacyTemplate(index); } });
            return;
        }
        if (index < 0) return;
        try {
            Object comboValue = BurpExtensionAccess.readField(extender, "request_group_cb");
            if (comboValue instanceof JComboBox<?>) {
                JComboBox<?> combo = (JComboBox<?>) comboValue;
                if (index < combo.getItemCount()) {
                    combo.setSelectedIndex(index);
                    BurpExtensionAccess.invokePrivate(extender, "loadSelectedRequestGroupToEditor",
                            new Class<?>[0], new Object[0]);
                    viewModel.refreshLegacySnapshotFromEdt();
                    setStatus("已切换当前模板。编辑并保存请使用“请求模板”专家页。");
                }
            }
        } catch (Exception error) {
            setStatus("切换请求模板失败：" + message(error));
        }
        refreshFromRuntime();
    }

    private void refreshFromRuntime() {
        if (!SwingUtilities.isEventDispatchThread()) {
            viewModel.onEdt(new Runnable() { public void run() { refreshFromRuntime(); } });
            return;
        }
        BurpViewModel.ReliabilityController active = controller;
        if (active == null) return;
        synchronizing = true;
        try {
            ScanConfig config = active.config();
            if (scopeRequired != null) scopeRequired.setSelected(config.scopeRequired);
            if (targetSource != null) targetSource.setSelected(config.targetEnabled);
            if (proxySource != null) proxySource.setSelected(config.proxyEnabled);
            if (repeaterSource != null) repeaterSource.setSelected(config.repeaterEnabled);
            if (intruderSource != null) intruderSource.setSelected(config.intruderEnabled);
            if (scannerSource != null) scannerSource.setSelected(config.scannerEnabled);
            if (unsafeMethods != null) unsafeMethods.setSelected(config.unsafeTemplateMethodsAllowed);
            if (moduleEnabled != null) moduleEnabled.setSelected(readSelected("switchs"));
            if (directoryEnabled != null) directoryEnabled.setSelected(readSelected("jp_host_uri_scan_2_jb"));
            if (boundarySummary != null) boundarySummary.setText(boundaryText(config));
            if (accessSummary != null) accessSummary.setText(accessText());
            refreshTemplatePicker();
            renderTemplatePreview(config);
            runConfigurationCheck(false);
        } finally {
            synchronizing = false;
        }
    }

    private void refreshTemplatePicker() {
        if (templatePicker == null) return;
        int selected = legacyComboIndex("request_group_cb");
        List<String> names = legacyComboItems("request_group_cb");
        if (templatePicker.getItemCount() == names.size()) {
            boolean equal = true;
            for (int i = 0; i < names.size(); i++) {
                if (!names.get(i).equals(String.valueOf(templatePicker.getItemAt(i)))) { equal = false; break; }
            }
            if (equal) {
                if (selected >= 0 && selected < templatePicker.getItemCount()) templatePicker.setSelectedIndex(selected);
                return;
            }
        }
        templatePicker.removeAllItems();
        for (String name : names) templatePicker.addItem(name);
        if (selected >= 0 && selected < templatePicker.getItemCount()) templatePicker.setSelectedIndex(selected);
    }

    private void renderTemplatePreview(ScanConfig config) {
        if (templatePreview == null || templateRiskSummary == null) return;
        String method = legacyComboValue("scan_method_cb").toUpperCase(Locale.ROOT);
        if (method.length() == 0) method = "GET";
        String path = readText("scan_path_tf").trim();
        String body = readText("scan_body_ta");
        String match = readText("scan_rule_match_ta");
        String deny = readText("scan_rule_deny_ta");
        List<String> headers = enabledHeaderNames();
        String templateName = legacyComboValue("request_group_cb");
        boolean safe = isReadOnlyMethod(method);
        String risk = safe ? "只读模板：允许执行" : (config.unsafeTemplateMethodsAllowed
                ? "写操作模板：已明确允许（请确认授权与副作用）" : "写操作模板：已被安全模式阻止");
        templateRiskSummary.setText("模板风险：" + risk);
        templatePreview.setText("模板：" + emptyFallback(templateName, "未选择") + "\n"
                + "请求行：" + method + " " + emptyFallback(path, "/") + " HTTP/1.1\n"
                + "请求 Body：" + body.length() + " 个字符" + (body.trim().isEmpty() ? "（未配置）" : "（内容已隐藏）") + "\n"
                + "额外 Header：" + (headers.isEmpty() ? "未配置" : String.join("、", headers)) + "\n"
                + "命中条件：" + (match.trim().isEmpty() ? "未配置" : "已配置（内容请在专家页编辑）") + "\n"
                + "排除条件：" + (deny.trim().isEmpty() ? "未配置" : "已配置（内容请在专家页编辑）") + "\n"
                + "扫描层级：" + enabledLevels() + "\n\n"
                + "最终目标 Host、Cookie、Authorization 与 Header 值会继承 Burp 流量或专家页配置；\n"
                + "配置向导不会展示敏感值。请在“请求模板”页复核完整请求。\n\n"
                + "执行策略：" + risk);
    }

    private void runConfigurationCheck() { runConfigurationCheck(true); }

    private void runConfigurationCheck(boolean updateStatus) {
        if (validationOutput == null || controller == null) return;
        ScanConfig config = controller.config();
        List<String> notices = new ArrayList<String>();
        List<String> warnings = new ArrayList<String>();
        if (!readSelected("switchs")) warnings.add("扫描模块已关闭：不会创建新的自动扫描任务。");
        else notices.add("扫描模块已启用。");
        if (!readSelected("jp_host_uri_scan_2_jb")) warnings.add("目录扫描已关闭：目录探测请求不会进入队列。");
        else notices.add("目录扫描已启用。");
        if (!config.scopeRequired) warnings.add("Burp Scope 未强制：请确认白名单 / 黑名单与授权边界。");
        else notices.add("Burp Scope 强制开启。");
        if (!config.targetEnabled && !config.proxyEnabled && !config.repeaterEnabled
                && !config.intruderEnabled && !config.scannerEnabled) {
            warnings.add("未启用任何自动扫描来源；只能通过手工入口创建任务。");
        } else notices.add("自动来源：" + sourceNames(config) + "。");
        if (!isAnyLevelEnabled()) warnings.add("未启用任何目录层级：目录扫描没有可执行的模板层级。");
        if (config.unsafeTemplateMethodsAllowed) warnings.add("允许写操作模板：请逐项复核 Body、Header、Scope 和测试授权。");
        else notices.add("写操作模板已阻止（默认安全策略）。");
        if (readSelected("White_switchs") && readText("White_switchs_list").trim().isEmpty()) {
            warnings.add("白名单已启用但没有规则：请在“访问控制”页补充 Host 规则。");
        }
        if (hasSensitiveHeader()) warnings.add("检测到 Authorization / Cookie / Token 等敏感 Header：本地配置和导出文件应按敏感数据管理。");
        else notices.add("未发现已启用的敏感额外 Header。 ");

        StringBuilder report = new StringBuilder("配置检查结果\n\n");
        for (String note : notices) report.append("✓ ").append(note).append('\n');
        for (String warning : warnings) report.append("! ").append(warning).append('\n');
        report.append("\n下一步建议：\n")
                .append("1. 在 Burp Target 中确认 Scope；\n")
                .append("2. 在“请求与认证”中复核模板方法和认证策略；\n")
                .append("3. 在“高级设置与规则”中调整字典、规则库、重试与队列。\n");
        validationOutput.setText(report.toString());
        if (updateStatus) setStatus(warnings.isEmpty() ? "配置检查通过：未发现阻断性风险。" : "配置检查发现 " + warnings.size() + " 项需要复核的风险。");
    }

    private void selectConfigTab(String title) {
        if (!SwingUtilities.isEventDispatchThread()) {
            viewModel.onEdt(new Runnable() { public void run() { selectConfigTab(title); } });
            return;
        }
        try {
            Object field = BurpExtensionAccess.readField(extender, "configurationTabs");
            if (!(field instanceof JTabbedPane)) return;
            JTabbedPane tabs = (JTabbedPane) field;
            int index = findTab(tabs, title);
            if (index >= 0) tabs.setSelectedIndex(index);
        } catch (Exception error) {
            setStatus("打开“" + title + "”失败：" + message(error));
        }
    }

    private void selectWorkflowStep(int index) {
        try {
            Object field = BurpExtensionAccess.readField(extender, "configurationTabs");
            if (!(field instanceof JTabbedPane)) return;
            JTabbedPane configTabs = (JTabbedPane) field;
            int tab = findTab(configTabs, TAB_TITLE);
            if (tab < 0) return;
            configTabs.setSelectedIndex(tab);
            JComponent panel = (JComponent) configTabs.getComponentAt(tab);
            if (panel instanceof JPanel) {
                for (java.awt.Component child : ((JPanel) panel).getComponents()) {
                    if (child instanceof JTabbedPane) ((JTabbedPane) child).setSelectedIndex(index);
                }
            }
        } catch (Exception ignored) { }
    }

    private void startRefreshTimer() {
        if (refreshTimer != null) return;
        refreshTimer = new Timer(750, new ActionListener() {
            public void actionPerformed(ActionEvent event) { refreshFromRuntime(); }
        });
        refreshTimer.setRepeats(true);
        refreshTimer.start();
    }

    private boolean readSelected(String fieldName) {
        try {
            Object value = BurpExtensionAccess.readField(extender, fieldName);
            return value instanceof JCheckBox && ((JCheckBox) value).isSelected();
        } catch (Exception ignored) { return false; }
    }

    private String readText(String fieldName) {
        try {
            Object value = BurpExtensionAccess.readField(extender, fieldName);
            return value instanceof JTextComponent ? ((JTextComponent) value).getText() : "";
        } catch (Exception ignored) { return ""; }
    }

    private int legacyComboIndex(String fieldName) {
        try {
            Object value = BurpExtensionAccess.readField(extender, fieldName);
            return value instanceof JComboBox<?> ? ((JComboBox<?>) value).getSelectedIndex() : -1;
        } catch (Exception ignored) { return -1; }
    }

    private String legacyComboValue(String fieldName) {
        try {
            Object value = BurpExtensionAccess.readField(extender, fieldName);
            if (value instanceof JComboBox<?>) {
                Object selected = ((JComboBox<?>) value).getSelectedItem();
                return selected == null ? "" : String.valueOf(selected);
            }
        } catch (Exception ignored) { }
        return "";
    }

    private List<String> legacyComboItems(String fieldName) {
        try {
            Object value = BurpExtensionAccess.readField(extender, fieldName);
            if (!(value instanceof JComboBox<?>)) return Collections.emptyList();
            JComboBox<?> combo = (JComboBox<?>) value;
            List<String> items = new ArrayList<String>();
            for (int i = 0; i < combo.getItemCount(); i++) items.add(String.valueOf(combo.getItemAt(i)));
            return items;
        } catch (Exception ignored) { return Collections.emptyList(); }
    }

    @SuppressWarnings("unchecked")
    private List<String> enabledHeaderNames() {
        try {
            Object result = BurpExtensionAccess.invokePrivate(extender, "getEnabledExtraHeaderLines",
                    new Class<?>[0], new Object[0]);
            if (!(result instanceof List<?>)) return Collections.emptyList();
            List<String> names = new ArrayList<String>();
            for (Object value : (List<Object>) result) {
                String raw = value == null ? "" : String.valueOf(value).trim();
                int colon = raw.indexOf(':');
                if (colon > 0) names.add(raw.substring(0, colon).trim());
            }
            return names;
        } catch (Exception ignored) { return Collections.emptyList(); }
    }

    private boolean hasSensitiveHeader() {
        for (String header : enabledHeaderNames()) {
            String lower = header.toLowerCase(Locale.ROOT);
            if (lower.contains("authorization") || lower.contains("cookie") || lower.contains("token")
                    || lower.contains("api-key") || lower.contains("secret")) return true;
        }
        return false;
    }

    private boolean isAnyLevelEnabled() {
        return readSelected("scan_level_0_jb") || readSelected("scan_level_1_jb")
                || readSelected("scan_level_2_jb") || readSelected("scan_level_3_jb")
                || readSelected("scan_level_4_jb");
    }

    private String enabledLevels() {
        List<String> values = new ArrayList<String>();
        if (readSelected("scan_level_0_jb")) values.add("根目录");
        if (readSelected("scan_level_1_jb")) values.add("1 级目录");
        if (readSelected("scan_level_2_jb")) values.add("2 级目录");
        if (readSelected("scan_level_3_jb")) values.add("3 级目录");
        if (readSelected("scan_level_4_jb")) values.add("4 级及以上");
        return values.isEmpty() ? "未启用" : String.join("、", values);
    }

    private String accessText() {
        boolean whitelist = readSelected("White_switchs");
        boolean blacklist = readSelected("Black_switchs");
        int whiteRules = lineCount(readText("White_switchs_list"));
        int blackRules = lineCount(readText("Black_switchs_list"));
        return "访问控制：白名单 " + (whitelist ? "启用（" + whiteRules + " 条）" : "未启用")
                + " ｜ 黑名单 " + (blacklist ? "启用（" + blackRules + " 条）" : "未启用")
                + "。完整规则请在“访问控制”页维护。";
    }

    private static int lineCount(String input) {
        int count = 0;
        if (input != null) for (String line : input.split("\\r?\\n")) if (!line.trim().isEmpty()) count++;
        return count;
    }

    private static String boundaryText(ScanConfig config) {
        return "当前扫描边界：Burp Scope" + (config.scopeRequired ? "（强制）" : "（未强制）")
                + " ｜ 自动来源：" + sourceNames(config)
                + " ｜ 写操作模板：" + (config.unsafeTemplateMethodsAllowed ? "已允许" : "已阻止");
    }

    private static String sourceNames(ScanConfig config) {
        List<String> values = new ArrayList<String>();
        if (config.targetEnabled) values.add("Target");
        if (config.proxyEnabled) values.add("Proxy");
        if (config.repeaterEnabled) values.add("Repeater");
        if (config.intruderEnabled) values.add("Intruder");
        if (config.scannerEnabled) values.add("Scanner");
        return values.isEmpty() ? "未启用" : String.join("、", values);
    }

    private static boolean isReadOnlyMethod(String method) {
        return "GET".equals(method) || "HEAD".equals(method) || "OPTIONS".equals(method);
    }

    private static String emptyFallback(String value, String fallback) {
        return value == null || value.trim().isEmpty() ? fallback : value;
    }

    private static int findTab(JTabbedPane tabs, String title) {
        for (int i = 0; i < tabs.getTabCount(); i++) if (title.equals(tabs.getTitleAt(i))) return i;
        return -1;
    }

    private void setStatus(String text) {
        if (applyStatus != null) applyStatus.setText("状态：" + (text == null ? "" : text));
    }

    private void log(String text) {
        BurpViewModel.ReliabilityController active = controller;
        if (active != null) active.log(text);
    }

    private static String message(Exception error) {
        String detail = error.getMessage();
        return detail == null || detail.trim().isEmpty() ? error.getClass().getSimpleName() : detail;
    }
}
