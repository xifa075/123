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
import java.awt.Component;
import java.awt.Container;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ContainerAdapter;
import java.awt.event.ContainerEvent;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import javax.swing.AbstractButton;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JToggleButton;
import javax.swing.JSpinner;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.text.JTextComponent;

/**
 * The only Swing boundary. All reads of legacy controls happen on the EDT, then immutable state
 * is published to workers through AtomicReference. Worker code must never call a Swing getter.
 */
public final class BurpViewModel {
    interface ReliabilityController {
        ScanConfig config();
        void updateConfig(ScanConfig next);
        void retryFailed();
        void retryTask(String key);
        void setPaused(boolean paused);
        boolean paused();
        List<TaskView> taskViews();
        String contextMenuStatus();
        ScanStatus status();
        void log(String line);
    }

    public static final class ScanStatus {
        final boolean paused;
        final int pending, running, retryable, success, failed, cancelled;
        final int deferred, inFlight, completed;
        ScanStatus(boolean paused, int pending, int running, int retryable, int success, int failed, int cancelled,
                   int deferred, int inFlight, int completed) {
            this.paused = paused; this.pending = pending; this.running = running; this.retryable = retryable;
            this.success = success; this.failed = failed; this.cancelled = cancelled;
            this.deferred = deferred; this.inFlight = inFlight; this.completed = completed;
        }
        String text() {
            return (paused ? "● 已暂停" : "● 扫描中")
                    + "  排队 " + pending + " · 执行 " + running + " · 待重试 " + retryable
                    + " · 已完成 " + success + " · 失败 " + failed + " · 已取消 " + cancelled
                    + " · 延迟队列 " + deferred + " · 运行中探针 " + inFlight;
        }
    }

    /** Immutable diagnostic projection; safe to hand from scheduler to EDT. */
    public static final class TaskView {
        final String key, source, host, url, state, message;
        final int attempts;
        final long createdAt, updatedAt;
        TaskView(String key, String source, String host, String url, String state, int attempts,
                 String message, long createdAt, long updatedAt) {
            this.key = key == null ? "" : key; this.source = source == null ? "" : source;
            this.host = host == null ? "" : host; this.url = url == null ? "" : url;
            this.state = state == null ? "UNKNOWN" : state; this.attempts = attempts;
            this.message = message == null ? "" : message; this.createdAt = createdAt; this.updatedAt = updatedAt;
        }
        boolean requiresAttention() {
            return "FAILED".equals(state) || "RETRYABLE".equals(state) || "CANCELLED".equals(state);
        }
    }

    private final BurpExtender extender;
    private final ScanResultViewModel resultView;
    private final AtomicReference<UiScanSnapshot> uiSnapshot =
            new AtomicReference<UiScanSnapshot>(UiScanSnapshot.disabled());
    private final Map<Component, Boolean> observed =
            Collections.synchronizedMap(new IdentityHashMap<Component, Boolean>());
    private volatile JLabel statusLabel;
    private volatile Timer statusTimer;
    private volatile Timer snapshotDebounce;
    private volatile Timer snapshotHeartbeat;
    private volatile RuleLibraryRepository ruleRepository;
    private volatile Consumer<UiScanSnapshot> snapshotConsumer;
    private volatile Timer workbenchTimer;
    private volatile JLabel workbenchScopeLabel;
    private volatile JLabel workbenchStatusLabel;
    private volatile JLabel contextMenuLabel;
    private volatile JToggleButton workbenchPauseButton;
    private volatile FailureTaskTableModel failureTaskModel;
    private volatile ReliabilityController workbenchController;
    private volatile ConfigurationWorkflowView configurationWorkflow;
    private volatile LayeredDictionaryConfigView layeredDictionaryView;

    public BurpViewModel(BurpExtender extender) {
        this.extender = extender;
        this.resultView = new ScanResultViewModel(extender, this);
    }

    public UiScanSnapshot currentSnapshot() { return uiSnapshot.get(); }

    /** UI command: keeps legacy pause state and immutable worker snapshot synchronized on the EDT. */
    public void setLegacyScanPaused(final boolean paused) {
        onEdt(new Runnable() {
            public void run() {
                try { BurpExtensionAccess.writeField(extender, "scanPaused", Boolean.valueOf(paused)); }
                catch (Exception ignored) { }
                captureAndPublish();
            }
        });
    }

    public void onEdt(Runnable action) {
        if (action == null) return;
        if (SwingUtilities.isEventDispatchThread()) action.run();
        else SwingUtilities.invokeLater(action);
    }

    /** Starts EDT-only legacy UI observation after the original extension has built its controls. */
    public void bindLegacyUiSnapshots(final RuleLibraryRepository repository,
                               final Consumer<UiScanSnapshot> consumer) {
        this.ruleRepository = repository;
        this.snapshotConsumer = consumer;
        onEdt(new Runnable() {
            public void run() {
                wireLegacyUi();
                captureAndPublish();
                resultView.bindOnEdt();
                startSnapshotHeartbeat();
            }
        });
    }

    public void installReliabilityTab(final ReliabilityController controller) {
        onEdt(new Runnable() {
            public void run() {
                try {
                    Object tabValue = BurpExtensionAccess.readField(extender, "configurationTabs");
                    if (!(tabValue instanceof JTabbedPane)) return;
                    JTabbedPane tabs = (JTabbedPane) tabValue;
                    boolean installed = false;
                    for (int i = 0; i < tabs.getTabCount(); i++) {
                        if ("可靠性".equals(tabs.getTitleAt(i))) { installed = true; break; }
                    }
                    if (!installed) tabs.addTab("可靠性", buildReliabilityPanel(controller));
                    installScanWorkbench(controller);
                    installConfigurationWorkflow(controller);
                    installLayeredDictionaryView();
                    wireComponentTree(tabs);
                    markSnapshotDirty();
                } catch (Exception error) {
                    controller.log("[CGN] 可靠性配置页加载失败: " + safeMessage(error));
                }
            }
        });
    }

    /** Invoked by configuration UI after editing legacy controls on the EDT. */
    public void refreshLegacySnapshotFromEdt() {
        if (SwingUtilities.isEventDispatchThread()) captureAndPublish();
        else onEdt(new Runnable() { public void run() { captureAndPublish(); } });
    }

    private void installConfigurationWorkflow(ReliabilityController controller) {
        if (configurationWorkflow == null) configurationWorkflow = new ConfigurationWorkflowView(extender, this);
        configurationWorkflow.install(controller);
    }

    private void installLayeredDictionaryView() {
        RuleLibraryRepository repository = ruleRepository;
        if (repository == null) return;
        if (layeredDictionaryView == null) {
            layeredDictionaryView = new LayeredDictionaryConfigView(extender, this, repository);
        }
        layeredDictionaryView.install();
    }

    public void renderStatus(final ScanStatus status) {
        final JLabel label = statusLabel;
        if (label == null || status == null) return;
        onEdt(new Runnable() { public void run() { label.setText(status.text()); } });
    }

    /** Result rendering is index-backed and debounced; never call legacy scan_uri_filter here. */
    public void refreshResultTable() { resultView.onLegacyTableRefreshRequested(); }

    public void requestResultViewRefresh(boolean filterChanged) {
        if (filterChanged) resultView.onLegacyFilterRequested();
        else resultView.onLegacyTableRefreshRequested();
    }

    public void onScanLogEntryAdded(Object entry) { resultView.onLogEntryAdded(entry); }

    public ScanResultViewModel.ResultUiMetrics resultUiMetrics() { return resultView.diagnostics(); }

    public void shutdown() {
        final Timer status = statusTimer;
        final Timer debounce = snapshotDebounce;
        final Timer heartbeat = snapshotHeartbeat;
        onEdt(new Runnable() {
            public void run() {
                if (status != null) status.stop();
                if (debounce != null) debounce.stop();
                if (heartbeat != null) heartbeat.stop();
                if (workbenchTimer != null) workbenchTimer.stop();
                if (configurationWorkflow != null) configurationWorkflow.shutdown();
                resultView.shutdown();
            }
        });
    }

    private void wireLegacyUi() {
        try {
            Object tabs = BurpExtensionAccess.readField(extender, "configurationTabs");
            if (tabs instanceof Component) wireComponentTree((Component) tabs);
            Object mainTabs = BurpExtensionAccess.readField(extender, "mainTabs");
            if (mainTabs instanceof Component) wireComponentTree((Component) mainTabs);
        } catch (Exception ignored) {
            // Capture still works for the direct field names below if the hierarchy is unavailable.
        }
        for (String name : snapshotFieldNames()) {
            try {
                Object value = BurpExtensionAccess.readField(extender, name);
                if (value instanceof Component) wireComponentTree((Component) value);
            } catch (Exception ignored) { }
        }
    }

    private void wireComponentTree(Component component) {
        if (component == null || observed.put(component, Boolean.TRUE) != null) return;
        if (component instanceof AbstractButton) {
            ((AbstractButton) component).addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent event) { markSnapshotDirty(); }
            });
        }
        if (component instanceof JTextComponent) {
            ((JTextComponent) component).getDocument().addDocumentListener(new DocumentListener() {
                public void insertUpdate(DocumentEvent event) { markSnapshotDirty(); }
                public void removeUpdate(DocumentEvent event) { markSnapshotDirty(); }
                public void changedUpdate(DocumentEvent event) { markSnapshotDirty(); }
            });
        }
        if (component instanceof JComboBox<?>) {
            ((JComboBox<?>) component).addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent event) { markSnapshotDirty(); }
            });
        }
        if (component instanceof JSpinner) {
            ((JSpinner) component).addChangeListener(new ChangeListener() {
                public void stateChanged(ChangeEvent event) { markSnapshotDirty(); }
            });
        }
        if (component instanceof JList<?>) {
            ((JList<?>) component).addListSelectionListener(new ListSelectionListener() {
                public void valueChanged(ListSelectionEvent event) {
                    if (!event.getValueIsAdjusting()) markSnapshotDirty();
                }
            });
        }
        if (component instanceof JTable) {
            ((JTable) component).getModel().addTableModelListener(new TableModelListener() {
                public void tableChanged(TableModelEvent event) { markSnapshotDirty(); }
            });
        }
        if (component instanceof Container) {
            final Container container = (Container) component;
            container.addContainerListener(new ContainerAdapter() {
                @Override public void componentAdded(ContainerEvent event) {
                    wireComponentTree(event.getChild());
                    markSnapshotDirty();
                }
                @Override public void componentRemoved(ContainerEvent event) { markSnapshotDirty(); }
            });
            for (Component child : container.getComponents()) wireComponentTree(child);
        }
    }

    private void markSnapshotDirty() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(new Runnable() { public void run() { markSnapshotDirty(); } });
            return;
        }
        if (snapshotDebounce == null) {
            snapshotDebounce = new Timer(125, new ActionListener() {
                public void actionPerformed(ActionEvent event) { captureAndPublish(); }
            });
            snapshotDebounce.setRepeats(false);
        }
        snapshotDebounce.restart();
    }

    private void startSnapshotHeartbeat() {
        if (snapshotHeartbeat != null) return;
        snapshotHeartbeat = new Timer(1000, new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                // Covers legacy buttons/listeners that cannot be reached through the public UI tree.
                captureAndPublish();
            }
        });
        snapshotHeartbeat.setRepeats(true);
        snapshotHeartbeat.start();
    }

    /** Must run on EDT. */
    private void captureAndPublish() {
        if (!SwingUtilities.isEventDispatchThread()) {
            onEdt(new Runnable() { public void run() { captureAndPublish(); } });
            return;
        }
        UiScanSnapshot previous = uiSnapshot.get();
        RuleLibraryRepository.RuleSnapshot rules = previous.ruleSnapshot;
        try {
            RuleLibraryRepository repository = ruleRepository;
            if (repository != null) rules = repository.snapshot();
        } catch (Exception ignored) {
            // Keep the last known-good immutable rules if a legacy UI update is in progress.
        }
        UiScanSnapshot next = new UiScanSnapshot(
                selected("switchs", false),
                selected("jp_host_uri_scan_2_jb", false),
                booleanField("scanPaused", false),
                selected("White_switchs", false),
                text("White_switchs_list"),
                selected("Black_switchs", false),
                text("Black_switchs_list"),
                text("jp_host_uri_scan_2_tf2"),
                interval(text("jp_host_uri_scan_2_tf")),
                selected("scan_level_0_jb", false),
                selected("scan_level_1_jb", false),
                selected("scan_level_2_jb", false),
                selected("scan_level_3_jb", false),
                selected("scan_level_4_jb", false),
                enabledHeaderLines(), rules);
        if (previous.sameContent(next)) return;
        uiSnapshot.set(next);
        Consumer<UiScanSnapshot> consumer = snapshotConsumer;
        if (consumer != null) consumer.accept(next);
    }

    @SuppressWarnings("unchecked")
    private List<String> enabledHeaderLines() {
        try {
            Object result = BurpExtensionAccess.invokePrivate(extender, "getEnabledExtraHeaderLines",
                    new Class<?>[0], new Object[0]);
            if (!(result instanceof List<?>)) return Collections.emptyList();
            List<String> output = new ArrayList<String>();
            for (Object value : (List<Object>) result) if (value != null) output.add(String.valueOf(value));
            return output;
        } catch (Exception ignored) {
            return Collections.emptyList();
        }
    }

    private boolean selected(String fieldName, boolean fallback) {
        try {
            Object value = BurpExtensionAccess.readField(extender, fieldName);
            return value instanceof AbstractButton ? ((AbstractButton) value).isSelected() : fallback;
        } catch (Exception ignored) { return fallback; }
    }

    private String text(String fieldName) {
        try {
            Object value = BurpExtensionAccess.readField(extender, fieldName);
            return value instanceof JTextComponent ? ((JTextComponent) value).getText() : "";
        } catch (Exception ignored) { return ""; }
    }

    private boolean booleanField(String name, boolean fallback) {
        try {
            Object value = BurpExtensionAccess.readField(extender, name);
            return value instanceof Boolean ? ((Boolean) value).booleanValue() : fallback;
        } catch (Exception ignored) { return fallback; }
    }

    private int interval(String text) {
        try { return Math.max(50, Integer.parseInt(text == null ? "" : text.trim())); }
        catch (RuntimeException ignored) { return UiScanSnapshot.DEFAULT_INTERVAL_MS; }
    }

    private static String[] snapshotFieldNames() {
        return new String[] { "switchs", "jp_host_uri_scan_2_jb", "jp_host_uri_scan_diy_uri",
                "jp_host_uri_scan_2_ta", "jp_host_uri_scan_2_tf", "jp_host_uri_scan_2_tf2",
                "White_switchs", "White_switchs_list", "Black_switchs", "Black_switchs_list",
                "scan_level_0_jb", "scan_level_1_jb", "scan_level_2_jb", "scan_level_3_jb",
                "scan_level_4_jb", "scan_method_cb", "scan_path_tf", "scan_body_ta",
                "scan_rule_match_ta", "scan_rule_deny_ta", "scan_rule_alert_jb", "request_group_cb",
                "requestTemplateList", "extraHeaderTable" };
    }

    private JPanel buildReliabilityPanel(final ReliabilityController controller) {
        final ScanConfig current = controller.config();
        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));

        JPanel sources = new JPanel(new FlowLayout(FlowLayout.LEFT));
        sources.setBorder(BorderFactory.createTitledBorder("自动扫描来源（响应阶段）"));
        addSourceCheck(sources, controller, ScanSource.PROXY, current.proxyEnabled);
        addSourceCheck(sources, controller, ScanSource.TARGET, current.targetEnabled);
        addSourceCheck(sources, controller, ScanSource.REPEATER, current.repeaterEnabled);
        addSourceCheck(sources, controller, ScanSource.INTRUDER, current.intruderEnabled);
        addSourceCheck(sources, controller, ScanSource.SCANNER, current.scannerEnabled);
        content.add(sources);

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controls.setBorder(BorderFactory.createTitledBorder("可靠性与安全边界"));
        final JCheckBox scope = new JCheckBox("强制遵守 Burp Scope（默认开启）", current.scopeRequired);
        scope.setToolTipText("开启后，仅当 Burp 回调可确认 URL 在 Scope 内时才排队扫描。");
        scope.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                controller.updateConfig(controller.config().withScopeRequired(scope.isSelected()));
            }
        });
        controls.add(scope);
        controls.add(new JLabel("失败重试（0-2）："));
        final JSpinner retries = new JSpinner(new SpinnerNumberModel(current.maxRetries, 0, ScanConfig.MAX_RETRIES, 1));
        retries.addChangeListener(event -> controller.updateConfig(
                controller.config().withRetries(((Number) retries.getValue()).intValue())));
        controls.add(retries);
        controls.add(new JLabel("待处理上限："));
        final JSpinner pending = new JSpinner(new SpinnerNumberModel(current.pendingLimit,
                ScanConfig.MIN_PENDING_LIMIT, ScanConfig.MAX_PENDING_LIMIT, 50));
        pending.addChangeListener(event -> controller.updateConfig(
                controller.config().withPendingLimit(((Number) pending.getValue()).intValue())));
        controls.add(pending);
        JButton retry = new JButton("重新排队失败任务");
        retry.addActionListener(event -> controller.retryFailed());
        controls.add(retry);
        content.add(controls);

        statusLabel = new JLabel(controller.status().text());
        JPanel status = new JPanel(new FlowLayout(FlowLayout.LEFT));
        status.setBorder(BorderFactory.createTitledBorder("调度状态"));
        status.add(statusLabel);
        content.add(status);

        JPanel hints = new JPanel(new FlowLayout(FlowLayout.LEFT));
        hints.setBorder(BorderFactory.createTitledBorder("工作流提示"));
        JLabel scopeHint = new JLabel(scanBoundaryText(controller.config()));
        scopeHint.setToolTipText("Burp Scope、白名单和黑名单决定是否发起扫描；Host、状态码和目录层级仅影响结果筛选。");
        hints.add(scopeHint);
        JLabel menuHint = new JLabel("Burp 右键菜单：" + safeText(controller.contextMenuStatus()));
        hints.add(menuHint);
        content.add(hints);
        resultView.installPerformanceControls(content);

        root.add(new JScrollPane(content), BorderLayout.CENTER);
        statusTimer = new Timer(500, event -> {
            renderStatus(controller.status());
            scopeHint.setText(scanBoundaryText(controller.config()));
            menuHint.setText("Burp 右键菜单：" + safeText(controller.contextMenuStatus()));
        });
        statusTimer.start();
        return root;
    }

    private void addSourceCheck(JPanel panel, final ReliabilityController controller,
                                final ScanSource source, boolean selected) {
        final JCheckBox box = new JCheckBox(source.label, selected);
        box.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                controller.updateConfig(controller.config().withSource(source, box.isSelected()));
            }
        });
        panel.add(box);
    }

    /** Adds a task-oriented control room instead of burying reliability controls in configuration. */
    private void installScanWorkbench(final ReliabilityController controller) {
        this.workbenchController = controller;
        try {
            Object tabsValue = BurpExtensionAccess.readField(extender, "mainTabs");
            if (!(tabsValue instanceof JTabbedPane)) return;
            JTabbedPane tabs = (JTabbedPane) tabsValue;
            for (int i = 0; i < tabs.getTabCount(); i++) {
                if ("扫描控制台".equals(tabs.getTitleAt(i))) {
                    refreshScanWorkbench();
                    return;
                }
            }
            tabs.addTab("扫描控制台", buildScanWorkbench(controller));
            startWorkbenchTimer();
        } catch (Exception error) {
            controller.log("[CGN] 扫描控制台加载失败: " + safeMessage(error));
        }
    }

    private JComponent buildScanWorkbench(final ReliabilityController controller) {
        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel overview = new JPanel();
        overview.setLayout(new BoxLayout(overview, BoxLayout.Y_AXIS));
        overview.setBorder(BorderFactory.createTitledBorder("当前扫描边界与状态"));
        workbenchScopeLabel = new JLabel(scanBoundaryText(controller.config()));
        workbenchScopeLabel.setToolTipText("Scope + 白名单/黑名单 + 自动来源决定是否发包；结果筛选不改变扫描边界。");
        overview.add(workbenchScopeLabel);
        workbenchStatusLabel = new JLabel(controller.status().text());
        overview.add(workbenchStatusLabel);
        contextMenuLabel = new JLabel("Burp 右键菜单：" + safeText(controller.contextMenuStatus()));
        overview.add(contextMenuLabel);
        JLabel note = new JLabel("提示：左侧 Host、状态码和目录层级只筛选当前结果视图，不会扩大或缩小扫描范围。");
        overview.add(note);
        root.add(overview, BorderLayout.NORTH);

        failureTaskModel = new FailureTaskTableModel();
        JTable taskTable = new JTable(failureTaskModel);
        taskTable.setAutoCreateRowSorter(true);
        taskTable.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        JScrollPane tablePane = new JScrollPane(taskTable);
        tablePane.setBorder(BorderFactory.createTitledBorder("需要处理的任务（失败 / 待重试 / 已取消）"));

        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        workbenchPauseButton = new JToggleButton(controller.paused() ? "恢复扫描" : "暂停扫描", controller.paused());
        workbenchPauseButton.setToolTipText("暂停后，已排队任务会保留并进入延迟队列；恢复后自动继续。");
        workbenchPauseButton.addActionListener(event -> {
            boolean paused = workbenchPauseButton.isSelected();
            controller.setPaused(paused);
            workbenchPauseButton.setText(paused ? "恢复扫描" : "暂停扫描");
        });
        actionPanel.add(workbenchPauseButton);

        JButton retrySelected = new JButton("重试选中任务");
        retrySelected.addActionListener(event -> {
            int row = taskTable.getSelectedRow();
            if (row < 0) return;
            int modelRow = taskTable.convertRowIndexToModel(row);
            TaskView task = failureTaskModel.rowAt(modelRow);
            if (task != null) controller.retryTask(task.key);
        });
        actionPanel.add(retrySelected);

        JButton retryAll = new JButton("重新排队全部失败任务");
        retryAll.addActionListener(event -> controller.retryFailed());
        actionPanel.add(retryAll);

        JButton copy = new JButton("复制任务诊断");
        copy.addActionListener(event -> {
            int row = taskTable.getSelectedRow();
            TaskView task = row < 0 ? null : failureTaskModel.rowAt(taskTable.convertRowIndexToModel(row));
            String diagnostic = task == null ? failureTaskModel.diagnosticText() : diagnosticText(task);
            copyDiagnostic(diagnostic, controller);
        });
        actionPanel.add(copy);

        JButton settings = new JButton("打开可靠性设置");
        settings.addActionListener(event -> selectReliabilityTab());
        actionPanel.add(settings);

        JPanel middle = new JPanel(new BorderLayout(4, 4));
        middle.add(actionPanel, BorderLayout.NORTH);
        middle.add(tablePane, BorderLayout.CENTER);
        root.add(middle, BorderLayout.CENTER);
        return root;
    }

    private void startWorkbenchTimer() {
        if (workbenchTimer != null) return;
        workbenchTimer = new Timer(500, event -> refreshScanWorkbench());
        workbenchTimer.setRepeats(true);
        workbenchTimer.start();
        refreshScanWorkbench();
    }

    private void refreshScanWorkbench() {
        if (!SwingUtilities.isEventDispatchThread()) {
            onEdt(new Runnable() { public void run() { refreshScanWorkbench(); } });
            return;
        }
        ReliabilityController controller = workbenchController;
        if (controller == null) return;
        if (workbenchScopeLabel != null) workbenchScopeLabel.setText(scanBoundaryText(controller.config()));
        if (workbenchStatusLabel != null) workbenchStatusLabel.setText(controller.status().text());
        if (contextMenuLabel != null) contextMenuLabel.setText("Burp 右键菜单：" + safeText(controller.contextMenuStatus()));
        if (workbenchPauseButton != null) {
            boolean paused = controller.paused();
            if (workbenchPauseButton.isSelected() != paused) workbenchPauseButton.setSelected(paused);
            workbenchPauseButton.setText(paused ? "恢复扫描" : "暂停扫描");
        }
        if (failureTaskModel != null) failureTaskModel.replace(controller.taskViews());
    }

    private void selectReliabilityTab() {
        try {
            Object value = BurpExtensionAccess.readField(extender, "configurationTabs");
            if (!(value instanceof JTabbedPane)) return;
            JTabbedPane tabs = (JTabbedPane) value;
            for (int i = 0; i < tabs.getTabCount(); i++) {
                if ("可靠性".equals(tabs.getTitleAt(i))) { tabs.setSelectedIndex(i); return; }
            }
        } catch (Exception ignored) { }
    }

    private static String scanBoundaryText(ScanConfig config) {
        if (config == null) return "扫描边界：配置加载中";
        List<String> sources = new ArrayList<String>();
        if (config.proxyEnabled) sources.add("Proxy");
        if (config.targetEnabled) sources.add("Target");
        if (config.repeaterEnabled) sources.add("Repeater");
        if (config.intruderEnabled) sources.add("Intruder");
        if (config.scannerEnabled) sources.add("Scanner");
        return "扫描边界：Burp Scope" + (config.scopeRequired ? "（强制）" : "（未强制）")
                + " ｜ 自动来源：" + (sources.isEmpty() ? "未启用" : String.join("、", sources))
                + " ｜ 失败重试：" + config.maxRetries + " 次";
    }

    private static void copyDiagnostic(String text, ReliabilityController controller) {
        if (text == null) text = "";
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        } catch (RuntimeException error) {
            controller.log("[CGN] 无法访问系统剪贴板，任务诊断如下：\n" + text);
        }
    }

    private static String diagnosticText(TaskView task) {
        if (task == null) return "";
        return "状态: " + stateLabel(task.state) + "\n"
                + "来源: " + task.source + "\n"
                + "Host: " + task.host + "\n"
                + "URL: " + task.url + "\n"
                + "尝试次数: " + task.attempts + "\n"
                + "最后更新: " + formatTime(task.updatedAt) + "\n"
                + "原因: " + task.message;
    }

    private static String stateLabel(String state) {
        if ("FAILED".equals(state)) return "失败";
        if ("RETRYABLE".equals(state)) return "待重试";
        if ("CANCELLED".equals(state)) return "已取消";
        if ("RUNNING".equals(state)) return "执行中";
        if ("PENDING".equals(state)) return "排队中";
        if ("SUCCESS".equals(state)) return "已完成";
        return safeText(state);
    }

    private static String formatTime(long value) {
        return value <= 0L ? "-" : new SimpleDateFormat("HH:mm:ss").format(new Date(value));
    }

    private static String safeText(String value) { return value == null ? "" : value; }

    private static final class FailureTaskTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = { "状态", "来源", "Host", "URL", "尝试", "最后更新", "原因" };
        private List<TaskView> rows = Collections.emptyList();
        void replace(List<TaskView> tasks) {
            List<TaskView> next = new ArrayList<TaskView>();
            if (tasks != null) for (TaskView task : tasks) if (task != null && task.requiresAttention()) next.add(task);
            rows = Collections.unmodifiableList(next);
            fireTableDataChanged();
        }
        TaskView rowAt(int row) { return row < 0 || row >= rows.size() ? null : rows.get(row); }
        String diagnosticText() {
            StringBuilder out = new StringBuilder();
            for (TaskView task : rows) {
                if (out.length() > 0) out.append("\n\n");
                out.append(BurpViewModel.diagnosticText(task));
            }
            return out.toString();
        }
        public int getRowCount() { return rows.size(); }
        public int getColumnCount() { return COLUMNS.length; }
        public String getColumnName(int column) { return COLUMNS[column]; }
        public Object getValueAt(int row, int column) {
            TaskView task = rowAt(row);
            if (task == null) return "";
            switch (column) {
                case 0: return stateLabel(task.state);
                case 1: return task.source;
                case 2: return task.host;
                case 3: return task.url;
                case 4: return Integer.valueOf(task.attempts);
                case 5: return formatTime(task.updatedAt);
                case 6: return task.message;
                default: return "";
            }
        }
    }

    private static String safeMessage(Exception error) {
        String message = error.getMessage();
        return message == null ? error.getClass().getSimpleName() : message;
    }
}
